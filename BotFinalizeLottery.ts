// BotFinalizeLottery.ts
import {
  createPublicClient,
  createWalletClient,
  http,
  parseAbi,
  type Hex,
  type Address,
} from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { etherlink } from "viem/chains";

// --- TYPES & INTERFACES ---
export interface Env {
  BOT_PRIVATE_KEY: string;
  REGISTRY_ADDRESS: string;
  RPC_URL?: string;
  BOT_STATE: KVNamespace;

  HOT_SIZE?: string;
  COLD_SIZE?: string;

  MAX_TX?: string;
  TIME_BUDGET_MS?: string;
  ATTEMPT_TTL_SEC?: string;

  // ✅ cron interval (minutes), used only for the status endpoint countdown
  CRON_EVERY_MINUTES?: string;
}

// ABIs
const registryAbi = parseAbi([
  "function getAllLotteriesCount() external view returns (uint256)",
  "function getAllLotteries(uint256 start, uint256 limit) external view returns (address[])",
]);

const lotteryAbi = parseAbi([
  "function status() external view returns (uint8)",
  "function paused() external view returns (bool)",
  "function deadline() external view returns (uint64)",
  "function getSold() external view returns (uint256)",
  "function minTickets() external view returns (uint64)",
  "function maxTickets() external view returns (uint64)",
  "function entropy() external view returns (address)",
  "function entropyProvider() external view returns (address)",
  "function entropyRequestId() external view returns (uint64)",
  "function finalize() external payable",
]);

const entropyAbi = parseAbi([
  "function getFee(address provider) external view returns (uint256)",
]);

// --- HELPERS ---
function chunkArray<T>(array: T[], size: number): T[][] {
  const result: T[][] = [];
  for (let i = 0; i < array.length; i += size) result.push(array.slice(i, i + size));
  return result;
}

function getSafeSize(val: string | undefined, defaultVal: bigint, maxVal: bigint): bigint {
  if (!val) return defaultVal;
  try {
    const parsed = BigInt(val);
    if (parsed < 0n) return defaultVal;
    return parsed > maxVal ? maxVal : parsed;
  } catch {
    return defaultVal;
  }
}

function getSafeInt(val: string | undefined, defaultVal: number, maxVal: number): number {
  if (!val) return defaultVal;
  const n = Number(val);
  if (!Number.isFinite(n)) return defaultVal;
  return Math.min(Math.max(0, Math.floor(n)), maxVal);
}

function nowSec(): bigint {
  return BigInt(Math.floor(Date.now() / 1000));
}

function lower(a: string): string {
  return a.toLowerCase();
}

function isTransientErrorMessage(msg: string): boolean {
  const m = msg.toLowerCase();
  return (
    m.includes("timeout") ||
    m.includes("timed out") ||
    m.includes("network") ||
    m.includes("gateway") ||
    m.includes("503") ||
    m.includes("429") ||
    m.includes("rate") ||
    m.includes("connection") ||
    m.includes("econn") ||
    m.includes("failed to fetch") ||
    m.includes("request took too long")
  );
}

// Prioritization: sold-out first, then expired with sold>0, then expired sold==0
function priorityScore(isFull: boolean, isExpired: boolean, sold: bigint): number {
  if (isFull) return 3;
  if (isExpired && sold > 0n) return 2;
  if (isExpired && sold === 0n) return 1;
  return 0;
}

// map status number to label (your Solidity enum order)
function statusLabel(s: bigint): string {
  switch (s) {
    case 0n:
      return "FundingPending(0)";
    case 1n:
      return "Open(1)";
    case 2n:
      return "Drawing(2)";
    case 3n:
      return "Completed(3)";
    case 4n:
      return "Canceled(4)";
    default:
      return `Unknown(${s.toString()})`;
  }
}

async function sleep(ms: number) {
  await new Promise((r) => setTimeout(r, ms));
}

async function withRetry<T>(
  fn: () => Promise<T>,
  opts: { tries: number; baseDelayMs: number; label?: string; isRetryable?: (e: any) => boolean }
): Promise<T> {
  const tries = Math.max(1, opts.tries);
  const base = Math.max(0, opts.baseDelayMs);
  const isRetryable = opts.isRetryable ?? ((e: any) => isTransientErrorMessage(String(e?.message || e)));

  let lastErr: any = null;

  for (let i = 0; i < tries; i++) {
    try {
      return await fn();
    } catch (e: any) {
      lastErr = e;
      const msg = (e?.shortMessage || e?.message || String(e)).toString();
      const retryable = isRetryable(e);

      if (!retryable || i === tries - 1) {
        if (opts.label) console.warn(`   ⛔ ${opts.label} failed: ${msg}`);
        throw e;
      }

      const delay = Math.min(4000, base * Math.pow(2, i));
      if (opts.label) console.warn(`   🌧️ ${opts.label} transient error: ${msg} (retry in ${delay}ms)`);
      await sleep(delay);
    }
  }

  throw lastErr;
}

async function kvPutSafe(env: Env, key: string, value: string, ttlSec = 7 * 24 * 3600) {
  try {
    await env.BOT_STATE.put(key, value, { expirationTtl: ttlSec });
  } catch {
    // ignore
  }
}

async function kvDelSafe(env: Env, key: string) {
  try {
    await env.BOT_STATE.delete(key);
  } catch {
    // ignore
  }
}

// ✅ cron interval utilities (for accurate countdown in UI)
function getCronEveryMinutes(env: Env): number {
  const raw = env.CRON_EVERY_MINUTES;
  const n = Number(raw);
  return Number.isFinite(n) ? Math.max(1, Math.floor(n)) : 1;
}

/**
 * Compute the next expected cron boundary strictly AFTER now.
 * Example: everyMinutes=3 -> boundaries at ... :00, :03, :06, :09 ...
 */
function nextCronMs(nowMs = Date.now(), everyMinutes = 1): number {
  const m = Math.max(1, Math.floor(everyMinutes));
  const step = m * 60_000;
  return (Math.floor(nowMs / step) + 1) * step;
}

// A little helper to safely parse KV numbers
function parseKvNum(v: string | null): number | null {
  if (!v) return null;
  const n = Number(v);
  return Number.isFinite(n) ? n : null;
}

function corsHeadersFor(req: Request): Record<string, string> {
  const origin = req.headers.get("Origin") || "*";
  return {
    "Access-Control-Allow-Origin": origin,
    "Access-Control-Allow-Methods": "GET,OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type",
    "Access-Control-Max-Age": "86400",
  };
}

// --- MAIN WORKER ---
export default {
  /**
   * Status endpoint for your website.
   * - GET /bot-status -> JSON
   * Any other path: 404
   *
   * ✅ Includes CORS so your frontend (localhost / production) can read it.
   */
  async fetch(req: Request, env: Env): Promise<Response> {
    const url = new URL(req.url);
    const cors = corsHeadersFor(req);

    if (req.method === "OPTIONS") {
      return new Response(null, { status: 204, headers: cors });
    }

    if (req.method !== "GET") {
      return new Response("Method Not Allowed", { status: 405, headers: cors });
    }
    if (url.pathname !== "/bot-status") {
      return new Response("Not Found", { status: 404, headers: cors });
    }

    const [
      lastRunTsRaw,
      lastFinishedTsRaw,
      lastOkTsRaw,
      lastStatus,
      lastError,
      lock,
      lastRunId,
      lastDurationRaw,
      lastTxCountRaw,
    ] = await Promise.all([
      env.BOT_STATE.get("last_run_ts"),
      env.BOT_STATE.get("last_run_finished_ts"),
      env.BOT_STATE.get("last_ok_ts"),
      env.BOT_STATE.get("last_run_status"),
      env.BOT_STATE.get("last_run_error"),
      env.BOT_STATE.get("lock"),
      env.BOT_STATE.get("last_run_id"),
      env.BOT_STATE.get("last_run_duration_ms"),
      env.BOT_STATE.get("last_run_tx_count"),
    ]);

    const now = Date.now();
    const lastRun = parseKvNum(lastRunTsRaw);
    const lastFinished = parseKvNum(lastFinishedTsRaw);
    const lastOk = parseKvNum(lastOkTsRaw);
    const durationMs = parseKvNum(lastDurationRaw);
    const lastTxCount = parseKvNum(lastTxCountRaw);

    // ✅ FIX: compute next run using your cron interval (e.g. 3 minutes)
    const cronEveryMinutes = getCronEveryMinutes(env);
    const nextRun = nextCronMs(now, cronEveryMinutes);

    return new Response(
      JSON.stringify(
        {
          status: lastStatus || "unknown",
          running: !!lock,
          lockRunId: lock || null,
          lastRunId: lastRunId || null,

          lastRun,
          lastFinished,
          durationMs,
          txCount: lastTxCount,

          secondsSinceLastRun: lastRun ? Math.floor((now - lastRun) / 1000) : null,
          lastOk,
          secondsSinceLastOk: lastOk ? Math.floor((now - lastOk) / 1000) : null,

          cronEveryMinutes,
          nextRun,
          secondsToNextRun: Math.max(0, Math.floor((nextRun - now) / 1000)),
          lastError: lastError || null,
        },
        null,
        2
      ),
      {
        headers: {
          ...cors,
          "content-type": "application/json; charset=utf-8",
          "cache-control": "public, max-age=2",
        },
      }
    );
  },

  async scheduled(_event: ScheduledEvent, env: Env, _ctx: ExecutionContext): Promise<void> {
    const START_TIME = Date.now();
    const LOCK_TTL_SEC = 180;
    const runId = crypto.randomUUID();

    console.log(`🤖 Run ${runId} started`);

    // Run markers early (best effort)
    await kvPutSafe(env, "last_run_ts", START_TIME.toString());
    await kvPutSafe(env, "last_run_status", "running");
    await kvPutSafe(env, "last_run_id", runId);
    await kvDelSafe(env, "last_run_error");
    await kvDelSafe(env, "last_run_duration_ms");
    await kvDelSafe(env, "last_run_tx_count");
    await kvDelSafe(env, "last_run_finished_ts");

    const existingLock = await env.BOT_STATE.get("lock");
    if (existingLock) {
      console.warn(`⚠️ Locked by run ${existingLock}. Skipping.`);
      await kvPutSafe(env, "last_run_status", "skipped_locked");
      await kvPutSafe(env, "last_run_finished_ts", Date.now().toString());
      await kvPutSafe(env, "last_run_duration_ms", String(Date.now() - START_TIME));
      return;
    }

    await env.BOT_STATE.put("lock", runId, { expirationTtl: LOCK_TTL_SEC });

    const confirmLock = await env.BOT_STATE.get("lock");
    if (confirmLock !== runId) {
      console.warn(`⚠️ Lock race lost. Exiting.`);
      await kvPutSafe(env, "last_run_status", "skipped_lock_race");
      await kvPutSafe(env, "last_run_finished_ts", Date.now().toString());
      await kvPutSafe(env, "last_run_duration_ms", String(Date.now() - START_TIME));
      return;
    }

    let txCount = 0;

    try {
      txCount = await runLogic(env, START_TIME);

      await kvPutSafe(env, "last_run_status", "ok");
      await kvPutSafe(env, "last_ok_ts", Date.now().toString());
      await kvPutSafe(env, "last_run_tx_count", String(txCount));
    } catch (e: any) {
      const msg = (e?.message || String(e)).toString();
      console.error("❌ Critical Error:", msg);

      await kvPutSafe(env, "last_run_status", "error");
      await kvPutSafe(env, "last_run_error", msg.slice(0, 500));
      await kvPutSafe(env, "last_run_tx_count", String(txCount));
    } finally {
      const finished = Date.now();
      await kvPutSafe(env, "last_run_finished_ts", finished.toString());
      await kvPutSafe(env, "last_run_duration_ms", String(finished - START_TIME));

      const currentLock = await env.BOT_STATE.get("lock");
      if (currentLock === runId) {
        await env.BOT_STATE.delete("lock");
        console.log(`🔓 Lock released`);
      }
    }
  },
};

async function runLogic(env: Env, startTimeMs: number): Promise<number> {
  if (!env.BOT_PRIVATE_KEY || !env.REGISTRY_ADDRESS) {
    throw new Error("Missing Env: BOT_PRIVATE_KEY/REGISTRY_ADDRESS");
  }

  const rpcUrl = env.RPC_URL || "https://node.mainnet.etherlink.com";
  const account = privateKeyToAccount(env.BOT_PRIVATE_KEY as Hex);

  // Tighten RPC timeouts + retries to reduce “request took too long”
  const transport = http(rpcUrl, {
    timeout: 12_000,
    retryCount: 2,
    retryDelay: 400,
  });

  const client = createPublicClient({ chain: etherlink, transport });
  const wallet = createWalletClient({ account, chain: etherlink, transport });

  console.log(`👛 Bot address: ${account.address}`);
  console.log(`🌐 RPC: ${rpcUrl}`);

  const HOT_SIZE = getSafeSize(env.HOT_SIZE, 100n, 500n);
  const COLD_SIZE = getSafeSize(env.COLD_SIZE, 50n, 200n);

  const MAX_TX = getSafeInt(env.MAX_TX, 5, 25);
  const TIME_BUDGET_MS = getSafeInt(env.TIME_BUDGET_MS, 25_000, 45_000);
  const ATTEMPT_TTL_SEC = getSafeInt(env.ATTEMPT_TTL_SEC, 600, 3600);

  const total = await withRetry(
    () =>
      client.readContract({
        address: env.REGISTRY_ADDRESS as Address,
        abi: registryAbi,
        functionName: "getAllLotteriesCount",
      }),
    { tries: 3, baseDelayMs: 250, label: "getAllLotteriesCount" }
  );

  if (total === 0n) {
    console.log("ℹ️ Registry empty. Done.");
    return 0;
  }

  const startHot = total > HOT_SIZE ? total - HOT_SIZE : 0n;
  const safeHotSize = total - startHot;

  const savedCursor = await env.BOT_STATE.get("cursor");
  let cursor = savedCursor ? BigInt(savedCursor) : 0n;
  if (cursor >= total) cursor = 0n;

  const startCold = cursor;
  const safeColdSize = (total - startCold) < COLD_SIZE ? total - startCold : COLD_SIZE;

  console.log(
    `🔍 Scanning: Hot[${startHot}..${startHot + safeHotSize}) Cold[${startCold}..${startCold + safeColdSize}) total=${total}`
  );

  const [hotBatch, coldBatch] = await withRetry(
    async () => {
      const [h, c] = await Promise.all([
        safeHotSize > 0n
          ? client.readContract({
              address: env.REGISTRY_ADDRESS as Address,
              abi: registryAbi,
              functionName: "getAllLotteries",
              args: [startHot, safeHotSize],
            })
          : Promise.resolve([] as Address[]),
        safeColdSize > 0n
          ? client.readContract({
              address: env.REGISTRY_ADDRESS as Address,
              abi: registryAbi,
              functionName: "getAllLotteries",
              args: [startCold, safeColdSize],
            })
          : Promise.resolve([] as Address[]),
      ]);
      return [h, c] as const;
    },
    { tries: 3, baseDelayMs: 250, label: "getAllLotteries batches" }
  );

  let nextCursor = startCold + safeColdSize;
  if (nextCursor >= total) nextCursor = 0n;

  const candidates = Array.from(new Set([...hotBatch, ...coldBatch]));
  if (candidates.length === 0) {
    console.log("ℹ️ No candidates. Done.");
    await env.BOT_STATE.put("cursor", nextCursor.toString());
    return 0;
  }

  const statusResults = await withRetry(
    () =>
      client.multicall({
        contracts: candidates.map((addr) => ({
          address: addr,
          abi: lotteryAbi,
          functionName: "status",
        })),
      }),
    { tries: 3, baseDelayMs: 250, label: "status multicall" }
  );

  const statusFailures = statusResults.filter((r) => r.status !== "success").length;
  console.log(`🧪 status multicall: total=${statusResults.length} failures=${statusFailures}`);

  const openLotteries: Address[] = [];
  for (let i = 0; i < candidates.length; i++) {
    const r = statusResults[i];
    if (r.status === "success") {
      const s = BigInt(r.result as bigint);
      console.log(`🔎 ${candidates[i]} status=${statusLabel(s)}`);
      if (s === 1n) openLotteries.push(candidates[i]);
    }
  }

  if (openLotteries.length === 0) {
    console.log("ℹ️ No Open lotteries found.");
    await env.BOT_STATE.put("cursor", nextCursor.toString());
    return 0;
  }

  console.log(`⚡ Found ${openLotteries.length} Open lotteries to analyze.`);

  const currentNonceStart = await withRetry(
    () =>
      client.getTransactionCount({
        address: account.address,
        blockTag: "pending",
      }),
    { tries: 3, baseDelayMs: 300, label: "getTransactionCount(pending)" }
  );

  let currentNonce = currentNonceStart;

  const chunks = chunkArray(openLotteries, 25);
  let txCount = 0;

  for (const chunk of chunks) {
    if (txCount >= MAX_TX) break;
    if (Date.now() - startTimeMs > TIME_BUDGET_MS) break;

    const tNow = nowSec();

    const detailCalls = chunk.flatMap((addr) => [
      { address: addr, abi: lotteryAbi, functionName: "deadline" },
      { address: addr, abi: lotteryAbi, functionName: "getSold" },
      { address: addr, abi: lotteryAbi, functionName: "minTickets" },
      { address: addr, abi: lotteryAbi, functionName: "maxTickets" },
      { address: addr, abi: lotteryAbi, functionName: "paused" },
      { address: addr, abi: lotteryAbi, functionName: "entropy" },
      { address: addr, abi: lotteryAbi, functionName: "entropyProvider" },
      { address: addr, abi: lotteryAbi, functionName: "entropyRequestId" },
    ]);

    const detailResults = await withRetry(
      () => client.multicall({ contracts: detailCalls }),
      { tries: 3, baseDelayMs: 250, label: "details multicall" }
    );

    type Candidate = {
      addr: Address;
      deadline: bigint;
      sold: bigint;
      minTickets: bigint;
      maxTickets: bigint;
      entropyAddr: Address;
      providerAddr: Address;
      isExpired: boolean;
      isFull: boolean;
      cancelPath: boolean;
      score: number;
    };

    const actionable: Candidate[] = [];

    for (let i = 0; i < chunk.length; i++) {
      const lottery = chunk[i];
      const baseIdx = i * 8;

      const rDeadline = detailResults[baseIdx];
      const rSold = detailResults[baseIdx + 1];
      const rMin = detailResults[baseIdx + 2];
      const rMax = detailResults[baseIdx + 3];
      const rPaused = detailResults[baseIdx + 4];
      const rEntropy = detailResults[baseIdx + 5];
      const rProvider = detailResults[baseIdx + 6];
      const rReq = detailResults[baseIdx + 7];

      if (
        rDeadline.status !== "success" ||
        rSold.status !== "success" ||
        rMin.status !== "success" ||
        rMax.status !== "success" ||
        rPaused.status !== "success" ||
        rEntropy.status !== "success" ||
        rProvider.status !== "success" ||
        rReq.status !== "success"
      )
        continue;

      if (rPaused.result === true) continue;

      const reqId = BigInt(rReq.result as bigint);
      if (reqId !== 0n) continue;

      const deadline = BigInt(rDeadline.result as bigint);
      const sold = BigInt(rSold.result as bigint);
      const minTickets = BigInt(rMin.result as bigint);
      const maxTickets = BigInt(rMax.result as bigint);

      const entropyAddr = rEntropy.result as Address;
      const providerAddr = rProvider.result as Address;

      const isExpired = tNow >= deadline;
      const isFull = maxTickets > 0n && sold >= maxTickets;

      if (!isExpired && !isFull) continue;

      const cancelPath = isExpired && sold < minTickets;

      actionable.push({
        addr: lottery,
        deadline,
        sold,
        minTickets,
        maxTickets,
        entropyAddr,
        providerAddr,
        isExpired,
        isFull,
        cancelPath,
        score: priorityScore(isFull, isExpired, sold),
      });
    }

    if (actionable.length === 0) continue;

    actionable.sort((a, b) => b.score - a.score);

    for (const c of actionable) {
      if (txCount >= MAX_TX) break;
      if (Date.now() - startTimeMs > TIME_BUDGET_MS) break;

      const attemptKey = `attempt:${lower(c.addr)}`;
      const recentAttempt = await env.BOT_STATE.get(attemptKey);
      if (recentAttempt) continue;

      console.log(
        `🚀 Finalize candidate: ${c.addr} (expired=${c.isExpired} full=${c.isFull} sold=${c.sold} min=${c.minTickets} max=${c.maxTickets} cancelPath=${c.cancelPath})`
      );

      let value = 0n;

      if (!c.cancelPath) {
        const feeKey = `fee:${lower(c.entropyAddr)}:${lower(c.providerAddr)}`;
        const cachedFee = await env.BOT_STATE.get(feeKey);

        if (cachedFee) {
          try {
            value = BigInt(cachedFee);
          } catch {
            value = 0n;
          }
        } else {
          try {
            const fee = await withRetry(
              () =>
                client.readContract({
                  address: c.entropyAddr,
                  abi: entropyAbi,
                  functionName: "getFee",
                  args: [c.providerAddr],
                }),
              { tries: 3, baseDelayMs: 250, label: "entropy.getFee" }
            );

            value = BigInt(fee);
            await env.BOT_STATE.put(feeKey, value.toString(), { expirationTtl: 60 });
          } catch (e: any) {
            const msg = (e?.shortMessage || e?.message || "").toString();
            console.warn(`   ⚠️ Fee lookup failed; skipping draw for now: ${msg}`);
            await env.BOT_STATE.put(attemptKey, `feeFail:${Date.now()}`, {
              expirationTtl: Math.min(300, ATTEMPT_TTL_SEC),
            });
            continue;
          }
        }
      }

      // --- SIMULATE ---
      try {
        await withRetry(
          () =>
            client.simulateContract({
              account,
              address: c.addr,
              abi: lotteryAbi,
              functionName: "finalize",
              value,
            }),
          { tries: 2, baseDelayMs: 200, label: "simulate finalize" }
        );
      } catch (e: any) {
        const msg = (e?.shortMessage || e?.message || "").toString();
        if (isTransientErrorMessage(msg)) {
          console.warn(`   🌧️ Transient sim error (will retry next run): ${msg}`);
          continue;
        }
        console.warn(`   ⏭️ Simulation revert: ${msg}`);
        await env.BOT_STATE.put(attemptKey, `revert:${Date.now()}`, {
          expirationTtl: Math.min(120, ATTEMPT_TTL_SEC),
        });
        continue;
      }

      await env.BOT_STATE.put(attemptKey, `${Date.now()}`, { expirationTtl: ATTEMPT_TTL_SEC });

      // --- SEND TX ---
      try {
        const hash = await withRetry(
          () =>
            wallet.writeContract({
              account,
              address: c.addr,
              abi: lotteryAbi,
              functionName: "finalize",
              value,
              nonce: currentNonce++,
            }),
          { tries: 2, baseDelayMs: 250, label: "send finalize tx" }
        );

        console.log(`   ✅ Tx Sent: ${hash}`);
        txCount++;
      } catch (e: any) {
        const msg = (e?.shortMessage || e?.message || "").toString();
        console.warn(`   ⏭️ Tx failed: ${msg}`);
      }
    }
  }

  await env.BOT_STATE.put("cursor", nextCursor.toString());
  console.log(`🏁 Run complete. txCount=${txCount} cursor=${nextCursor.toString()}`);

  return txCount;
}