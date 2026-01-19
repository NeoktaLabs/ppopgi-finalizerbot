import {
  createPublicClient,
  createWalletClient,
  http,
  parseAbi,
  type Hex,
  type Address,
} from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { defineChain } from "viem";

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
}

// Etherlink Config
// Etherlink Config
const ETHERLINK = defineChain({
  id: 42793,
  name: "Etherlink Mainnet",
  network: "etherlink",
  nativeCurrency: { name: "Tezos", symbol: "XTZ", decimals: 18 },
  rpcUrls: { default: { http: ["https://node.mainnet.etherlink.com"] } },

  // ✅ Add this
  contracts: {
    multicall3: {
      address: "0xcA11bde05977b3631167028862bE2a173976CA11",
      blockCreated: 0, // ok to leave 0 if you don't know the exact deployment block
    },
  },
});

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
    m.includes("fetch") ||
    m.includes("network") ||
    m.includes("gateway") ||
    m.includes("503") ||
    m.includes("429") ||
    m.includes("rate") ||
    m.includes("connection") ||
    m.includes("econn") ||
    m.includes("failed to fetch")
  );
}

// Prioritization: sold-out first, then expired with sold>0, then expired sold==0
function priorityScore(isFull: boolean, isExpired: boolean, sold: bigint): number {
  if (isFull) return 3;
  if (isExpired && sold > 0n) return 2;
  if (isExpired && sold === 0n) return 1;
  return 0;
}

// --- MAIN WORKER ---
export default {
  async scheduled(_event: ScheduledEvent, env: Env, _ctx: ExecutionContext): Promise<void> {
    const START_TIME = Date.now();
    const LOCK_TTL_SEC = 180;
    const runId = crypto.randomUUID();

    console.log(`🤖 Run ${runId} started`);

    // 1) LOCK ACQUISITION (best-effort)
    const existingLock = await env.BOT_STATE.get("lock");
    if (existingLock) {
      console.warn(`⚠️ Locked by run ${existingLock}. Skipping.`);
      return;
    }

    await env.BOT_STATE.put("lock", runId, { expirationTtl: LOCK_TTL_SEC });

    const confirmLock = await env.BOT_STATE.get("lock");
    if (confirmLock !== runId) {
      console.warn(`⚠️ Lock race lost. Exiting.`);
      return;
    }

    try {
      await runLogic(env, START_TIME);
    } catch (e: any) {
      console.error("❌ Critical Error:", e?.message || e);
    } finally {
      // 2) LOCK RELEASE
      const currentLock = await env.BOT_STATE.get("lock");
      if (currentLock === runId) {
        await env.BOT_STATE.delete("lock");
        console.log(`🔓 Lock released`);
      }
    }
  },
};

async function runLogic(env: Env, startTimeMs: number) {
  if (!env.BOT_PRIVATE_KEY || !env.REGISTRY_ADDRESS) throw new Error("Missing Env: BOT_PRIVATE_KEY/REGISTRY_ADDRESS");

  const rpcUrl = env.RPC_URL || "https://node.mainnet.etherlink.com";
  const account = privateKeyToAccount(env.BOT_PRIVATE_KEY as Hex);

  const client = createPublicClient({ chain: ETHERLINK, transport: http(rpcUrl) });
  const wallet = createWalletClient({ account, chain: ETHERLINK, transport: http(rpcUrl) });

  // Tuning
  const HOT_SIZE = getSafeSize(env.HOT_SIZE, 100n, 500n);
  const COLD_SIZE = getSafeSize(env.COLD_SIZE, 50n, 200n);

  const MAX_TX = getSafeInt(env.MAX_TX, 5, 25);
  const TIME_BUDGET_MS = getSafeInt(env.TIME_BUDGET_MS, 25_000, 45_000);
  const ATTEMPT_TTL_SEC = getSafeInt(env.ATTEMPT_TTL_SEC, 600, 3600);

  // --- 1) FETCH TOTAL ---
  const total = await client.readContract({
    address: env.REGISTRY_ADDRESS as Address,
    abi: registryAbi,
    functionName: "getAllLotteriesCount",
  });

  if (total === 0n) {
    console.log("ℹ️ Registry empty. Done.");
    return;
  }

  // --- 2) SCAN CONFIG ---
  const startHot = total > HOT_SIZE ? total - HOT_SIZE : 0n;
  const safeHotSize = total - startHot;

  const savedCursor = await env.BOT_STATE.get("cursor");
  let cursor = savedCursor ? BigInt(savedCursor) : 0n;
  if (cursor >= total) cursor = 0n;

  const startCold = cursor;
  const safeColdSize = (total - startCold) < COLD_SIZE ? (total - startCold) : COLD_SIZE;

  console.log(
    `🔍 Scanning: Hot[${startHot}..${startHot + safeHotSize}) Cold[${startCold}..${startCold + safeColdSize}) total=${total}`
  );

  // --- 3) FETCH BATCHES ---
  const [hotBatch, coldBatch] = await Promise.all([
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

  // Compute next cursor; commit it at end
  let nextCursor = startCold + safeColdSize;
  if (nextCursor >= total) nextCursor = 0n;

  // Deduplicate candidates
  const candidates = Array.from(new Set([...hotBatch, ...coldBatch]));
  if (candidates.length === 0) {
    console.log("ℹ️ No candidates. Done.");
    await env.BOT_STATE.put("cursor", nextCursor.toString());
    return;
  }

  // --- 4) STATUS FILTER (Multicall) ---
  const statusResults = await client.multicall({
    contracts: candidates.map((addr) => ({
      address: addr,
      abi: lotteryAbi,
      functionName: "status",
    })),
  });

  const openLotteries: Address[] = [];
  statusResults.forEach((res, i) => {
    // Open = 1 (uint8 -> bigint)
    if (res.status === "success" && res.result === 1n) openLotteries.push(candidates[i]);
  });

  if (openLotteries.length === 0) {
    console.log("ℹ️ No Open lotteries found.");
    await env.BOT_STATE.put("cursor", nextCursor.toString());
    return;
  }

  console.log(`⚡ Found ${openLotteries.length} Open lotteries to analyze.`);

  // --- 5) PREPARE TX LOOP ---
  let currentNonce = await client.getTransactionCount({
    address: account.address,
    blockTag: "pending",
  });

  const CHUNK_SIZE = 25;
  const chunks = chunkArray(openLotteries, CHUNK_SIZE);

  let txCount = 0;

  // --- 6) PROCESSING LOOP ---
  for (const chunk of chunks) {
    if (txCount >= MAX_TX) break;
    if (Date.now() - startTimeMs > TIME_BUDGET_MS) break;

    const tNow = nowSec();

    // Detail multicall (7 calls per lottery)
    const detailCalls = chunk.flatMap((addr) => [
      { address: addr, abi: lotteryAbi, functionName: "deadline" },
      { address: addr, abi: lotteryAbi, functionName: "getSold" },
      { address: addr, abi: lotteryAbi, functionName: "maxTickets" },
      { address: addr, abi: lotteryAbi, functionName: "paused" },
      { address: addr, abi: lotteryAbi, functionName: "entropy" },
      { address: addr, abi: lotteryAbi, functionName: "entropyProvider" },
      { address: addr, abi: lotteryAbi, functionName: "entropyRequestId" },
    ]);

    const detailResults = await client.multicall({ contracts: detailCalls });

    type Candidate = {
      addr: Address;
      deadline: bigint;
      sold: bigint;
      maxTickets: bigint;
      entropyAddr: Address;
      providerAddr: Address;
      isExpired: boolean;
      isFull: boolean;
      score: number;
    };

    const actionable: Candidate[] = [];

    for (let i = 0; i < chunk.length; i++) {
      const lottery = chunk[i];
      const baseIdx = i * 7;

      const rDeadline = detailResults[baseIdx];
      const rSold = detailResults[baseIdx + 1];
      const rMax = detailResults[baseIdx + 2];
      const rPaused = detailResults[baseIdx + 3];
      const rEntropy = detailResults[baseIdx + 4];
      const rProvider = detailResults[baseIdx + 5];
      const rReq = detailResults[baseIdx + 6];

      if (
        rDeadline.status !== "success" ||
        rSold.status !== "success" ||
        rMax.status !== "success" ||
        rPaused.status !== "success" ||
        rEntropy.status !== "success" ||
        rProvider.status !== "success" ||
        rReq.status !== "success"
      ) continue;

      if (rPaused.result === true) continue;

      const reqId = BigInt(rReq.result as bigint);
      if (reqId !== 0n) continue; // request pending (shouldn't happen in Open often, but safe)

      const deadline = BigInt(rDeadline.result as bigint);
      const sold = BigInt(rSold.result as bigint);
      const maxTickets = BigInt(rMax.result as bigint);
      const entropyAddr = rEntropy.result as Address;
      const providerAddr = rProvider.result as Address;

      const isExpired = tNow >= deadline;
      const isFull = maxTickets > 0n && sold >= maxTickets;

      if (!isExpired && !isFull) continue;

      actionable.push({
        addr: lottery,
        deadline,
        sold,
        maxTickets,
        entropyAddr,
        providerAddr,
        isExpired,
        isFull,
        score: priorityScore(isFull, isExpired, sold),
      });
    }

    if (actionable.length === 0) continue;

    // prioritize
    actionable.sort((a, b) => b.score - a.score);

    for (const c of actionable) {
      if (txCount >= MAX_TX) break;
      if (Date.now() - startTimeMs > TIME_BUDGET_MS) break;

      // Idempotency guard (check only when we're about to act)
      const attemptKey = `attempt:${lower(c.addr)}`;
      const recentAttempt = await env.BOT_STATE.get(attemptKey);
      if (recentAttempt) continue;

      console.log(
        `🚀 Finalize candidate: ${c.addr} (expired=${c.isExpired} full=${c.isFull} sold=${c.sold} max=${c.maxTickets})`
      );

      // Fee lookup (KV cache first)
      const feeKey = `fee:${lower(c.entropyAddr)}:${lower(c.providerAddr)}`;
      let fee: bigint | null = null;

      const cachedFee = await env.BOT_STATE.get(feeKey);
      if (cachedFee) {
        try { fee = BigInt(cachedFee); } catch { fee = null; }
      }

      if (fee === null) {
        fee = await client.readContract({
          address: c.entropyAddr,
          abi: entropyAbi,
          functionName: "getFee",
          args: [c.providerAddr],
        });
        // cache for 60s
        await env.BOT_STATE.put(feeKey, fee.toString(), { expirationTtl: 60 });
      }

      let value = fee;

      // --- SIMULATE ---
      try {
        await client.simulateContract({
          account,
          address: c.addr,
          abi: lotteryAbi,
          functionName: "finalize",
          value,
        });
      } catch (e: any) {
        const msg = (e?.shortMessage || e?.message || "").toString();
        if (isTransientErrorMessage(msg)) {
          console.warn(`   🌧️ Transient sim error (will retry next run): ${msg}`);
          continue;
        }

        // Fee mismatch -> refresh fee once
        if (msg.includes("InsufficientFee") || msg.toLowerCase().includes("insufficient fee")) {
          try {
            const refreshedFee = await client.readContract({
              address: c.entropyAddr,
              abi: entropyAbi,
              functionName: "getFee",
              args: [c.providerAddr],
            });
            value = refreshedFee;
            await env.BOT_STATE.put(feeKey, refreshedFee.toString(), { expirationTtl: 60 });

            await client.simulateContract({
              account,
              address: c.addr,
              abi: lotteryAbi,
              functionName: "finalize",
              value,
            });
          } catch (e2: any) {
            const msg2 = (e2?.shortMessage || e2?.message || "").toString();
            console.warn(`   ⏭️ Simulation failed after fee refresh: ${msg2}`);
            continue;
          }
        } else {
          // likely NotReadyToFinalize / RequestPending / already finalized etc.
          console.warn(`   ⏭️ Simulation revert: ${msg}`);
          // Short cooldown to avoid hammering reverts (not full ATTEMPT_TTL)
          await env.BOT_STATE.put(attemptKey, `revert:${Date.now()}`, { expirationTtl: Math.min(120, ATTEMPT_TTL_SEC) });
          continue;
        }
      }

      // Now mark attempt ONLY after passing simulation (prevents liveness loss on RPC issues)
      await env.BOT_STATE.put(attemptKey, `${Date.now()}`, { expirationTtl: ATTEMPT_TTL_SEC });

      // --- SEND TX ---
      try {
        const hash = await wallet.writeContract({
          account,
          address: c.addr,
          abi: lotteryAbi,
          functionName: "finalize",
          value,
          nonce: currentNonce++,
        });

        console.log(`   ✅ Tx Sent: ${hash}`);
        txCount++;
      } catch (e: any) {
        const msg = (e?.shortMessage || e?.message || "").toString();
        console.warn(`   ⏭️ Tx failed: ${msg}`);
        // keep attempt TTL to prevent fee burn spamming; expires naturally
      }
    }
  }

  // Update cursor after processing phase
  await env.BOT_STATE.put("cursor", nextCursor.toString());

  console.log(`🏁 Run complete. txCount=${txCount} cursor=${nextCursor.toString()}`);
}