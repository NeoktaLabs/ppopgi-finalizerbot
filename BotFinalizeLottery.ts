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
import { formatUnits as viemFormatUnits } from "viem";

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

  // ✅ NEW: tweet sync (indexer-driven)
  SUBGRAPH_URL: string;
  SITE_URL: string;
  X_USER_ACCESS_TOKEN: string; // wrangler secret
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

// map status number to label (your Solidity enum order)
function statusLabel(s: bigint): string {
  switch (s) {
    case 0n: return "FundingPending(0)";
    case 1n: return "Open(1)";
    case 2n: return "Drawing(2)";
    case 3n: return "Completed(3)";
    case 4n: return "Canceled(4)";
    default: return `Unknown(${s.toString()})`;
  }
}

// --------------------
// ✅ Twitter helpers
// --------------------
function shortAddr(a: string) {
  const s = (a || "").toLowerCase();
  if (!s.startsWith("0x") || s.length < 10) return s || "—";
  return `${s.slice(0, 4)}…${s.slice(-4)}`;
}

function explorerAddr(a: string) {
  const s = (a || "").toLowerCase();
  return `https://explorer.etherlink.com/address/${s}`;
}

function raffleLink(siteUrl: string, raffleId: string) {
  return `${siteUrl.replace(/\/$/, "")}/?raffle=${raffleId.toLowerCase()}`;
}

function fmtUsdc6(raw: string | bigint) {
  try {
    const v = typeof raw === "bigint" ? raw : BigInt(raw || "0");
    return Number(viemFormatUnits(v, 6)).toLocaleString("en-US", {
      maximumFractionDigits: 2,
    });
  } catch {
    return "0";
  }
}

/** GraphQL fetch that survives 429/plain-text bodies (same robustness as your frontend) */
async function gqlFetch<T>(url: string, query: string, variables: Record<string, any>): Promise<T> {
  const res = await fetch(url, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ query, variables }),
  });

  const text = await res.text();

  let json: any = null;
  try {
    json = text ? JSON.parse(text) : null;
  } catch {
    throw new Error(`SUBGRAPH_BAD_JSON_${res.status}`);
  }

  if (!res.ok) throw new Error(`SUBGRAPH_HTTP_${res.status}`);
  if (json?.errors?.length) throw new Error("SUBGRAPH_GQL_ERROR");

  return json.data as T;
}

async function postTweet(env: Env, text: string) {
  const token = env.X_USER_ACCESS_TOKEN;
  if (!token) throw new Error("MISSING_ENV_X_USER_ACCESS_TOKEN");

  const res = await fetch("https://api.x.com/2/tweets", {
    method: "POST",
    headers: {
      "content-type": "application/json",
      authorization: `Bearer ${token}`,
    },
    body: JSON.stringify({ text }),
  });

  const body = await res.text();
  if (!res.ok) {
    throw new Error(`X_TWEET_FAILED_${res.status}: ${body.slice(0, 300)}`);
  }
}

type TweetCreate = {
  id: string;
  name: string;
  creator: string;
  winningPot: string;
  createdAtTimestamp: string;
};

type TweetWin = {
  id: string;
  name: string;
  creator: string;
  winner: string;
  winningPot: string;
  completedAt: string;
};

type TweetCancel = {
  id: string;
  name: string;
  creator: string;
  canceledAt: string;
};

async function tweetSync(env: Env) {
  const subgraphUrl = env.SUBGRAPH_URL;
  const siteUrl = env.SITE_URL;

  if (!subgraphUrl) throw new Error("MISSING_ENV_SUBGRAPH_URL");
  if (!siteUrl) throw new Error("MISSING_ENV_SITE_URL");

  const lastCreated = Number((await env.BOT_STATE.get("tweet:last_created_ts")) || "0");
  const lastCompleted = Number((await env.BOT_STATE.get("tweet:last_completed_ts")) || "0");
  const lastCanceled = Number((await env.BOT_STATE.get("tweet:last_canceled_ts")) || "0");

  const query = `
    query TweetFeed($n: Int!) {
      latestCreated: raffles(
        first: $n
        orderBy: createdAtTimestamp
        orderDirection: desc
      ) {
        id
        name
        creator
        winningPot
        createdAtTimestamp
      }

      latestCompleted: raffles(
        first: $n
        orderBy: completedAt
        orderDirection: desc
        where: { status: COMPLETED }
      ) {
        id
        name
        creator
        winner
        winningPot
        completedAt
      }

      latestCanceled: raffles(
        first: $n
        orderBy: canceledAt
        orderDirection: desc
        where: { status: CANCELED }
      ) {
        id
        name
        creator
        canceledAt
      }
    }
  `;

  type Resp = {
    latestCreated: TweetCreate[];
    latestCompleted: TweetWin[];
    latestCanceled: TweetCancel[];
  };

  const data = await gqlFetch<Resp>(subgraphUrl, query, { n: 10 });

  const newCreated = (data.latestCreated || []).filter(r => Number(r.createdAtTimestamp || "0") > lastCreated);
  const newWins = (data.latestCompleted || []).filter(r => Number(r.completedAt || "0") > lastCompleted);
  const newCancels = (data.latestCanceled || []).filter(r => Number(r.canceledAt || "0") > lastCanceled);

  newCreated.sort((a, b) => Number(a.createdAtTimestamp) - Number(b.createdAtTimestamp));
  newWins.sort((a, b) => Number(a.completedAt) - Number(b.completedAt));
  newCancels.sort((a, b) => Number(a.canceledAt) - Number(b.canceledAt));

  let maxCreated = lastCreated;
  let maxCompleted = lastCompleted;
  let maxCanceled = lastCanceled;

  // CREATE
  for (const r of newCreated) {
    const ts = Number(r.createdAtTimestamp || "0");
    const dedupeKey = `tweet:seen:create:${r.id.toLowerCase()}:${ts}`;
    if (await env.BOT_STATE.get(dedupeKey)) continue;

    const pot = fmtUsdc6(r.winningPot);
    const link = raffleLink(siteUrl, r.id);

    const text =
`🎉 New raffle is live: ${r.name}
💰 Prize: ${pot} USDC
👤 Creator: ${shortAddr(r.creator)} (${explorerAddr(r.creator)})
🎟️ Join: ${link}`;

    await postTweet(env, text);

    await env.BOT_STATE.put(dedupeKey, "1", { expirationTtl: 60 * 60 * 24 * 30 });
    if (ts > maxCreated) maxCreated = ts;
  }

  // WIN / SETTLED
  for (const r of newWins) {
    const ts = Number(r.completedAt || "0");
    const dedupeKey = `tweet:seen:win:${r.id.toLowerCase()}:${ts}`;
    if (await env.BOT_STATE.get(dedupeKey)) continue;

    const pot = fmtUsdc6(r.winningPot);
    const link = raffleLink(siteUrl, r.id);

    const text =
`🏆 Raffle settled: ${r.name}
💰 Prize: ${pot} USDC
👤 Creator: ${shortAddr(r.creator)} (${explorerAddr(r.creator)})
🎉 Winner: ${shortAddr(r.winner)} (${explorerAddr(r.winner)})
🔗 View: ${link}`;

    await postTweet(env, text);

    await env.BOT_STATE.put(dedupeKey, "1", { expirationTtl: 60 * 60 * 24 * 30 });
    if (ts > maxCompleted) maxCompleted = ts;
  }

  // CANCEL
  for (const r of newCancels) {
    const ts = Number(r.canceledAt || "0");
    const dedupeKey = `tweet:seen:cancel:${r.id.toLowerCase()}:${ts}`;
    if (await env.BOT_STATE.get(dedupeKey)) continue;

    const link = raffleLink(siteUrl, r.id);

    const text =
`⛔ Raffle canceled: ${r.name}
📍 Raffle: ${r.id.toLowerCase()}
❗ Reason: not enough tickets sold (min tickets not reached)
🔗 Details: ${link}`;

    await postTweet(env, text);

    await env.BOT_STATE.put(dedupeKey, "1", { expirationTtl: 60 * 60 * 24 * 30 });
    if (ts > maxCanceled) maxCanceled = ts;
  }

  await env.BOT_STATE.put("tweet:last_created_ts", String(maxCreated));
  await env.BOT_STATE.put("tweet:last_completed_ts", String(maxCompleted));
  await env.BOT_STATE.put("tweet:last_canceled_ts", String(maxCanceled));

  console.log(
    `🐦 tweetSync done: created=${newCreated.length} wins=${newWins.length} cancels=${newCancels.length}`
  );
}

// --- MAIN WORKER ---
export default {
  async scheduled(_event: ScheduledEvent, env: Env, _ctx: ExecutionContext): Promise<void> {
    const START_TIME = Date.now();
    const LOCK_TTL_SEC = 180;
    const runId = crypto.randomUUID();

    console.log(`🤖 Run ${runId} started`);

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
      const currentLock = await env.BOT_STATE.get("lock");
      if (currentLock === runId) {
        await env.BOT_STATE.delete("lock");
        console.log(`🔓 Lock released`);
      }
    }
  },
};

async function runLogic(env: Env, startTimeMs: number) {
  if (!env.BOT_PRIVATE_KEY || !env.REGISTRY_ADDRESS) {
    throw new Error("Missing Env: BOT_PRIVATE_KEY/REGISTRY_ADDRESS");
  }

  const rpcUrl = env.RPC_URL || "https://node.mainnet.etherlink.com";
  const account = privateKeyToAccount(env.BOT_PRIVATE_KEY as Hex);

  const client = createPublicClient({ chain: etherlink, transport: http(rpcUrl) });
  const wallet = createWalletClient({ account, chain: etherlink, transport: http(rpcUrl) });

  console.log(`👛 Bot address: ${account.address}`);

  const HOT_SIZE = getSafeSize(env.HOT_SIZE, 100n, 500n);
  const COLD_SIZE = getSafeSize(env.COLD_SIZE, 50n, 200n);

  const MAX_TX = getSafeInt(env.MAX_TX, 5, 25);
  const TIME_BUDGET_MS = getSafeInt(env.TIME_BUDGET_MS, 25_000, 45_000);
  const ATTEMPT_TTL_SEC = getSafeInt(env.ATTEMPT_TTL_SEC, 600, 3600);

  const total = await client.readContract({
    address: env.REGISTRY_ADDRESS as Address,
    abi: registryAbi,
    functionName: "getAllLotteriesCount",
  });

  if (total === 0n) {
    console.log("ℹ️ Registry empty. Done.");
    // still try tweet sync
    try {
      await tweetSync(env);
    } catch (e: any) {
      console.warn("🐦 tweetSync failed:", e?.message || e);
    }
    return;
  }

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

  let nextCursor = startCold + safeColdSize;
  if (nextCursor >= total) nextCursor = 0n;

  const candidates = Array.from(new Set([...hotBatch, ...coldBatch]));
  if (candidates.length === 0) {
    console.log("ℹ️ No candidates. Done.");
    await env.BOT_STATE.put("cursor", nextCursor.toString());

    try {
      await tweetSync(env);
    } catch (e: any) {
      console.warn("🐦 tweetSync failed:", e?.message || e);
    }
    return;
  }

  const statusResults = await client.multicall({
    contracts: candidates.map((addr) => ({
      address: addr,
      abi: lotteryAbi,
      functionName: "status",
    })),
  });

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

    try {
      await tweetSync(env);
    } catch (e: any) {
      console.warn("🐦 tweetSync failed:", e?.message || e);
    }
    return;
  }

  console.log(`⚡ Found ${openLotteries.length} Open lotteries to analyze.`);

  let currentNonce = await client.getTransactionCount({
    address: account.address,
    blockTag: "pending",
  });

  const chunks = chunkArray(openLotteries, 25);
  let txCount = 0;

  for (const chunk of chunks) {
    if (txCount >= MAX_TX) break;
    if (Date.now() - startTimeMs > TIME_BUDGET_MS) break;

    const tNow = nowSec();

    // 8 calls per lottery (includes minTickets)
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

    const detailResults = await client.multicall({ contracts: detailCalls });

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
      ) continue;

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

      // value depends on cancel vs draw
      let value = 0n;

      if (!c.cancelPath) {
        const feeKey = `fee:${lower(c.entropyAddr)}:${lower(c.providerAddr)}`;
        const cachedFee = await env.BOT_STATE.get(feeKey);

        if (cachedFee) {
          try { value = BigInt(cachedFee); } catch { value = 0n; }
        } else {
          try {
            const fee = await client.readContract({
              address: c.entropyAddr,
              abi: entropyAbi,
              functionName: "getFee",
              args: [c.providerAddr],
            });
            value = BigInt(fee);
            await env.BOT_STATE.put(feeKey, value.toString(), { expirationTtl: 60 });
          } catch (e: any) {
            const msg = (e?.shortMessage || e?.message || "").toString();
            console.warn(`   ⚠️ Fee lookup reverted; skipping draw for now: ${msg}`);
            await env.BOT_STATE.put(attemptKey, `feeRevert:${Date.now()}`, {
              expirationTtl: Math.min(300, ATTEMPT_TTL_SEC),
            });
            continue;
          }
        }
      }

      // SIMULATE
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
        console.warn(`   ⏭️ Simulation revert: ${msg}`);
        await env.BOT_STATE.put(attemptKey, `revert:${Date.now()}`, {
          expirationTtl: Math.min(120, ATTEMPT_TTL_SEC),
        });
        continue;
      }

      await env.BOT_STATE.put(attemptKey, `${Date.now()}`, { expirationTtl: ATTEMPT_TTL_SEC });

      // SEND TX
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
      }
    }
  }

  await env.BOT_STATE.put("cursor", nextCursor.toString());
  console.log(`🏁 Run complete. txCount=${txCount} cursor=${nextCursor.toString()}`);

  // ✅ NEW: tweet only what’s already indexed (subgraph)
  try {
    await tweetSync(env);
  } catch (e: any) {
    console.warn("🐦 tweetSync failed:", e?.message || e);
  }
}