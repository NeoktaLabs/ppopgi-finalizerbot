# Ppopgi Finalizer Bot

The Ppopgi Finalizer Bot is a permissionless automation service that ensures raffles on **Ppopgi** always reach a final state.

Running on **Cloudflare Workers (Cron)**, the bot continuously scans the on-chain registry and identifies raffles that are eligible to be finalized or canceled. When conditions are met, it safely calls the `finalize()` function using exact oracle fees and on-chain simulation to avoid wasted transactions.

The bot is designed with reliability and efficiency in mind:
- Hybrid hot/cold scanning to scale to thousands of raffles
- Multicall-based filtering to minimize RPC load
- Idempotency guards to prevent repeated fee spending
- Exact-fee payments for entropy requests
- Serverless execution with no long-running infrastructure

The Finalizer Bot guarantees protocol liveness while keeping operational costs low and predictable.