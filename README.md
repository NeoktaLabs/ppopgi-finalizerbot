# Ppopgi (뽑기) — Finalizer Bot

This repository contains the **Finalizer Bot** for Ppopgi, a permissionless automation service ensuring raffle liveness on **Etherlink (Tezos L2)**.

While anyone can finalize a raffle manually, this bot acts as a safety net to prevent raffles from becoming stuck.

## What the bot does
- Scans the on-chain registry for active raffles
- Detects raffles eligible for finalization or cancellation
- Calls `finalize()` with the correct randomness fee
- Ensures raffles always reach a terminal state

## Design Principles
- Permissionless (no special privileges)
- Exact fee payment (no overpayment dust)
- Idempotent and crash-safe execution
- Minimal RPC and gas usage
- No custody of user funds

## Technology
- Cloudflare Workers (Cron)
- viem
- Etherlink RPC
- Cloudflare KV (locking, cursors, idempotency)

## Operational Notes
- Runs every minute
- Uses a dedicated low-balance hot wallet
- Safe to run even when no raffles exist

## Important Notice
This bot is optional infrastructure and does not introduce trust assumptions.  
Raffles remain fully permissionless even without it.

The bot is experimental and provided as-is.