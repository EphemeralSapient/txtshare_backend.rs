[![Rust](https://github.com/EphemeralSapient/txtshare_backend.rs/actions/workflows/rust.yml/badge.svg?branch=main)](https://github.com/EphemeralSapient/txtshare_backend.rs/actions/workflows/rust.yml)

## Remake

This repo basically attempt of re-do existing [backend](https://raw.githubusercontent.com/EphemeralSapient/txtshare_backend/main/README.md) written in Express.js to Rust with gRPC.

Usage and design can be found under `proto/` folder.

Uses postgreSQL and similar design to original backend API structure.

I was interested in Rust for benchmark ( yet to do benchmark between existing and new implementation )

## Tech used and plans

1. Tonic along with tokio-postgres client.
2. jsonwebtoken and other similar stuff in original repo

I'm not sure when I'll add redis support but then kinda eager to deploy this on GCP with free tier [PostgreSQL on micro E2 free tier and deploy this on app engine]

Docker support is on next TODO list