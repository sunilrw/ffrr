# FFRR Development & Build Rules

## Fast Incremental Builds (Low CPU & Fast Link Policy)
- **During development, iteration, and testing**:
  - Use `cargo check` (1–2s) or `cargo build` (fast incremental dev build) instead of full release/cross-compile builds.
  - `.cargo/config.toml` sets `[build] jobs = 4` so Cargo never pegs all CPU cores on the host machine.
  - `[profile.dev]` and `[profile.release]` in `Cargo.toml` have `lto = false` and `incremental = true` so incremental edits recompile and link in ~2–5 seconds instead of running expensive whole-program LTO linking.
- **Full Optimized Release / Windows `.exe` Distribution Builds**:
  - Only run full distribution builds (`cargo build --profile dist` and `cargo build --profile dist --target x86_64-pc-windows-gnu`) when the user explicitly confirms we are ready for a final release/dist package.
