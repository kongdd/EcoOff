# AGENTS.md

## Code Style

- Keep code compact and readable; avoid decorative blank lines.
- Prefer small, direct functions over extra abstraction.
- Keep line width under 100 chars.
- Use early returns for error/edge cases.
- Do not add dependencies unless they remove real complexity.

## Project Rules

- Runtime config is `~\ecooff\config.toml`.
- `config.toml` changes should reload without restarting EcoOff.
- `scan_interval_secs` controls the scan interval.
- `ecooff log` prints only the last 20 lines, then the log path.
- Cargo outputs one binary: `target\release\ecooff.exe`.
- Keep installed copies in sync when needed:
  - `~\ecooff\ecooff.exe`
  - `~\.cargo\bin\ecooff.exe`

## Verify

Run before finishing code changes:

```powershell
cargo fmt
cargo build --release
cargo clippy --all-targets --all-features
```
