# noeco

> noeco.exe干死WIN11效率模式, 仅200kb
Disable Windows EcoQoS throttling for matched processes.

## Files

```bash
~\noeco\config.toml         # config
~\noeco\noeco.log           # log
~\noeco\noeco.exe           # program
```

## Config

```toml
scan_interval_secs = 60
allow = ["python.exe", "node.exe", "Code.exe"]
allow_parent = ["Code.exe"]
deny = ["svchost.exe", "explorer.exe"]
```

`allow` matches process names. `allow_parent` matches child processes. `deny`
excludes process names. Config reloads on change.

## Run

```bash
noeco --verbose

noeco start
noeco log
noeco stop

# Optional: run at login
noeco install
noeco uninstall
```

- `start` runs noeco in the background; it survives terminal close.
- `install` registers a Windows logon task.

## Build

```bash
cargo build --release
cargo build --release --features daemon
```

Cargo always writes `target\release\noeco.exe`. Use the normal build for
console checking, and the `daemon` build for background use.
