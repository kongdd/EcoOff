# noeco

> 200kb干死Win11效能模式——noeco。   
> 台式机不需要节能，效率优先，老电脑还能鞠躬尽瘁再战几年。

Disable Windows EcoQoS throttling for matched processes.

## Files

```bash
~/noeco/config.toml         # config
~/noeco/noeco.log           # log
~/noeco/noeco.exe           # program
```

## Config

```toml
scan_interval_secs = 60
allow = ["python.exe", "node.exe", "Code.exe"]
allow_parent = ["Code.exe"]
deny = ["svchost.exe", "explorer.exe"]
```

- `allow`        : matches process names. 
- `allow_parent` : matches child processes. 
- `deny`         : excludes process names. Config reloads on change.

## Build

```bash
cargo build --release
```

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
