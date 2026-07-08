# noeco

Disable Windows EcoQoS throttling for matched processes.

## Files

```bash
~\noeco\config.txt          # rules
~\noeco\noeco.log           # log
~\noeco\noeco.exe           # program
```

## Config

```text
+python.exe
+parent:Code.exe
-svchost.exe
```

`+name` allows a process, 
`+parent:` allows child
processes, `-name` denies a process.

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
