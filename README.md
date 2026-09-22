# EcoOff

> 面向 Windows 的 EcoQoS 控制台：解除目标进程的效能限制。

EcoOff 现使用 Tauri 2 提供本地界面，可查看运行状态、可折叠进程树和日志，并直接编辑规则。应用启动时会自动删除旧版 `noeco` 登录计划任务；Release 版本不显示控制台黑窗。

## 数据文件

```text
~/ecooff/config.toml   # 配置
~/ecooff/ecooff.log    # 日志
```

配置修改后自动生效：

```toml
scan_interval_secs = 20
allow = ["python.exe", "node.exe", "Code.exe"]
allow_parent = ["Code.exe"]
deny = ["svchost.exe", "explorer.exe"]
```

- `allow`：按进程名匹配。
- `allow_parent`：匹配指定进程的全部后代。
- `deny`：排除进程，优先级最高。

## 构建

Windows 需安装 Microsoft C++ Build Tools 和 WebView2，并在 x64 Native Tools 终端构建：

```powershell
cargo run
cargo build --release
```

产物仅一个：`target\release\ecooff.exe`。
