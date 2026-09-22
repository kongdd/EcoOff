use std::{
    collections::HashMap,
    fs::{self, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
    process::Command,
    sync::{Arc, Mutex},
    thread::{self, sleep},
    time::Duration,
};

use serde::Serialize;
use tauri::State;
use windows_sys::Win32::{
    Foundation::{CloseHandle, GetLastError, INVALID_HANDLE_VALUE, SYSTEMTIME},
    System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, PROCESSENTRY32W, Process32FirstW, Process32NextW,
        TH32CS_SNAPPROCESS,
    },
    System::SystemInformation::GetLocalTime,
    System::Threading::{
        OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SET_INFORMATION,
        SetProcessInformation,
    },
};

use crate::rule::{self, EditableConfig};

const CLASS_POWER_THROTTLING: i32 = 4;
const VERSION: u32 = 1;
const EXECUTION_SPEED: u32 = 0x1;

#[repr(C)]
struct PowerThrottle {
    version: u32,
    control: u32,
    state: u32,
}

pub struct Proc {
    pub pid: u32,
    pub parent: u32,
    pub name: String,
}

#[derive(Clone, Default, Serialize)]
struct ScanState {
    last_scan: String,
    scanned: usize,
    processes: Vec<ProcessState>,
}

#[derive(Clone, Serialize)]
struct ProcessState {
    pid: u32,
    parent_pid: u32,
    name: String,
    parent: String,
    ok: bool,
    detail: String,
}

pub struct Monitor(Arc<Mutex<ScanState>>);

impl Monitor {
    pub fn start() -> Self {
        let state = Arc::new(Mutex::new(ScanState::default()));
        let worker = Arc::clone(&state);
        thread::spawn(move || run(worker));
        Self(state)
    }
}

#[derive(Serialize)]
pub struct Dashboard {
    active: bool,
    last_scan: String,
    scanned: usize,
    processes: Vec<ProcessState>,
    config: EditableConfig,
    logs: Vec<String>,
    config_path: String,
    log_path: String,
}

#[tauri::command]
pub fn dashboard(monitor: State<'_, Monitor>) -> Dashboard {
    let config_path = home_file("config.toml");
    let log_path = home_file("ecooff.log");
    let scan = monitor
        .0
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .clone();
    let config = rule::load(&config_path).unwrap_or_default();
    Dashboard {
        active: true,
        last_scan: scan.last_scan,
        scanned: scan.scanned,
        processes: scan.processes,
        config: (&config).into(),
        logs: last_lines(&log_path, 120),
        config_path: config_path.display().to_string(),
        log_path: log_path.display().to_string(),
    }
}

#[tauri::command]
pub fn save_config(config: EditableConfig) -> Result<(), String> {
    let path = home_file("config.toml");
    rule::save(&path, config).map_err(|error| error.to_string())?;
    log_line(&home_file("ecooff.log"), "config saved");
    Ok(())
}

pub fn remove_legacy_task() {
    let mut command = Command::new("schtasks");
    command.args(["/Delete", "/TN", "noeco", "/F"]);
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        command.creation_flags(0x08000000);
    }
    let _ = command.output();
}

fn run(state: Arc<Mutex<ScanState>>) {
    let config_path = home_file("config.toml");
    let log_path = home_file("ecooff.log");
    init_files(&config_path, &log_path);
    log_line(&log_path, "started ui mode");
    let mut config = rule::load(&config_path).unwrap_or_default();
    let mut previous = HashMap::new();

    loop {
        if let Ok(updated) = rule::load(&config_path) {
            config = updated;
        }
        let all = processes();
        let mut shown = Vec::new();
        let mut current = HashMap::new();
        for process in all.values() {
            if !rule::matched(process, &all, &config.rule) {
                continue;
            }
            let result = disable_eco_qos(process.pid);
            if previous.get(&process.pid) != Some(&result) {
                let message = match result {
                    Ok(()) => format!("ecooff pid={} name={}", process.pid, process.name),
                    Err(error) => format!(
                        "failed pid={} name={} error={error}",
                        process.pid, process.name
                    ),
                };
                log_line(&log_path, message);
            }
            let (ok, detail) = match result {
                Ok(()) => (true, "已解除效能限制".to_string()),
                Err(error) => (false, format!("失败 · {error}")),
            };
            shown.push(ProcessState {
                pid: process.pid,
                parent_pid: process.parent,
                name: process.name.clone(),
                parent: all
                    .get(&process.parent)
                    .map(|parent| parent.name.clone())
                    .unwrap_or_else(|| "—".into()),
                ok,
                detail,
            });
            current.insert(process.pid, result);
        }
        previous = current;
        shown.sort_unstable_by(|a, b| a.name.cmp(&b.name).then(a.pid.cmp(&b.pid)));
        *state.lock().unwrap_or_else(|error| error.into_inner()) = ScanState {
            last_scan: timestamp(),
            scanned: all.len(),
            processes: shown,
        };
        sleep(Duration::from_secs(config.scan_interval_secs));
    }
}

pub fn home_file(name: &str) -> PathBuf {
    std::env::var_os("USERPROFILE")
        .map(PathBuf::from)
        .unwrap_or_default()
        .join("ecooff")
        .join(name)
}

fn init_files(config: &Path, log: &Path) {
    if let Some(dir) = config.parent() {
        let _ = fs::create_dir_all(dir);
    }
    if !config.exists() {
        let legacy = config
            .parent()
            .unwrap_or(Path::new(""))
            .with_file_name("noeco")
            .join("config.toml");
        if fs::copy(legacy, config).is_err() {
            let _ = rule::save(config, EditableConfig::from(&rule::Config::default()));
        }
    }
    let _ = OpenOptions::new().create(true).append(true).open(log);
}

fn last_lines(path: &Path, count: usize) -> Vec<String> {
    let Ok(text) = fs::read_to_string(path) else {
        return Vec::new();
    };
    let lines = text.lines().collect::<Vec<_>>();
    lines[lines.len().saturating_sub(count)..]
        .iter()
        .map(|line| (*line).to_string())
        .collect()
}

fn log_line(path: &Path, message: impl AsRef<str>) {
    if let Ok(mut file) = OpenOptions::new().create(true).append(true).open(path) {
        let _ = writeln!(file, "[{}] {}", timestamp(), message.as_ref());
    }
}

fn timestamp() -> String {
    unsafe {
        let mut time: SYSTEMTIME = std::mem::zeroed();
        GetLocalTime(&mut time);
        format!(
            "{:04}-{:02}-{:02} {:02}:{:02}:{:02}",
            time.wYear, time.wMonth, time.wDay, time.wHour, time.wMinute, time.wSecond
        )
    }
}

fn processes() -> HashMap<u32, Proc> {
    let mut out = HashMap::new();
    unsafe {
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if snapshot == INVALID_HANDLE_VALUE {
            return out;
        }
        let mut entry: PROCESSENTRY32W = std::mem::zeroed();
        entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;
        if Process32FirstW(snapshot, &mut entry) == 0 {
            let _ = CloseHandle(snapshot);
            return out;
        }
        loop {
            let process = Proc {
                pid: entry.th32ProcessID,
                parent: entry.th32ParentProcessID,
                name: wide_name(&entry.szExeFile),
            };
            out.insert(process.pid, process);
            if Process32NextW(snapshot, &mut entry) == 0 {
                break;
            }
        }
        let _ = CloseHandle(snapshot);
    }
    out
}

fn wide_name(values: &[u16]) -> String {
    let len = values
        .iter()
        .position(|&value| value == 0)
        .unwrap_or(values.len());
    String::from_utf16_lossy(&values[..len])
}

fn disable_eco_qos(pid: u32) -> Result<(), u32> {
    unsafe {
        let process = OpenProcess(
            PROCESS_SET_INFORMATION | PROCESS_QUERY_LIMITED_INFORMATION,
            0,
            pid,
        );
        if process.is_null() {
            return Err(GetLastError());
        }
        let mut state = PowerThrottle {
            version: VERSION,
            control: EXECUTION_SPEED,
            state: 0,
        };
        let ok = SetProcessInformation(
            process,
            CLASS_POWER_THROTTLING,
            &mut state as *mut _ as *mut _,
            std::mem::size_of::<PowerThrottle>() as u32,
        );
        let error = GetLastError();
        let _ = CloseHandle(process);
        if ok == 0 { Err(error) } else { Ok(()) }
    }
}
