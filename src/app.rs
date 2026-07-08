use std::{
    collections::{HashMap, HashSet},
    fs::{self, File, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
    thread::sleep,
    time::Duration,
};
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

use crate::{MODE, rule};

const CLASS_POWER_THROTTLING: i32 = 4;
const VERSION: u32 = 1;
const EXECUTION_SPEED: u32 = 0x1;
const SCAN_INTERVAL: Duration = Duration::from_secs(60);

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

pub fn run() {
    let cfg = home_file("config.txt");
    let log_path = home_file("noeco.log");
    let verbose = verbose_enabled();
    init_log(&log_path);
    let rules = match rule::load(&cfg) {
        Ok(r) => r,
        Err(e) => {
            log_line(
                &log_path,
                verbose,
                format!("failed to read config {}: {}", cfg.display(), e),
            );
            rule::Rule::default()
        }
    };
    log_line(
        &log_path,
        verbose,
        format!(
            "started mode={} config={} log={}",
            MODE,
            cfg.display(),
            log_path.display()
        ),
    );
    log_line(
        &log_path,
        verbose,
        format!(
            "rules allow_name={} allow_parent={} deny_name={}",
            rules.allow_name.len(),
            rules.allow_parent.len(),
            rules.deny_name.len()
        ),
    );

    let mut done = HashSet::<u32>::new();
    let mut failed = HashSet::<u32>::new();
    loop {
        let ps = processes();
        for p in ps.values() {
            if !rule::matched(p, &ps, &rules) {
                continue;
            }
            match noeco(p.pid) {
                Ok(()) if done.insert(p.pid) => {
                    log_line(
                        &log_path,
                        verbose,
                        format!("noeco pid={} name={}", p.pid, p.name),
                    );
                }
                Err(e) if failed.insert(p.pid) => {
                    log_line(
                        &log_path,
                        verbose,
                        format!("failed pid={} name={} error={}", p.pid, p.name, e),
                    );
                }
                _ => {}
            }
        }
        sleep(SCAN_INTERVAL);
    }
}

fn verbose_enabled() -> bool {
    !cfg!(feature = "daemon") || std::env::args_os().any(|x| x == "--verbose")
}

pub fn home_file(name: &str) -> PathBuf {
    std::env::var_os("USERPROFILE")
        .map(PathBuf::from)
        .unwrap_or_default()
        .join("noeco")
        .join(name)
}

fn init_log(path: &Path) {
    if let Some(dir) = path.parent() {
        let _ = fs::create_dir_all(dir);
    }
    let _ = File::create(path);
}

fn log_line(path: &Path, verbose: bool, msg: impl AsRef<str>) {
    let line = format!("[{}] {}", timestamp(), msg.as_ref());
    if verbose {
        eprintln!("{line}");
    }
    if let Ok(mut f) = OpenOptions::new().create(true).append(true).open(path) {
        let _ = writeln!(f, "{line}");
    }
}

fn timestamp() -> String {
    unsafe {
        let mut t: SYSTEMTIME = std::mem::zeroed();
        GetLocalTime(&mut t);
        format!(
            "{:04}-{:02}-{:02} {:02}:{:02}:{:02}",
            t.wYear, t.wMonth, t.wDay, t.wHour, t.wMinute, t.wSecond
        )
    }
}

fn processes() -> HashMap<u32, Proc> {
    let mut out = HashMap::new();
    unsafe {
        let h = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if h == INVALID_HANDLE_VALUE {
            return out;
        }
        let mut e: PROCESSENTRY32W = std::mem::zeroed();
        e.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;
        if Process32FirstW(h, &mut e) == 0 {
            let _ = CloseHandle(h);
            return out;
        }
        loop {
            let p = Proc {
                pid: e.th32ProcessID,
                parent: e.th32ParentProcessID,
                name: wide_name(&e.szExeFile),
            };
            out.insert(p.pid, p);
            if Process32NextW(h, &mut e) == 0 {
                break;
            }
        }
        let _ = CloseHandle(h);
    }

    out
}

fn wide_name(xs: &[u16]) -> String {
    let len = xs.iter().position(|&x| x == 0).unwrap_or(xs.len());
    String::from_utf16_lossy(&xs[..len])
}

fn noeco(pid: u32) -> Result<(), u32> {
    unsafe {
        let h = OpenProcess(
            PROCESS_SET_INFORMATION | PROCESS_QUERY_LIMITED_INFORMATION,
            0,
            pid,
        );
        if h.is_null() {
            return Err(GetLastError());
        }
        let mut s = PowerThrottle {
            version: VERSION,
            control: EXECUTION_SPEED,
            state: 0,
        };
        let ok = SetProcessInformation(
            h,
            CLASS_POWER_THROTTLING,
            &mut s as *mut _ as *mut _,
            std::mem::size_of::<PowerThrottle>() as u32,
        );
        let err = GetLastError();
        let _ = CloseHandle(h);
        if ok == 0 { Err(err) } else { Ok(()) }
    }
}
