#![cfg_attr(
    all(feature = "daemon", not(debug_assertions)),
    windows_subsystem = "windows"
)]

use std::{
    collections::{HashMap, HashSet},
    fs::{self, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
    thread::sleep,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use sysinfo::{Pid, ProcessesToUpdate, System};

use windows_sys::Win32::{
    Foundation::CloseHandle,
    System::Threading::{
        OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SET_INFORMATION,
        SetProcessInformation,
    },
};

const CLASS_POWER_THROTTLING: i32 = 4;
const VERSION: u32 = 1;
const EXECUTION_SPEED: u32 = 0x1;

#[cfg(feature = "daemon")]
const MODE: &str = "daemon";
#[cfg(not(feature = "daemon"))]
const MODE: &str = "verbose";

#[repr(C)]
struct PowerThrottle {
    version: u32,
    control: u32,
    state: u32,
}

#[derive(Default)]
struct Rule {
    allow_name: HashSet<String>,
    allow_path: Vec<String>,
    allow_parent: HashSet<String>,
    deny_name: HashSet<String>,
}

fn low(s: impl AsRef<str>) -> String {
    s.as_ref().to_ascii_lowercase()
}

fn home_file(name: &str) -> PathBuf {
    std::env::var_os("USERPROFILE")
        .map(PathBuf::from)
        .unwrap_or_default()
        .join("noeco")
        .join(name)
}

fn config_path() -> PathBuf {
    home_file("config.txt")
}

fn log_path() -> PathBuf {
    home_file("noeco.log")
}

fn verbose_enabled() -> bool {
    !cfg!(feature = "daemon") || std::env::args_os().any(|x| x == "--verbose")
}

fn log_line(path: &Path, verbose: bool, msg: impl AsRef<str>) {
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or_default();
    let line = format!("[{}] {}", ts, msg.as_ref());

    if verbose {
        eprintln!("{line}");
    }

    if let Ok(mut f) = OpenOptions::new().create(true).append(true).open(path) {
        let _ = writeln!(f, "{line}");
    }
}

fn load_rules(path: &Path) -> std::io::Result<Rule> {
    let mut r = Rule::default();
    let text = fs::read_to_string(path)?;

    for line in text.lines() {
        let s = line.trim();

        if s.is_empty() || s.starts_with('#') {
            continue;
        }

        if let Some(x) = s.strip_prefix("+path:") {
            r.allow_path.push(low(x));
        } else if let Some(x) = s.strip_prefix("+parent:") {
            r.allow_parent.insert(low(x));
        } else if let Some(x) = s.strip_prefix('+') {
            r.allow_name.insert(low(x));
        } else if let Some(x) = s.strip_prefix('-') {
            r.deny_name.insert(low(x));
        }
    }

    Ok(r)
}

fn pname(p: &sysinfo::Process) -> String {
    p.name().to_string_lossy().to_string()
}

fn pexe(p: &sysinfo::Process) -> String {
    p.exe()
        .map(|x| x.to_string_lossy().to_string())
        .unwrap_or_default()
}

fn has_parent(pid: Pid, ps: &HashMap<Pid, &sysinfo::Process>, names: &HashSet<String>) -> bool {
    let mut cur = pid;

    for _ in 0..32 {
        let Some(p) = ps.get(&cur) else {
            return false;
        };

        let Some(ppid) = p.parent() else {
            return false;
        };

        let Some(parent) = ps.get(&ppid) else {
            return false;
        };

        if names.contains(&low(pname(parent))) {
            return true;
        }

        cur = ppid;
    }

    false
}

fn matched(pid: Pid, p: &sysinfo::Process, ps: &HashMap<Pid, &sysinfo::Process>, r: &Rule) -> bool {
    let name = low(pname(p));

    if r.deny_name.contains(&name) {
        return false;
    }

    if r.allow_name.contains(&name) {
        return true;
    }

    let exe = low(pexe(p));

    if r.allow_path.iter().any(|x| exe.contains(x)) {
        return true;
    }

    has_parent(pid, ps, &r.allow_parent)
}

fn noeco(pid: u32) -> Result<(), u32> {
    unsafe {
        let h = OpenProcess(
            PROCESS_SET_INFORMATION | PROCESS_QUERY_LIMITED_INFORMATION,
            0,
            pid,
        );

        if h.is_null() {
            return Err(windows_sys::Win32::Foundation::GetLastError());
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
        let err = windows_sys::Win32::Foundation::GetLastError();

        let _ = CloseHandle(h);

        match ok {
            0 => Err(err),
            _ => Ok(()),
        }
    }
}

fn main() {
    let cfg = config_path();
    let log = log_path();
    let verbose = verbose_enabled();
    let rules = match load_rules(&cfg) {
        Ok(r) => r,
        Err(e) => {
            log_line(
                &log,
                verbose,
                format!("failed to read config {}: {}", cfg.display(), e),
            );
            Rule::default()
        }
    };

    log_line(
        &log,
        verbose,
        format!(
            "started mode={} config={} log={} allow_name={} allow_path={} allow_parent={} deny_name={}",
            MODE,
            cfg.display(),
            log.display(),
            rules.allow_name.len(),
            rules.allow_path.len(),
            rules.allow_parent.len(),
            rules.deny_name.len()
        ),
    );

    let mut sys = System::new_all();
    let mut printed = HashSet::<u32>::new();
    let mut failed = HashSet::<u32>::new();

    loop {
        sys.refresh_processes(ProcessesToUpdate::All, true);

        let ps: HashMap<Pid, &sysinfo::Process> =
            sys.processes().iter().map(|(pid, p)| (*pid, p)).collect();

        for (pid, p) in sys.processes() {
            if !matched(*pid, p, &ps, &rules) {
                continue;
            }

            let pid = pid.as_u32();

            match noeco(pid) {
                Ok(()) if printed.insert(pid) => {
                    let name = pname(p);
                    log_line(&log, verbose, format!("noeco pid={} name={}", pid, name));
                }
                Err(e) if failed.insert(pid) => {
                    log_line(
                        &log,
                        verbose,
                        format!("failed pid={} name={} error={}", pid, pname(p), e),
                    );
                }
                _ => {}
            }
        }
        sleep(Duration::from_secs(5));
    }
}
