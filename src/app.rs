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
    Foundation::{CloseHandle, GetLastError},
    System::Threading::{
        OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SET_INFORMATION,
        SetProcessInformation,
    },
};

use crate::{MODE, rule};

const CLASS_POWER_THROTTLING: i32 = 4;
const VERSION: u32 = 1;
const EXECUTION_SPEED: u32 = 0x1;

#[repr(C)]
struct PowerThrottle {
    version: u32,
    control: u32,
    state: u32,
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

    let mut sys = System::new_all();
    let mut done = HashSet::<u32>::new();
    let mut failed = HashSet::<u32>::new();

    loop {
        sys.refresh_processes(ProcessesToUpdate::All, true);

        let ps: HashMap<Pid, &sysinfo::Process> =
            sys.processes().iter().map(|(pid, p)| (*pid, p)).collect();

        for (pid, p) in sys.processes() {
            if !rule::matched(*pid, p, &ps, &rules) {
                continue;
            }

            let pid = pid.as_u32();
            match noeco(pid) {
                Ok(()) if done.insert(pid) => {
                    log_line(
                        &log_path,
                        verbose,
                        format!("noeco pid={} name={}", pid, rule::pname(p)),
                    );
                }
                Err(e) if failed.insert(pid) => {
                    log_line(
                        &log_path,
                        verbose,
                        format!("failed pid={} name={} error={}", pid, rule::pname(p), e),
                    );
                }
                _ => {}
            }
        }

        sleep(Duration::from_secs(5));
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
