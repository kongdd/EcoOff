use std::{
    ffi::OsString,
    fs, io,
    process::{Command, ExitStatus, Stdio},
};

use crate::app;

const TASK: &str = "noeco";
#[cfg(windows)]
const DETACHED_PROCESS: u32 = 0x00000008;

pub fn handle_args() -> io::Result<bool> {
    let Some(cmd) = command() else {
        return Ok(false);
    };
    match cmd.to_string_lossy().as_ref() {
        "install" => install()?,
        "uninstall" => {
            check(
                run("schtasks", ["/Delete", "/TN", TASK, "/F"])?,
                "schtasks /Delete",
            )?;
        }
        "start" => start()?,
        "stop" => stop()?,
        "log" => log()?,
        "status" => {
            check(
                run("schtasks", ["/Query", "/TN", TASK, "/FO", "LIST"])?,
                "schtasks /Query",
            )?;
        }
        "help" | "-h" | "--help" => usage(),
        _ => usage(),
    }
    Ok(true)
}

fn command() -> Option<OsString> {
    std::env::args_os().skip(1).find(|x| x != "--verbose")
}

fn install() -> io::Result<()> {
    check(run("schtasks", install_args())?, "schtasks /Create")
}

fn start() -> io::Result<()> {
    let exe = std::env::current_exe().unwrap_or_else(|_| "noeco.exe".into());
    let mut cmd = Command::new(exe);
    cmd.stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());

    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        cmd.creation_flags(DETACHED_PROCESS);
    }
    let child = cmd.spawn()?;
    println!("started noeco");
    println!("  pid     {}", child.id());
    println!("  log     {}", app::home_file("noeco.log").display());
    println!("  config  {}", app::home_file("config.txt").display());
    Ok(())
}

fn install_args() -> Vec<OsString> {
    let exe = std::env::current_exe().unwrap_or_else(|_| "noeco.exe".into());
    vec![
        "/Create".into(),
        "/TN".into(),
        TASK.into(),
        "/TR".into(),
        exe.into_os_string(),
        "/SC".into(),
        "ONLOGON".into(),
        "/RL".into(),
        "HIGHEST".into(),
        "/F".into(),
    ]
}

fn run<I, S>(program: &str, args: I) -> io::Result<ExitStatus>
where
    I: IntoIterator<Item = S>,
    S: AsRef<std::ffi::OsStr>,
{
    Command::new(program).args(args).status()
}

fn check(status: ExitStatus, name: &str) -> io::Result<()> {
    if status.success() {
        return Ok(());
    }
    Err(io::Error::other(format!("{name} failed: {status}")))
}

fn stop() -> io::Result<()> {
    let status = run("taskkill", ["/IM", "noeco.exe", "/F"])?;
    if status.success() {
        println!("stopped noeco");
    } else {
        println!("noeco was not running");
    }
    Ok(())
}

fn log() -> io::Result<()> {
    let text = fs::read_to_string(app::home_file("noeco.log"))?;
    print!("{text}");
    Ok(())
}

fn usage() {
    eprintln!("usage: noeco [start|stop|log|install|uninstall|status|help]");
}
