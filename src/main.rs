#![cfg_attr(feature = "daemon", windows_subsystem = "windows")]

mod app;
mod rule;
mod task;

const MODE: &str = if cfg!(feature = "daemon") {
    "daemon"
} else {
    "verbose"
};

fn main() -> std::io::Result<()> {
    if task::handle_args()? {
        return Ok(());
    }
    app::run();
    Ok(())
}
