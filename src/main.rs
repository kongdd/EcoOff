#![cfg_attr(
    all(feature = "daemon", not(debug_assertions)),
    windows_subsystem = "windows"
)]

mod app;
mod rule;
mod task;

#[cfg(feature = "daemon")]
const MODE: &str = "daemon";

#[cfg(not(feature = "daemon"))]
const MODE: &str = "verbose";

fn main() -> std::io::Result<()> {
    if task::handle_args()? {
        return Ok(());
    }
    app::run();
    Ok(())
}
