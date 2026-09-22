#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod app;
mod rule;

fn main() {
    app::remove_legacy_task();
    tauri::Builder::default()
        .manage(app::Monitor::start())
        .invoke_handler(tauri::generate_handler![app::dashboard, app::save_config])
        .run(tauri::generate_context!())
        .expect("failed to run EcoOff");
}
