mod annotations;
mod app;
mod help;
mod palette;
mod theme;
mod undo;
mod views;

use app::ReghidraApp;

fn main() -> eframe::Result {
    env_logger::init();

    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1400.0, 900.0])
            .with_min_inner_size([800.0, 600.0])
            .with_title("Reghidra"),
        ..Default::default()
    };

    eframe::run_native(
        "Reghidra",
        options,
        Box::new(|cc| Ok(Box::new(ReghidraApp::new(cc)))),
    )
}
