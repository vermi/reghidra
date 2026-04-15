#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use reghidra_gui::ReghidraApp;

fn load_icon() -> egui::IconData {
    let png_bytes = include_bytes!("../../../assets/reghidra.png");
    let img = image::load_from_memory(png_bytes)
        .expect("Failed to decode icon PNG")
        .into_rgba8();
    let (width, height) = img.dimensions();
    egui::IconData {
        rgba: img.into_raw(),
        width,
        height,
    }
}

fn main() -> eframe::Result {
    env_logger::init();

    let icon = load_icon();

    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1400.0, 900.0])
            .with_min_inner_size([800.0, 600.0])
            .with_title("Reghidra")
            .with_icon(icon),
        ..Default::default()
    };

    eframe::run_native(
        "Reghidra",
        options,
        Box::new(|cc| Ok(Box::new(ReghidraApp::new(cc)))),
    )
}
