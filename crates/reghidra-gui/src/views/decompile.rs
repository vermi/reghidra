use crate::app::ReghidraApp;
use egui::{RichText, Ui};

pub fn render(app: &mut ReghidraApp, ui: &mut Ui) {
    let Some(ref project) = app.project else {
        return;
    };

    let selected_addr = app.selected_address.unwrap_or(0);
    let mono = egui::TextStyle::Monospace;

    let func = project
        .analysis
        .function_containing(selected_addr)
        .or_else(|| project.analysis.function_at(selected_addr));

    let Some(func) = func else {
        ui.label("Select a function to view decompiled output.");
        return;
    };

    let func_entry = func.entry_address;
    let func_name = func.name.clone();

    // Use cached decompile output if the function hasn't changed
    let needs_decompile = match &app.decompile_cache {
        Some((cached_entry, _)) => *cached_entry != func_entry,
        None => true,
    };
    if needs_decompile {
        if let Some(code) = project.decompile(func_entry) {
            app.decompile_cache = Some((func_entry, code));
        } else {
            app.decompile_cache = None;
        }
    }

    let Some((_, ref code)) = app.decompile_cache else {
        ui.label("Could not decompile this function.");
        return;
    };

    ui.label(RichText::new(format!("Decompiled: {func_name}")).strong());
    ui.separator();

    // Clone to avoid borrow conflict with app.theme
    let lines: Vec<&str> = code.lines().collect();
    let theme_clone = app.theme.clone();

    egui::ScrollArea::vertical()
        .auto_shrink([false, false])
        .show(ui, |ui| {
            for line in &lines {
                let color = theme_clone.colorize_decompile_line(line);
                ui.label(RichText::new(*line).text_style(mono.clone()).color(color));
            }
        });
}
