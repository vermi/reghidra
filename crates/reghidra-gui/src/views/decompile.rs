use crate::app::ReghidraApp;
use egui::{RichText, Ui};

pub fn render(app: &mut ReghidraApp, ui: &mut Ui) {
    let Some(ref project) = app.project else {
        return;
    };

    let selected_addr = app.selected_address.unwrap_or(0);
    let mono = egui::TextStyle::Monospace;
    let theme = &app.theme;

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

    let decomp = project.decompile(func_entry);

    let Some(code) = decomp else {
        ui.label("Could not decompile this function.");
        return;
    };

    ui.label(RichText::new(format!("Decompiled: {func_name}")).strong());
    ui.separator();

    egui::ScrollArea::vertical()
        .auto_shrink([false, false])
        .show(ui, |ui| {
            for line in code.lines() {
                let color = theme.colorize_decompile_line(line);
                ui.label(RichText::new(line).text_style(mono.clone()).color(color));
            }
        });
}
