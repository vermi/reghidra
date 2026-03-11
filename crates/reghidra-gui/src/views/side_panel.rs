use crate::app::{ReghidraApp, SidePanel};
use egui::Ui;

pub fn render(app: &mut ReghidraApp, ui: &mut Ui) {
    let Some(ref project) = app.project else {
        return;
    };

    let query = app.search_query.to_lowercase();
    let selected_addr = app.selected_address;

    // Pre-collect data we need to avoid borrow conflicts
    let mut navigate_to: Option<u64> = None;

    match app.side_panel {
        SidePanel::Functions => {
            let functions = project.functions();
            let filtered: Vec<_> = if query.is_empty() {
                functions.iter().collect()
            } else {
                functions
                    .iter()
                    .filter(|(addr, name)| {
                        name.to_lowercase().contains(&query)
                            || format!("0x{addr:x}").contains(&query)
                    })
                    .collect()
            };

            ui.label(format!("{} functions", filtered.len()));
            ui.separator();

            egui::ScrollArea::vertical().show(ui, |ui| {
                for (addr, name) in &filtered {
                    let label = format!("0x{addr:08x}  {name}");
                    let selected = selected_addr == Some(*addr);
                    if ui.selectable_label(selected, &label).clicked() {
                        navigate_to = Some(*addr);
                    }
                }
            });
        }

        SidePanel::Symbols => {
            let filtered: Vec<_> = project
                .binary
                .symbols
                .iter()
                .filter(|s| {
                    query.is_empty()
                        || s.name.to_lowercase().contains(&query)
                        || format!("0x{:x}", s.address).contains(&query)
                })
                .collect();

            ui.label(format!("{} symbols", filtered.len()));
            ui.separator();

            egui::ScrollArea::vertical().show(ui, |ui| {
                for sym in &filtered {
                    let kind = match sym.kind {
                        reghidra_core::SymbolKind::Function => "fn",
                        reghidra_core::SymbolKind::Object => "obj",
                        reghidra_core::SymbolKind::Section => "sec",
                        reghidra_core::SymbolKind::File => "file",
                        reghidra_core::SymbolKind::Unknown => "?",
                    };
                    let label = format!("[{kind}] 0x{:08x}  {}", sym.address, sym.name);
                    let selected = selected_addr == Some(sym.address);
                    if ui.selectable_label(selected, &label).clicked() {
                        navigate_to = Some(sym.address);
                    }
                }
            });
        }

        SidePanel::Imports => {
            let filtered: Vec<_> = project
                .binary
                .imports
                .iter()
                .filter(|s| query.is_empty() || s.name.to_lowercase().contains(&query))
                .collect();

            ui.label(format!("{} imports", filtered.len()));
            ui.separator();

            egui::ScrollArea::vertical().show(ui, |ui| {
                for imp in &filtered {
                    let label = format!("0x{:08x}  {}", imp.address, imp.name);
                    let selected = selected_addr == Some(imp.address);
                    if ui.selectable_label(selected, &label).clicked() {
                        navigate_to = Some(imp.address);
                    }
                }
            });
        }

        SidePanel::Exports => {
            let filtered: Vec<_> = project
                .binary
                .exports
                .iter()
                .filter(|s| query.is_empty() || s.name.to_lowercase().contains(&query))
                .collect();

            ui.label(format!("{} exports", filtered.len()));
            ui.separator();

            egui::ScrollArea::vertical().show(ui, |ui| {
                for exp in &filtered {
                    let label = format!("0x{:08x}  {}", exp.address, exp.name);
                    let selected = selected_addr == Some(exp.address);
                    if ui.selectable_label(selected, &label).clicked() {
                        navigate_to = Some(exp.address);
                    }
                }
            });
        }

        SidePanel::Sections => {
            let sections: Vec<_> = project.binary.sections.iter().collect();

            ui.label(format!("{} sections", sections.len()));
            ui.separator();

            egui::ScrollArea::vertical().show(ui, |ui| {
                for sec in &sections {
                    if !query.is_empty() && !sec.name.to_lowercase().contains(&query) {
                        continue;
                    }
                    let perms = format!(
                        "{}{}{}",
                        if sec.is_readable { "r" } else { "-" },
                        if sec.is_writable { "w" } else { "-" },
                        if sec.is_executable { "x" } else { "-" },
                    );
                    let label = format!(
                        "{:<16} 0x{:08x} [{}] size=0x{:x}",
                        sec.name, sec.virtual_address, perms, sec.virtual_size
                    );
                    let selected = selected_addr == Some(sec.virtual_address);
                    if ui.selectable_label(selected, &label).clicked() {
                        navigate_to = Some(sec.virtual_address);
                    }
                }
            });
        }

        SidePanel::Strings => {
            let filtered: Vec<_> = project
                .binary
                .strings
                .iter()
                .filter(|s| {
                    query.is_empty()
                        || s.value.to_lowercase().contains(&query)
                        || s.auto_name.to_lowercase().contains(&query)
                })
                .collect();

            ui.label(format!("{} strings", filtered.len()));
            ui.separator();

            egui::ScrollArea::vertical().show(ui, |ui| {
                for s in &filtered {
                    let display_val: String = s.value.chars().take(50).collect();
                    let label = format!(
                        "0x{:08x}  {}  \"{}\"",
                        s.address, s.auto_name, display_val
                    );
                    let selected = selected_addr == Some(s.address);
                    if ui.selectable_label(selected, &label).clicked() {
                        navigate_to = Some(s.address);
                    }
                }
            });
        }
    }

    if let Some(addr) = navigate_to {
        app.navigate_to(addr);
    }
}
