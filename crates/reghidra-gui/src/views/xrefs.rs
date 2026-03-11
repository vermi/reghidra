use crate::app::ReghidraApp;
use egui::{RichText, Ui};

/// Render cross-references panel for the currently selected address.
pub fn render(app: &mut ReghidraApp, ui: &mut Ui) {
    let Some(ref project) = app.project else {
        return;
    };

    let selected_addr = app.selected_address.unwrap_or(0);
    let mono = egui::TextStyle::Monospace;
    let theme = &app.theme;

    let xrefs_to = project.analysis.xrefs.xrefs_to(selected_addr);
    let xrefs_from = project.analysis.xrefs.xrefs_from(selected_addr);

    let to_entries: Vec<_> = xrefs_to
        .iter()
        .map(|x| {
            let caller = project
                .analysis
                .function_containing(x.from)
                .map(|f| f.name.clone())
                .unwrap_or_else(|| format!("0x{:x}", x.from));
            (x.from, caller, x.kind)
        })
        .collect();

    let from_entries: Vec<_> = xrefs_from
        .iter()
        .map(|x| {
            let target_name = project
                .function_name(x.to)
                .map(|s| s.to_string())
                .or_else(|| {
                    project
                        .binary
                        .strings
                        .iter()
                        .find(|s| s.address == x.to)
                        .map(|s| format!("\"{}\"", s.value.chars().take(40).collect::<String>()))
                })
                .unwrap_or_else(|| format!("0x{:x}", x.to));
            (x.to, target_name, x.kind)
        })
        .collect();

    let mut navigate_to = None;
    let mut new_hovered: Option<u64> = None;

    ui.label(RichText::new(format!("Xrefs for 0x{selected_addr:08x}")).strong());
    ui.separator();

    if to_entries.is_empty() && from_entries.is_empty() {
        ui.label("No cross-references at this address.");
        return;
    }

    egui::ScrollArea::vertical()
        .id_salt("xrefs_scroll")
        .auto_shrink([false, false])
        .show(ui, |ui| {
            if !to_entries.is_empty() {
                ui.label(
                    RichText::new(format!("References TO this address ({})", to_entries.len()))
                        .color(theme.xref_to_header),
                );
                for (from_addr, caller, kind) in &to_entries {
                    let resp = ui
                        .horizontal(|ui| {
                            if ui
                                .link(
                                    RichText::new(format!("0x{from_addr:08x}"))
                                        .text_style(mono.clone())
                                        .color(theme.addr_normal),
                                )
                                .clicked()
                            {
                                navigate_to = Some(*from_addr);
                            }
                            let kind_str = format!("[{kind:?}]");
                            let kind_color = theme.xref_kind_color(*kind);
                            ui.label(
                                RichText::new(format!("  {kind_str:<20} {caller}"))
                                    .text_style(mono.clone())
                                    .color(kind_color),
                            );
                        })
                        .response;
                    if resp.hovered() {
                        new_hovered = Some(*from_addr);
                    }
                }
                ui.add_space(8.0);
            }

            if !from_entries.is_empty() {
                ui.label(
                    RichText::new(format!(
                        "References FROM this address ({})",
                        from_entries.len()
                    ))
                    .color(theme.xref_from_header),
                );
                for (to_addr, target, kind) in &from_entries {
                    let resp = ui
                        .horizontal(|ui| {
                            if ui
                                .link(
                                    RichText::new(format!("0x{to_addr:08x}"))
                                        .text_style(mono.clone())
                                        .color(theme.addr_normal),
                                )
                                .clicked()
                            {
                                navigate_to = Some(*to_addr);
                            }
                            let kind_str = format!("[{kind:?}]");
                            let kind_color = theme.xref_kind_color(*kind);
                            ui.label(
                                RichText::new(format!("  {kind_str:<20} {target}"))
                                    .text_style(mono.clone())
                                    .color(kind_color),
                            );
                        })
                        .response;
                    if resp.hovered() {
                        new_hovered = Some(*to_addr);
                    }
                }
            }
        });

    if new_hovered.is_some() {
        app.hovered_address = new_hovered;
    }

    if let Some(addr) = navigate_to {
        app.navigate_to(addr);
    }
}
