use crate::app::ReghidraApp;
use crate::context_menu::{
    address_context_menu, apply_context_action, ContextAction, ExtraContext, RenameKind,
};
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
                .map(|f| {
                    project
                        .renamed_functions
                        .get(&f.entry_address)
                        .cloned()
                        .unwrap_or_else(|| {
                            reghidra_core::demangle::display_name_short(&f.name).into_owned()
                        })
                })
                .unwrap_or_else(|| format!("0x{:x}", x.from));
            (x.from, caller, x.kind)
        })
        .collect();

    let from_entries: Vec<_> = xrefs_from
        .iter()
        .map(|x| {
            let target_name = project
                .display_function_name(x.to)
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
    let mut ctx_action: Option<ContextAction> = None;

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
                        .response
                        .interact(egui::Sense::click());
                    if resp.hovered() {
                        new_hovered = Some(*from_addr);
                    }
                    let is_func = project.analysis.function_at(*from_addr).is_some();
                    let rename_kind = if is_func {
                        RenameKind::Function
                    } else {
                        RenameKind::None
                    };
                    let is_bookmarked = project.bookmarks.contains(from_addr);
                    let has_comment = project.comments.contains_key(from_addr);
                    address_context_menu(
                        &resp,
                        *from_addr,
                        rename_kind,
                        is_bookmarked,
                        has_comment,
                        ExtraContext::default(),
                        &mut ctx_action,
                    );
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
                        .response
                        .interact(egui::Sense::click());
                    if resp.hovered() {
                        new_hovered = Some(*to_addr);
                    }
                    let is_func = project.analysis.function_at(*to_addr).is_some();
                    let rename_kind = if is_func {
                        RenameKind::Function
                    } else {
                        RenameKind::None
                    };
                    let is_bookmarked = project.bookmarks.contains(to_addr);
                    let has_comment = project.comments.contains_key(to_addr);
                    let string_value = project
                        .binary
                        .strings
                        .iter()
                        .find(|s| s.address == *to_addr)
                        .map(|s| s.value.as_str());
                    address_context_menu(
                        &resp,
                        *to_addr,
                        rename_kind,
                        is_bookmarked,
                        has_comment,
                        ExtraContext {
                            string_value,
                            variable: None,
                        },
                        &mut ctx_action,
                    );
                }
            }
        });

    if new_hovered.is_some() {
        app.hovered_address_next = new_hovered;
    }

    if let Some(addr) = navigate_to {
        app.navigate_to(addr);
    }

    if let Some(action) = ctx_action {
        apply_context_action(app, action);
    }
}
