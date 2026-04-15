use crate::app::{ReghidraApp, SidePanel};
use crate::context_menu::{
    address_context_menu, apply_context_action, ContextAction, ExtraContext, RenameKind,
};
use egui::Ui;

/// Standard row height for the side panel's selectable-label lists.
/// Used by `ScrollArea::show_rows` to virtualize the panel — without
/// virtualization, panels with thousands of entries (the canonical
/// "open a real PE binary" case) re-lay-out every row every frame
/// and trip the GUI into 80% CPU and multi-GB memory growth as egui
/// caches per-widget state for thousands of off-screen rows.
const SIDE_PANEL_ROW_HEIGHT: f32 = 18.0;

pub fn render(app: &mut ReghidraApp, ui: &mut Ui) {
    // The Detections tab manages its own borrows internally.
    if app.side_panel == SidePanel::Detections {
        crate::views::detections::render(app, ui);
        return;
    }

    let Some(ref project) = app.project else {
        return;
    };

    let query = app.search_query.to_lowercase();
    let selected_addr = app.selected_address;

    // Pre-collect data we need to avoid borrow conflicts
    let mut navigate_to: Option<u64> = None;
    let mut ctx_action: Option<ContextAction> = None;

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

            let theme = app.theme.clone();
            egui::ScrollArea::vertical().auto_shrink([false, false]).show_rows(
                ui,
                SIDE_PANEL_ROW_HEIGHT,
                filtered.len(),
                |ui, row_range| {
                    for idx in row_range {
                        let (addr, name) = filtered[idx];
                        let label = format!("0x{addr:08x}  {name}");
                        let selected = selected_addr == Some(*addr);

                        // Check for detection hits on this function.
                        let det_hits = project.detection_results.function_hits.get(addr);
                        let badge_color = det_hits.and_then(|hits| {
                            let has_malicious = hits.iter().any(|h| {
                                matches!(h.severity, reghidra_core::DetectionSeverity::Malicious)
                            });
                            let has_suspicious = hits.iter().any(|h| {
                                matches!(h.severity, reghidra_core::DetectionSeverity::Suspicious)
                            });
                            if has_malicious {
                                Some(theme.detection_malicious)
                            } else if has_suspicious {
                                Some(theme.detection_suspicious)
                            } else if !hits.is_empty() {
                                Some(theme.detection_info)
                            } else {
                                None
                            }
                        });
                        let badge_tooltip = det_hits.map(|hits| {
                            hits.iter()
                                .map(|h| h.rule_name.as_str())
                                .collect::<Vec<_>>()
                                .join(", ")
                        });

                        let resp = if badge_color.is_some() {
                            // Render label + badge circle in a horizontal row.
                            let row_resp = ui.horizontal(|ui| {
                                let r = ui.selectable_label(selected, &label);
                                // Right-align badge.
                                ui.with_layout(
                                    egui::Layout::right_to_left(egui::Align::Center),
                                    |ui| {
                                        let (rect, _) = ui.allocate_exact_size(
                                            egui::vec2(8.0, 8.0),
                                            egui::Sense::hover(),
                                        );
                                        ui.painter().circle_filled(
                                            rect.center(),
                                            4.0,
                                            badge_color.unwrap(),
                                        );
                                    },
                                );
                                r
                            });
                            row_resp.inner
                        } else {
                            ui.selectable_label(selected, &label)
                        };

                        if let Some(tooltip) = badge_tooltip {
                            resp.clone().on_hover_text(tooltip);
                        }
                        if resp.clicked() {
                            navigate_to = Some(*addr);
                        }
                        let is_bookmarked = project.bookmarks.contains(addr);
                        let has_comment = project.comments.contains_key(addr);
                        address_context_menu(
                            &resp,
                            *addr,
                            RenameKind::Function,
                            is_bookmarked,
                            has_comment,
                            ExtraContext::default(),
                            &mut ctx_action,
                        );
                    }
                },
            );
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

            egui::ScrollArea::vertical().auto_shrink([false, false]).show_rows(
                ui,
                SIDE_PANEL_ROW_HEIGHT,
                filtered.len(),
                |ui, row_range| {
                    for idx in row_range {
                        let sym = filtered[idx];
                        let kind = match sym.kind {
                            reghidra_core::SymbolKind::Function => "fn",
                            reghidra_core::SymbolKind::Object => "obj",
                            reghidra_core::SymbolKind::Section => "sec",
                            reghidra_core::SymbolKind::File => "file",
                            reghidra_core::SymbolKind::Unknown => "?",
                        };
                        let label = format!("[{kind}] 0x{:08x}  {}", sym.address, sym.name);
                        let selected = selected_addr == Some(sym.address);
                        let resp = ui.selectable_label(selected, &label);
                        if resp.clicked() {
                            navigate_to = Some(sym.address);
                        }
                        let is_func = matches!(sym.kind, reghidra_core::SymbolKind::Function)
                            || project.analysis.function_at(sym.address).is_some();
                        let rename_kind = if is_func {
                            RenameKind::Function
                        } else {
                            RenameKind::None
                        };
                        let is_bookmarked = project.bookmarks.contains(&sym.address);
                        let has_comment = project.comments.contains_key(&sym.address);
                        let string_value = project
                            .binary
                            .strings
                            .iter()
                            .find(|s| s.address == sym.address)
                            .map(|s| s.value.as_str());
                        address_context_menu(
                            &resp,
                            sym.address,
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
                },
            );
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

            egui::ScrollArea::vertical().auto_shrink([false, false]).show_rows(
                ui,
                SIDE_PANEL_ROW_HEIGHT,
                filtered.len(),
                |ui, row_range| {
                    for idx in row_range {
                        let imp = filtered[idx];
                        let label = format!("0x{:08x}  {}", imp.address, imp.name);
                        let selected = selected_addr == Some(imp.address);
                        let resp = ui.selectable_label(selected, &label);
                        if resp.clicked() {
                            navigate_to = Some(imp.address);
                        }
                        let is_func = project.analysis.function_at(imp.address).is_some();
                        let rename_kind = if is_func {
                            RenameKind::Function
                        } else {
                            RenameKind::None
                        };
                        let is_bookmarked = project.bookmarks.contains(&imp.address);
                        let has_comment = project.comments.contains_key(&imp.address);
                        address_context_menu(
                            &resp,
                            imp.address,
                            rename_kind,
                            is_bookmarked,
                            has_comment,
                            ExtraContext::default(),
                            &mut ctx_action,
                        );
                    }
                },
            );
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

            egui::ScrollArea::vertical().auto_shrink([false, false]).show_rows(
                ui,
                SIDE_PANEL_ROW_HEIGHT,
                filtered.len(),
                |ui, row_range| {
                    for idx in row_range {
                        let exp = filtered[idx];
                        let label = format!("0x{:08x}  {}", exp.address, exp.name);
                        let selected = selected_addr == Some(exp.address);
                        let resp = ui.selectable_label(selected, &label);
                        if resp.clicked() {
                            navigate_to = Some(exp.address);
                        }
                        let is_func = project.analysis.function_at(exp.address).is_some();
                        let rename_kind = if is_func {
                            RenameKind::Function
                        } else {
                            RenameKind::None
                        };
                        let is_bookmarked = project.bookmarks.contains(&exp.address);
                        let has_comment = project.comments.contains_key(&exp.address);
                        address_context_menu(
                            &resp,
                            exp.address,
                            rename_kind,
                            is_bookmarked,
                            has_comment,
                            ExtraContext::default(),
                            &mut ctx_action,
                        );
                    }
                },
            );
        }

        SidePanel::Sections => {
            let filtered: Vec<_> = project
                .binary
                .sections
                .iter()
                .filter(|sec| query.is_empty() || sec.name.to_lowercase().contains(&query))
                .collect();

            ui.label(format!("{} sections", filtered.len()));
            ui.separator();

            egui::ScrollArea::vertical().auto_shrink([false, false]).show_rows(
                ui,
                SIDE_PANEL_ROW_HEIGHT,
                filtered.len(),
                |ui, row_range| {
                    for idx in row_range {
                        let sec = filtered[idx];
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
                        let resp = ui.selectable_label(selected, &label);
                        if resp.clicked() {
                            navigate_to = Some(sec.virtual_address);
                        }
                        let addr = sec.virtual_address;
                        let is_bookmarked = project.bookmarks.contains(&addr);
                        let has_comment = project.comments.contains_key(&addr);
                        address_context_menu(
                            &resp,
                            addr,
                            RenameKind::None,
                            is_bookmarked,
                            has_comment,
                            ExtraContext::default(),
                            &mut ctx_action,
                        );
                    }
                },
            );
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

            egui::ScrollArea::vertical().auto_shrink([false, false]).show_rows(
                ui,
                SIDE_PANEL_ROW_HEIGHT,
                filtered.len(),
                |ui, row_range| {
                    for idx in row_range {
                        let s = filtered[idx];
                        let display_val: String = s.value.chars().take(50).collect();
                        let label = format!(
                            "0x{:08x}  {}  \"{}\"",
                            s.address, s.auto_name, display_val
                        );
                        let selected = selected_addr == Some(s.address);
                        let resp = ui.selectable_label(selected, &label);
                        if resp.clicked() {
                            navigate_to = Some(s.address);
                        }
                        let is_bookmarked = project.bookmarks.contains(&s.address);
                        let has_comment = project.comments.contains_key(&s.address);
                        address_context_menu(
                            &resp,
                            s.address,
                            RenameKind::None,
                            is_bookmarked,
                            has_comment,
                            ExtraContext {
                                string_value: Some(s.value.as_str()),
                                variable: None,
                            },
                            &mut ctx_action,
                        );
                    }
                },
            );
        }

        // Handled by early-return at the top of this function.
        SidePanel::Detections => {}
    }

    if let Some(addr) = navigate_to {
        app.navigate_to(addr);
    }
    if let Some(action) = ctx_action {
        apply_context_action(app, action);
    }
}
