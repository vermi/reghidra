use crate::app::ReghidraApp;
use egui::{RichText, Ui};

pub fn render(app: &mut ReghidraApp, ui: &mut Ui) {
    let Some(ref project) = app.project else {
        return;
    };

    if project.instructions.is_empty() {
        ui.label("No instructions disassembled.");
        return;
    }

    let selected_addr = app.selected_address.unwrap_or(0);
    let show_bytes = app.show_bytes_in_disasm;
    let mono = egui::TextStyle::Monospace;
    let theme = app.theme.clone();
    let highlighted_mnemonic = app.highlighted_mnemonic.clone();

    // Detect if the selected address changed (e.g. sidebar click, vim nav)
    let should_scroll = app.prev_selected_address != app.selected_address;
    app.prev_selected_address = app.selected_address;

    let mut navigate_to = None;
    let mut clicked_mnemonic: Option<String> = None;

    egui::ScrollArea::vertical()
        .auto_shrink([false, false])
        .scroll_bar_visibility(egui::scroll_area::ScrollBarVisibility::AlwaysVisible)
        .show(ui, |ui| {
            for idx in 0..project.instructions.len() {
                let insn = &project.instructions[idx];
                let is_selected = insn.address == selected_addr;
                let mnemonic_lower = insn.mnemonic.to_lowercase();
                let is_mnemonic_highlighted = highlighted_mnemonic
                    .as_ref()
                    .is_some_and(|m| m == &mnemonic_lower);

                // Function header
                if let Some(func) = project.analysis.function_at(insn.address) {
                    let xref_count = project.analysis.xrefs.ref_count_to(insn.address);
                    let is_user_renamed = project.renamed_functions.contains_key(&insn.address);
                    let display_name = project
                        .renamed_functions
                        .get(&insn.address)
                        .map(|s| s.as_str())
                        .unwrap_or(&func.name);

                    // Use distinct colors for different function sources (unless user-renamed)
                    let header_color = if is_user_renamed {
                        theme.func_header
                    } else if func.source == reghidra_core::FunctionSource::Signature {
                        theme.func_header_sig
                    } else if func.source == reghidra_core::FunctionSource::AutoNamed {
                        theme.func_header_auto
                    } else {
                        theme.func_header
                    };

                    if idx > 0 {
                        ui.add_space(4.0);
                    }
                    ui.horizontal(|ui| {
                        ui.label(
                            RichText::new(format!(
                                "; ======= {} ({} insns, {} xrefs) =======",
                                display_name, func.instruction_count, xref_count
                            ))
                            .text_style(mono.clone())
                            .color(header_color)
                            .strong(),
                        );
                    });
                }

                // Xrefs TO this address (non-function-entry branch targets)
                let xrefs_to = project.analysis.xrefs.xrefs_to(insn.address);
                if !xrefs_to.is_empty() && project.analysis.function_at(insn.address).is_none() {
                    let count = xrefs_to.len();
                    ui.label(
                        RichText::new(format!("; {count} xref(s) here"))
                            .text_style(mono.clone())
                            .color(theme.xref_hint),
                    );
                }

                // Bookmark indicator
                if project.bookmarks.contains(&insn.address) {
                    ui.label(
                        RichText::new("; [BOOKMARK]")
                            .text_style(mono.clone())
                            .color(theme.bookmark),
                    );
                }

                // Pick background: selected row > mnemonic highlight > none
                let frame = if is_selected {
                    egui::Frame::new().fill(theme.bg_selected)
                } else if is_mnemonic_highlighted {
                    egui::Frame::new().fill(theme.bg_mnemonic_highlight)
                } else {
                    egui::Frame::NONE
                };

                let row_response = frame
                    .show(ui, |ui| {
                        ui.horizontal(|ui| {
                            // Address
                            let addr_color = if is_selected {
                                theme.addr_selected
                            } else {
                                theme.addr_normal
                            };
                            let addr_text = RichText::new(format!("0x{:08x}", insn.address))
                                .text_style(mono.clone())
                                .color(addr_color);

                            if ui.link(addr_text).clicked() {
                                navigate_to = Some(insn.address);
                            }

                            // Bytes
                            if show_bytes {
                                let hex: String = insn
                                    .bytes
                                    .iter()
                                    .map(|b| format!("{b:02x}"))
                                    .collect::<Vec<_>>()
                                    .join(" ");
                                ui.label(
                                    RichText::new(format!("{hex:<24}"))
                                        .text_style(mono.clone())
                                        .color(theme.text_dim),
                                );
                            }

                            // Mnemonic (clickable for highlighting)
                            let mc = theme.mnemonic_color(&insn.mnemonic);
                            let mnemonic_text = RichText::new(format!("{:<8}", insn.mnemonic))
                                .text_style(mono.clone())
                                .color(mc);

                            if ui.link(mnemonic_text).clicked() {
                                clicked_mnemonic = Some(mnemonic_lower.clone());
                            }

                            // Operands
                            ui.label(
                                RichText::new(&insn.operands)
                                    .text_style(mono.clone())
                                    .color(theme.text_primary),
                            );

                            // Xref annotations: show call/jump target name (clickable)
                            let xrefs_from = project.analysis.xrefs.xrefs_from(insn.address);
                            for xref in xrefs_from {
                                if let Some(target_name) = project.function_name(xref.to) {
                                    if ui
                                        .link(
                                            RichText::new(format!("  ; -> {target_name}"))
                                                .text_style(mono.clone())
                                                .color(theme.xref_func),
                                        )
                                        .clicked()
                                    {
                                        navigate_to = Some(xref.to);
                                    }
                                } else if let Some(s) = project
                                    .binary
                                    .strings
                                    .iter()
                                    .find(|s| s.address == xref.to)
                                {
                                    let preview: String = s.value.chars().take(40).collect();
                                    if ui
                                        .link(
                                            RichText::new(format!("  ; \"{preview}\""))
                                                .text_style(mono.clone())
                                                .color(theme.xref_string),
                                        )
                                        .clicked()
                                    {
                                        navigate_to = Some(xref.to);
                                    }
                                }
                            }

                            // User comment
                            if let Some(comment) = project.comments.get(&insn.address) {
                                ui.label(
                                    RichText::new(format!("  ; {comment}"))
                                        .text_style(mono.clone())
                                        .color(theme.comment),
                                );
                            }
                        });
                    })
                    .response;

                // Scroll to the selected row when the selection changes
                if is_selected && should_scroll {
                    row_response.scroll_to_me(Some(egui::Align::Center));
                }
            }
        });

    // Handle mnemonic click: toggle highlight (click same mnemonic again to clear)
    if let Some(mnemonic) = clicked_mnemonic {
        if app.highlighted_mnemonic.as_ref() == Some(&mnemonic) {
            app.highlighted_mnemonic = None;
        } else {
            app.highlighted_mnemonic = Some(mnemonic);
        }
    }

    if let Some(addr) = navigate_to {
        app.navigate_to(addr);
    }
}
