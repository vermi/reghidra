use crate::app::ReghidraApp;
use crate::context_menu::{
    address_context_menu, apply_context_action, ContextAction, ExtraContext, RenameKind,
};
use egui::{RichText, Ui};

/// Each item in the flat display list is exactly one row height.
enum DisplayLine {
    /// Spacer before a function header (if not the first).
    Spacer,
    /// Function header line.
    FuncHeader {
        address: u64,
        display_name: String,
        insn_count: usize,
        xref_count: usize,
        color: egui::Color32,
    },
    /// Xref count annotation for non-function-entry targets.
    XrefHint {
        count: usize,
    },
    /// Bookmark indicator line.
    Bookmark,
    /// An actual instruction row.
    Instruction {
        idx: usize,
    },
}

/// Tracks the last nav_generation each disasm pane has seen, keyed by ui Id.
/// Using a small fixed array avoids HashMap overhead for the typical 1-2 panes.
static DISASM_LAST_GEN: std::sync::Mutex<[(u64, u64); 2]> =
    std::sync::Mutex::new([(0, 0); 2]);

pub fn reset_scroll_gen() {
    *DISASM_LAST_GEN.lock().unwrap() = [(0, 0); 2];
}

pub fn render(app: &mut ReghidraApp, ui: &mut Ui) {
    let Some(ref project) = app.project else {
        return;
    };

    if project.instructions.is_empty() {
        ui.label("No instructions disassembled.");
        return;
    }

    let selected_addr = app.selected_address.unwrap_or(0);
    let hovered_addr = app.hovered_address;
    let show_bytes = app.show_bytes_in_disasm;
    let mono = egui::TextStyle::Monospace;
    let theme = app.theme.clone();
    let highlighted_mnemonic = app.highlighted_mnemonic.clone();

    // Per-pane scroll tracking: each pane (identified by ui id hash) stores
    // the last nav_generation it scrolled to.
    let pane_key = ui.id().value();
    let should_scroll = {
        let mut gens = DISASM_LAST_GEN.lock().unwrap();
        // Find existing slot or allocate an empty one
        let idx = gens.iter().position(|s| s.0 == pane_key)
            .or_else(|| gens.iter().position(|s| s.0 == 0));
        if let Some(idx) = idx {
            gens[idx].0 = pane_key;
            if gens[idx].1 != app.nav_generation {
                gens[idx].1 = app.nav_generation;
                true
            } else {
                false
            }
        } else {
            true
        }
    };

    // Build a flat display list where each item = one fixed-height row
    let mut display_lines: Vec<DisplayLine> = Vec::new();
    let mut scroll_to_display_row: Option<usize> = None;

    for (idx, insn) in project.instructions.iter().enumerate() {
        // Function header
        if let Some(func) = project.analysis.function_at(insn.address) {
            let is_user_renamed = project.renamed_functions.contains_key(&insn.address);
            let display_name = project
                .renamed_functions
                .get(&insn.address)
                .map(|s| s.as_str())
                .unwrap_or(&func.name)
                .to_string();

            let header_color = if is_user_renamed {
                theme.func_header
            } else if func.source == reghidra_core::FunctionSource::Signature {
                theme.func_header_sig
            } else if func.source == reghidra_core::FunctionSource::AutoNamed {
                theme.func_header_auto
            } else {
                theme.func_header
            };

            let xref_count = project.analysis.xrefs.ref_count_to(insn.address);

            if idx > 0 {
                display_lines.push(DisplayLine::Spacer);
            }
            display_lines.push(DisplayLine::FuncHeader {
                address: insn.address,
                display_name,
                insn_count: func.instruction_count,
                xref_count,
                color: header_color,
            });
        }

        // Xrefs TO this address (non-function-entry branch targets)
        let xrefs_to = project.analysis.xrefs.xrefs_to(insn.address);
        if !xrefs_to.is_empty() && project.analysis.function_at(insn.address).is_none() {
            display_lines.push(DisplayLine::XrefHint {
                count: xrefs_to.len(),
            });
        }

        // Bookmark indicator
        if project.bookmarks.contains(&insn.address) {
            display_lines.push(DisplayLine::Bookmark);
        }

        // Track which display row corresponds to the selected instruction
        if should_scroll && insn.address == selected_addr {
            scroll_to_display_row = Some(display_lines.len());
        }

        display_lines.push(DisplayLine::Instruction { idx });
    }

    let mut navigate_to = None;
    let mut clicked_mnemonic: Option<String> = None;
    let mut new_hovered: Option<u64> = None;
    let mut ctx_action: Option<ContextAction> = None;

    let total_rows = display_lines.len();
    let row_height = 18.0;

    let scroll_area = egui::ScrollArea::vertical()
        .id_salt("disasm_scroll")
        .auto_shrink([false, false])
        .scroll_bar_visibility(egui::scroll_area::ScrollBarVisibility::AlwaysVisible);

    let visible_height = ui.available_height();
    let spacing_y = ui.spacing().item_spacing.y;
    let scroll_area = if let Some(row_idx) = scroll_to_display_row {
        let target_offset =
            (row_idx as f32 * (row_height + spacing_y) - visible_height / 2.0).max(0.0);
        scroll_area.vertical_scroll_offset(target_offset)
    } else {
        scroll_area
    };

    scroll_area.show_rows(ui, row_height, total_rows, |ui, row_range| {
        for display_idx in row_range {
            match &display_lines[display_idx] {
                DisplayLine::Spacer => {
                    ui.add_space(row_height);
                }
                DisplayLine::FuncHeader {
                    address,
                    display_name,
                    insn_count,
                    xref_count,
                    color,
                    ..
                } => {
                    let resp = ui.add(
                        egui::Label::new(
                            RichText::new(format!(
                                "; ======= {} ({} insns, {} xrefs) =======",
                                display_name, insn_count, xref_count
                            ))
                            .text_style(mono.clone())
                            .color(*color)
                            .strong(),
                        )
                        .sense(egui::Sense::click()),
                    );
                    let is_bookmarked = project.bookmarks.contains(address);
                    let has_comment = project.comments.contains_key(address);
                    address_context_menu(
                        &resp,
                        *address,
                        RenameKind::Function,
                        is_bookmarked,
                        has_comment,
                        ExtraContext::default(),
                        &mut ctx_action,
                    );
                }
                DisplayLine::XrefHint { count } => {
                    ui.label(
                        RichText::new(format!("; {count} xref(s) here"))
                            .text_style(mono.clone())
                            .color(theme.xref_hint),
                    );
                }
                DisplayLine::Bookmark => {
                    ui.label(
                        RichText::new("; [BOOKMARK]")
                            .text_style(mono.clone())
                            .color(theme.bookmark),
                    );
                }
                DisplayLine::Instruction { idx } => {
                    let insn = &project.instructions[*idx];
                    let is_selected = insn.address == selected_addr;
                    let is_hovered_cross = hovered_addr == Some(insn.address) && !is_selected;
                    let mnemonic_lower = insn.mnemonic.to_lowercase();
                    let is_mnemonic_highlighted = highlighted_mnemonic
                        .as_ref()
                        .is_some_and(|m| m == &mnemonic_lower);

                    let frame = if is_selected {
                        egui::Frame::new().fill(theme.bg_selected)
                    } else if is_hovered_cross {
                        egui::Frame::new().fill(theme.bg_hover)
                    } else if is_mnemonic_highlighted {
                        egui::Frame::new().fill(theme.bg_mnemonic_highlight)
                    } else {
                        egui::Frame::NONE
                    };

                    let resp = frame
                        .show(ui, |ui| {
                            ui.horizontal(|ui| {
                                // Address
                                let addr_color = if is_selected {
                                    theme.addr_selected
                                } else {
                                    theme.addr_normal
                                };
                                let addr_text =
                                    RichText::new(format!("0x{:08x}", insn.address))
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
                                let mnemonic_text =
                                    RichText::new(format!("{:<8}", insn.mnemonic))
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

                                // Xref annotations
                                let xrefs_from =
                                    project.analysis.xrefs.xrefs_from(insn.address);
                                for xref in xrefs_from {
                                    if let Some(target_name) =
                                        project.function_name(xref.to)
                                    {
                                        if ui
                                            .link(
                                                RichText::new(format!(
                                                    "  ; -> {target_name}"
                                                ))
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
                                        let preview: String =
                                            s.value.chars().take(40).collect();
                                        if ui
                                            .link(
                                                RichText::new(format!(
                                                    "  ; \"{preview}\""
                                                ))
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
                                if let Some(comment) =
                                    project.comments.get(&insn.address)
                                {
                                    ui.label(
                                        RichText::new(format!("  ; {comment}"))
                                            .text_style(mono.clone())
                                            .color(theme.comment),
                                    );
                                }
                            });
                        })
                        .response;

                    // Track hover for cross-view highlighting
                    if resp.hovered() {
                        new_hovered = Some(insn.address);
                    }

                    // Right-click context menu — make the row sense clicks so
                    // the menu can attach to it.
                    let resp = resp.interact(egui::Sense::click());
                    let is_func_entry =
                        project.analysis.function_at(insn.address).is_some();
                    let rename_kind = if is_func_entry {
                        RenameKind::Function
                    } else {
                        RenameKind::None
                    };
                    let is_bookmarked = project.bookmarks.contains(&insn.address);
                    let has_comment = project.comments.contains_key(&insn.address);
                    // If any of the instruction's xref'd targets is a string,
                    // expose Copy String for the first such string.
                    let string_value = project
                        .analysis
                        .xrefs
                        .xrefs_from(insn.address)
                        .iter()
                        .find_map(|x| {
                            project
                                .binary
                                .strings
                                .iter()
                                .find(|s| s.address == x.to)
                                .map(|s| s.value.as_str())
                        });
                    address_context_menu(
                        &resp,
                        insn.address,
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
        }
    });

    // Update hover state (only if mouse is over an instruction in this view)
    if new_hovered.is_some() {
        app.hovered_address_next = new_hovered;
    }

    // Handle mnemonic click
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

    if let Some(action) = ctx_action {
        apply_context_action(app, action);
    }
}
