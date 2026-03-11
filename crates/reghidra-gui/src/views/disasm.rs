use crate::app::ReghidraApp;
use egui::{RichText, Ui};

/// Each item in the flat display list is exactly one row height.
enum DisplayLine {
    /// Spacer before a function header (if not the first).
    Spacer,
    /// Function header line.
    FuncHeader {
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

/// Per-instance scroll tracking so split view panes don't stomp each other.
static DISASM_NAV_GEN_PRIMARY: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(0);
static DISASM_NAV_GEN_SECONDARY: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(0);

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

    // Use per-pane generation tracker so split view panes scroll independently
    let is_primary = ui.id().with("split_left") != ui.id();
    let gen_tracker = if is_primary {
        &DISASM_NAV_GEN_PRIMARY
    } else {
        &DISASM_NAV_GEN_SECONDARY
    };
    let last_gen = gen_tracker.load(std::sync::atomic::Ordering::Relaxed);
    let should_scroll = app.nav_generation != last_gen;
    if should_scroll {
        gen_tracker.store(app.nav_generation, std::sync::atomic::Ordering::Relaxed);
    }

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

    let total_rows = display_lines.len();
    let row_height = 18.0;

    let scroll_area = egui::ScrollArea::vertical()
        .id_salt("disasm_scroll")
        .auto_shrink([false, false])
        .scroll_bar_visibility(egui::scroll_area::ScrollBarVisibility::AlwaysVisible);

    let scroll_area = if let Some(row_idx) = scroll_to_display_row {
        let target_offset = (row_idx as f32 * row_height - 200.0).max(0.0);
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
                    display_name,
                    insn_count,
                    xref_count,
                    color,
                    ..
                } => {
                    ui.label(
                        RichText::new(format!(
                            "; ======= {} ({} insns, {} xrefs) =======",
                            display_name, insn_count, xref_count
                        ))
                        .text_style(mono.clone())
                        .color(*color)
                        .strong(),
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
                }
            }
        }
    });

    // Update hover state (only if mouse is over an instruction in this view)
    if new_hovered.is_some() {
        app.hovered_address = new_hovered;
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
}
