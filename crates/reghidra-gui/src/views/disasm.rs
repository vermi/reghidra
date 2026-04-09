use crate::app::ReghidraApp;
use crate::context_menu::{
    address_context_menu, apply_context_action, ContextAction, ExtraContext, RenameKind,
};
use egui::{RichText, Ui};

/// Each item in the flat display list is exactly one row height.
#[derive(Clone)]
enum DisplayLine {
    /// Spacer before a function header (if not the first).
    Spacer,
    /// Top/bottom rule line of a function header block.
    FuncHeaderRule {
        color: egui::Color32,
    },
    /// Name line of a function header block. Carries the click/context
    /// target so right-click actions (rename, comment, bookmark, etc.)
    /// hit the function entry.
    FuncHeaderName {
        address: u64,
        display_name: String,
        color: egui::Color32,
    },
    /// Stats line of a function header block (insn count + xref count +
    /// entry address). Not interactive.
    FuncHeaderStats {
        address: u64,
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

/// Build the flat per-row display list for the disassembly view from
/// the project state. This is the O(N_instructions) walk that the
/// disasm view used to perform every frame; the call site now caches
/// the result and only re-runs it when one of its inputs (function
/// renames, bookmark add/remove) has actually changed, gated by
/// `app.disasm_display_generation`.
///
/// Inputs that affect the result:
///
/// - `project.instructions` (only changes on file open / re-analysis)
/// - `project.analysis.functions` and their source classifications
///   (only changes on re-analysis)
/// - `project.analysis.xrefs` ref counts (only changes on re-analysis)
/// - `project.renamed_functions` for `FuncHeaderName.display_name`
/// - `project.bookmarks` for the `Bookmark` rows
///
/// Theme colors are baked in at build time. Switching the theme
/// invalidates the cache via `disasm_display_generation` (see the
/// theme toggle path).
fn build_display_lines(
    project: &reghidra_core::Project,
    theme: &crate::theme::Theme,
) -> Vec<DisplayLine> {
    let mut display_lines: Vec<DisplayLine> = Vec::with_capacity(project.instructions.len() + 64);
    for (idx, insn) in project.instructions.iter().enumerate() {
        if let Some(func) = project.analysis.function_at(insn.address) {
            let is_user_renamed = project.renamed_functions.contains_key(&insn.address);
            let display_name = project
                .renamed_functions
                .get(&insn.address)
                .cloned()
                .unwrap_or_else(|| reghidra_core::demangle::display_name_short(&func.name).into_owned());
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
            display_lines.push(DisplayLine::FuncHeaderRule { color: header_color });
            display_lines.push(DisplayLine::FuncHeaderName {
                address: insn.address,
                display_name,
                color: header_color,
            });
            display_lines.push(DisplayLine::FuncHeaderStats {
                address: insn.address,
                insn_count: func.instruction_count,
                xref_count,
                color: header_color,
            });
            display_lines.push(DisplayLine::FuncHeaderRule { color: header_color });
        }
        let xrefs_to = project.analysis.xrefs.xrefs_to(insn.address);
        if !xrefs_to.is_empty() && project.analysis.function_at(insn.address).is_none() {
            display_lines.push(DisplayLine::XrefHint {
                count: xrefs_to.len(),
            });
        }
        if project.bookmarks.contains(&insn.address) {
            display_lines.push(DisplayLine::Bookmark);
        }
        display_lines.push(DisplayLine::Instruction { idx });
    }
    display_lines
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

    // Cached display list. Pre-PR: rebuilt every frame, walking all
    // ~226k instructions on a real PE binary and burning 80% CPU on
    // a 1393-function fixture. Now: rebuild only when
    // `disasm_display_generation` changes (function rename, bookmark
    // toggle, file open). The cache is stored as `Box<dyn Any>` on
    // the App so app.rs doesn't need to know `DisplayLine`'s shape.
    let cache_gen = app.disasm_display_generation;
    let cache_hit = match &app.disasm_lines_cache {
        Some((cached_gen, any)) => {
            *cached_gen == cache_gen && any.downcast_ref::<Vec<DisplayLine>>().is_some()
        }
        None => false,
    };
    if !cache_hit {
        let lines = build_display_lines(project, &theme);
        app.disasm_lines_cache = Some((cache_gen, Box::new(lines)));
    }
    // Re-borrow `project` after the &mut app borrow above ended.
    let Some(ref project) = app.project else {
        return;
    };
    let display_lines: &Vec<DisplayLine> = app
        .disasm_lines_cache
        .as_ref()
        .and_then(|(_, any)| any.downcast_ref::<Vec<DisplayLine>>())
        .expect("disasm cache populated above");

    // Locate the row to scroll to (if any) by walking the cached
    // display list. Cheap compared to rebuilding it.
    let scroll_to_display_row: Option<usize> = if should_scroll {
        display_lines.iter().position(|line| match line {
            DisplayLine::Instruction { idx } => {
                project
                    .instructions
                    .get(*idx)
                    .is_some_and(|insn| insn.address == selected_addr)
            }
            _ => false,
        })
    } else {
        None
    };

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
                DisplayLine::FuncHeaderRule { color } => {
                    ui.label(
                        RichText::new("; ──────────────────────────────────────────────────────")
                            .text_style(mono.clone())
                            .color(*color),
                    );
                }
                DisplayLine::FuncHeaderName {
                    address,
                    display_name,
                    color,
                } => {
                    let resp = ui.add(
                        egui::Label::new(
                            RichText::new(format!("; FUNCTION  {}", display_name))
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
                DisplayLine::FuncHeaderStats {
                    address,
                    insn_count,
                    xref_count,
                    color,
                } => {
                    ui.label(
                        RichText::new(format!(
                            ";   0x{:x} · {} insns · {} xrefs",
                            address, insn_count, xref_count
                        ))
                        .text_style(mono.clone())
                        .color(*color),
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

                    // Make the whole row sense clicks. This serves two
                    // purposes:
                    //   1. Attaches the right-click context menu to the row.
                    //   2. Catches left-clicks anywhere on the row (address,
                    //      bytes, operands, whitespace) and navigates to the
                    //      instruction. Without this, only the narrow address
                    //      link was navigable — and in practice the outer
                    //      `.interact(Sense::click())` swallowed the click
                    //      before the inner link saw it, so clicking the
                    //      disasm row appeared to do nothing.
                    let resp = resp.interact(egui::Sense::click());
                    if resp.clicked() {
                        navigate_to = Some(insn.address);
                    }
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
