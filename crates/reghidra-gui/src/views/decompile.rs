use crate::app::ReghidraApp;
use crate::context_menu::{address_context_menu, apply_context_action, ContextAction};
use egui::{RichText, Ui};
use reghidra_core::AnnotatedLine;

static DECOMP_LAST_GEN: std::sync::Mutex<[(u64, u64); 2]> =
    std::sync::Mutex::new([(0, 0); 2]);

pub fn reset_scroll_gen() {
    *DECOMP_LAST_GEN.lock().unwrap() = [(0, 0); 2];
}

pub fn render(app: &mut ReghidraApp, ui: &mut Ui) {
    let Some(ref project) = app.project else {
        return;
    };

    // Use code_address for function lookup so the view persists when
    // the user navigates to a data address in another pane.
    // Falls back to the decompile cache entry if function_containing fails
    // (e.g. goto label past the first ret in a multi-return function).
    let code_addr = app.code_address.unwrap_or(0);
    let selected_addr = app.selected_address.unwrap_or(0);
    let hovered_addr = app.hovered_address;
    let mono = egui::TextStyle::Monospace;

    let func = project
        .analysis
        .function_containing(code_addr)
        .or_else(|| project.analysis.function_at(code_addr))
        .or_else(|| {
            app.decompile_cache
                .as_ref()
                .and_then(|(entry, _, _, _)| project.analysis.function_at(*entry))
        });

    let Some(func) = func else {
        ui.label("Select a function to view decompiled output.");
        return;
    };

    let func_entry = func.entry_address;
    // Header display uses the demangled form (and user rename if present);
    // the raw mangled name stays canonical in storage.
    let func_name = project
        .renamed_functions
        .get(&func_entry)
        .cloned()
        .unwrap_or_else(|| reghidra_core::demangle::display_name(&func.name).into_owned());

    // Use cached decompile output if the function and rename generation haven't changed
    let needs_decompile = match &app.decompile_cache {
        Some((cached_entry, cached_rename_gen, _, _)) => {
            *cached_entry != func_entry || *cached_rename_gen != app.rename_generation
        }
        None => true,
    };
    if needs_decompile {
        if let Some((lines, var_names)) = project.decompile_annotated(func_entry) {
            app.decompile_cache =
                Some((func_entry, app.rename_generation, lines, var_names));
        } else {
            app.decompile_cache = None;
        }
    }

    let Some((_, _, ref annotated_lines, ref var_names)) = app.decompile_cache else {
        ui.label("Could not decompile this function.");
        return;
    };

    ui.label(RichText::new(format!("Decompiled: {func_name}")).strong());
    ui.separator();

    let theme = app.theme.clone();
    let annotated_lines = annotated_lines.clone();
    let var_names = var_names.clone();

    // Build a reverse map: function name -> address
    let func_name_to_addr: std::collections::HashMap<String, u64> = project
        .analysis
        .functions
        .iter()
        .map(|f| {
            // Must match what the decompiler prints so click-to-navigate works
            // after the demangling pass.
            let name = project
                .renamed_functions
                .get(&f.entry_address)
                .cloned()
                .unwrap_or_else(|| reghidra_core::demangle::display_name(&f.name).into_owned());
            (name, f.entry_address)
        })
        .collect();

    // Build address-to-block mapping for the current function's IR
    let addr_to_block: std::collections::HashMap<u64, u64> =
        if let Some(ir) = project.analysis.ir_for(func_entry) {
            let mut map = std::collections::HashMap::new();
            for block in &ir.blocks {
                for insn in &block.instructions {
                    map.insert(insn.address, block.address);
                }
            }
            map
        } else {
            std::collections::HashMap::new()
        };

    // The block address that contains the selected instruction
    let selected_block = addr_to_block.get(&selected_addr).copied();
    // The block address that contains the hovered instruction (from another view)
    let hovered_block = hovered_addr.and_then(|a| addr_to_block.get(&a).copied());

    // Per-pane scroll tracking
    let pane_key = ui.id().value();
    let should_scroll = {
        let mut gens = DECOMP_LAST_GEN.lock().unwrap();
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

    // Find the line index to scroll to
    let scroll_to_line = if should_scroll {
        selected_block.and_then(|sb| {
            annotated_lines
                .iter()
                .position(|line| line.addr == Some(sb))
        })
    } else {
        None
    };

    let mut navigate_to = None;
    let mut new_hovered: Option<u64> = None;
    let mut ctx_action: Option<ContextAction> = None;

    // Pre-compute bookmark/comment sets used by the context menu — done once
    // here so the per-token render closure doesn't need to re-borrow project.
    let bookmarks: std::collections::HashSet<u64> =
        project.bookmarks.iter().copied().collect();
    let comments: std::collections::HashSet<u64> =
        project.comments.keys().copied().collect();
    let function_addrs: std::collections::HashSet<u64> = project
        .analysis
        .functions
        .iter()
        .map(|f| f.entry_address)
        .collect();
    // Reverse map of user-renamed labels: name → address
    let label_name_to_addr: std::collections::HashMap<String, u64> = project
        .label_names
        .iter()
        .map(|(addr, name)| (name.clone(), *addr))
        .collect();

    let row_height = 18.0;
    let total_lines = annotated_lines.len();

    let scroll_area = egui::ScrollArea::vertical()
        .id_salt("decompile_scroll")
        .auto_shrink([false, false]);

    let visible_height = ui.available_height();
    let spacing_y = ui.spacing().item_spacing.y;
    let scroll_area = if let Some(line_idx) = scroll_to_line {
        let target_offset =
            (line_idx as f32 * (row_height + spacing_y) - visible_height / 2.0).max(0.0);
        scroll_area.vertical_scroll_offset(target_offset)
    } else {
        scroll_area
    };

    scroll_area.show_rows(ui, row_height, total_lines, |ui, row_range| {
        for idx in row_range {
            let line = &annotated_lines[idx];
            let line_block = line.addr;
            // Only highlight if we actually have a matching block (not None == None)
            let is_selected_block = selected_block.is_some()
                && line_block.is_some()
                && line_block == selected_block;
            let is_hovered_block = hovered_block.is_some()
                && line_block.is_some()
                && line_block == hovered_block
                && !is_selected_block;

            let frame = if is_selected_block {
                egui::Frame::new().fill(theme.bg_selected)
            } else if is_hovered_block {
                egui::Frame::new().fill(theme.bg_hover)
            } else {
                egui::Frame::NONE
            };

            let resp = frame
                .show(ui, |ui| {
                    render_interactive_line(
                        ui,
                        line,
                        &mono,
                        &theme,
                        &func_name_to_addr,
                        &label_name_to_addr,
                        &var_names,
                        func_entry,
                        &mut navigate_to,
                        &mut ctx_action,
                        &bookmarks,
                        &comments,
                        &function_addrs,
                    );
                })
                .response;

            // Track hover: when hovering a decomp line, broadcast its
            // source address so the disasm view can highlight it.
            // (Per-token context menus are attached inside render_interactive_line;
            // adding a row-level interact(click) here would steal left-clicks
            // from the inner link tokens.)
            if resp.hovered() {
                if let Some(addr) = line.addr {
                    new_hovered = Some(addr);
                }
            }
        }
    });

    // Only update hovered_address if the mouse is actually in this view
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

/// Render a single decompile line with clickable function names and addresses.
#[allow(clippy::too_many_arguments)]
fn render_interactive_line(
    ui: &mut Ui,
    line: &AnnotatedLine,
    mono: &egui::TextStyle,
    theme: &crate::theme::Theme,
    func_name_to_addr: &std::collections::HashMap<String, u64>,
    label_name_to_addr: &std::collections::HashMap<String, u64>,
    var_names: &[String],
    func_entry: u64,
    navigate_to: &mut Option<u64>,
    ctx_action: &mut Option<ContextAction>,
    bookmarks: &std::collections::HashSet<u64>,
    comments: &std::collections::HashSet<u64>,
    function_addrs: &std::collections::HashSet<u64>,
) {
    let text = &line.text;
    let trimmed = text.trim();

    let mut tokens = tokenize_line(text, func_name_to_addr, label_name_to_addr, var_names);

    if tokens.is_empty() {
        // No interactive tokens — plain label
        let color = theme.colorize_decompile_line(text);
        ui.label(
            RichText::new(text.as_str())
                .text_style(mono.clone())
                .color(color),
        );
        return;
    }

    ui.horizontal(|ui| {
        tokens.sort_by_key(|t| t.start);

        let mut pos = 0;
        for token in &tokens {
            // Plain text before this token
            if token.start > pos {
                let before = &text[pos..token.start];
                if !before.is_empty() {
                    let color = theme.colorize_decompile_line(trimmed);
                    ui.spacing_mut().item_spacing.x = 0.0;
                    ui.label(
                        RichText::new(before)
                            .text_style(mono.clone())
                            .color(color),
                    );
                }
            }

            // Clickable token
            let token_text = &text[token.start..token.end];
            let color = match token.kind {
                TokenKind::FuncCall => theme.xref_func,
                TokenKind::GotoLabel => theme.addr_normal,
                TokenKind::HexAddress => theme.addr_normal,
                TokenKind::Variable => theme.text_primary,
            };

            ui.spacing_mut().item_spacing.x = 0.0;
            let link_resp = ui.link(
                RichText::new(token_text)
                    .text_style(mono.clone())
                    .color(color),
            );

            match &token.kind {
                TokenKind::Variable => {
                    // No navigation; right-click → Rename Variable.
                    let displayed_name = token_text.to_string();
                    use crate::context_menu::{ExtraContext, RenameKind};
                    address_context_menu(
                        &link_resp,
                        func_entry,
                        RenameKind::Variable,
                        false,
                        false,
                        ExtraContext {
                            string_value: None,
                            variable: Some((func_entry, displayed_name)),
                        },
                        ctx_action,
                    );
                }
                _ => {
                    if link_resp.clicked() {
                        *navigate_to = Some(token.target_addr);
                    }
                    let target = token.target_addr;
                    let rename_kind = match token.kind {
                        TokenKind::FuncCall => crate::context_menu::RenameKind::Function,
                        TokenKind::GotoLabel => crate::context_menu::RenameKind::Label,
                        TokenKind::HexAddress if function_addrs.contains(&target) => {
                            crate::context_menu::RenameKind::Function
                        }
                        _ => crate::context_menu::RenameKind::None,
                    };
                    let is_bookmarked = bookmarks.contains(&target);
                    let has_comment = comments.contains(&target);
                    address_context_menu(
                        &link_resp,
                        target,
                        rename_kind,
                        is_bookmarked,
                        has_comment,
                        crate::context_menu::ExtraContext::default(),
                        ctx_action,
                    );
                }
            }

            pos = token.end;
        }

        // Remaining text after last token
        if pos < text.len() {
            let after = &text[pos..];
            if !after.is_empty() {
                let color = theme.colorize_decompile_line(trimmed);
                ui.spacing_mut().item_spacing.x = 0.0;
                ui.label(
                    RichText::new(after)
                        .text_style(mono.clone())
                        .color(color),
                );
            }
        }
    });
}

#[derive(Debug, Clone, Copy)]
enum TokenKind {
    FuncCall,
    GotoLabel,
    HexAddress,
    Variable,
}

#[derive(Debug)]
struct ClickableToken {
    start: usize,
    end: usize,
    target_addr: u64,
    kind: TokenKind,
}

/// Find clickable tokens in a decompile line.
fn tokenize_line(
    text: &str,
    func_name_to_addr: &std::collections::HashMap<String, u64>,
    label_name_to_addr: &std::collections::HashMap<String, u64>,
    var_names: &[String],
) -> Vec<ClickableToken> {
    let mut tokens = Vec::new();

    // 1. Function names as whole words
    for (name, &addr) in func_name_to_addr {
        if name.is_empty() {
            continue;
        }
        let mut search_from = 0;
        while let Some(pos) = text[search_from..].find(name.as_str()) {
            let abs_pos = search_from + pos;
            let end_pos = abs_pos + name.len();

            let before_ok = abs_pos == 0
                || !text.as_bytes()[abs_pos - 1].is_ascii_alphanumeric()
                    && text.as_bytes()[abs_pos - 1] != b'_';
            let after_ok = end_pos >= text.len()
                || text.as_bytes()[end_pos] == b'('
                || (!text.as_bytes()[end_pos].is_ascii_alphanumeric()
                    && text.as_bytes()[end_pos] != b'_');

            if before_ok && after_ok {
                tokens.push(ClickableToken {
                    start: abs_pos,
                    end: end_pos,
                    target_addr: addr,
                    kind: TokenKind::FuncCall,
                });
            }
            search_from = end_pos;
        }
    }

    // 2. Goto/label references: "label_XXXX"
    let mut search_from = 0;
    while let Some(pos) = text[search_from..].find("label_") {
        let abs_pos = search_from + pos;
        let hex_start = abs_pos + 6;
        let hex_end = text[hex_start..]
            .find(|c: char| !c.is_ascii_hexdigit())
            .map(|p| hex_start + p)
            .unwrap_or(text.len());
        if hex_end > hex_start {
            if let Ok(addr) = u64::from_str_radix(&text[hex_start..hex_end], 16) {
                tokens.push(ClickableToken {
                    start: abs_pos,
                    end: hex_end,
                    target_addr: addr,
                    kind: TokenKind::GotoLabel,
                });
            }
        }
        search_from = hex_end;
    }

    // 2b. User-renamed labels: whole-word match against the label_names map.
    for (name, &addr) in label_name_to_addr {
        if name.is_empty() {
            continue;
        }
        let mut search_from = 0;
        while let Some(pos) = text[search_from..].find(name.as_str()) {
            let abs_pos = search_from + pos;
            let end_pos = abs_pos + name.len();
            let before_ok = abs_pos == 0
                || !text.as_bytes()[abs_pos - 1].is_ascii_alphanumeric()
                    && text.as_bytes()[abs_pos - 1] != b'_';
            let after_ok = end_pos >= text.len()
                || (!text.as_bytes()[end_pos].is_ascii_alphanumeric()
                    && text.as_bytes()[end_pos] != b'_');
            if before_ok && after_ok {
                tokens.push(ClickableToken {
                    start: abs_pos,
                    end: end_pos,
                    target_addr: addr,
                    kind: TokenKind::GotoLabel,
                });
            }
            search_from = end_pos;
        }
    }

    // 2c. Variable references: whole-word match against the function's
    //     post-rename variable names.
    for name in var_names {
        if name.is_empty() {
            continue;
        }
        let mut search_from = 0;
        while let Some(pos) = text[search_from..].find(name.as_str()) {
            let abs_pos = search_from + pos;
            let end_pos = abs_pos + name.len();
            let before_ok = abs_pos == 0
                || !text.as_bytes()[abs_pos - 1].is_ascii_alphanumeric()
                    && text.as_bytes()[abs_pos - 1] != b'_';
            let after_ok = end_pos >= text.len()
                || (!text.as_bytes()[end_pos].is_ascii_alphanumeric()
                    && text.as_bytes()[end_pos] != b'_');
            if before_ok && after_ok {
                tokens.push(ClickableToken {
                    start: abs_pos,
                    end: end_pos,
                    target_addr: 0, // unused for Variable tokens
                    kind: TokenKind::Variable,
                });
            }
            search_from = end_pos;
        }
    }

    // 3. Hex addresses: "0xNNNN" (not inside identifiers, > 0xFF)
    search_from = 0;
    while let Some(pos) = text[search_from..].find("0x") {
        let abs_pos = search_from + pos;
        let before_ok = abs_pos == 0
            || !text.as_bytes()[abs_pos - 1].is_ascii_alphanumeric()
                && text.as_bytes()[abs_pos - 1] != b'_';
        if before_ok {
            let hex_start = abs_pos + 2;
            let hex_end = text[hex_start..]
                .find(|c: char| !c.is_ascii_hexdigit())
                .map(|p| hex_start + p)
                .unwrap_or(text.len());
            if hex_end > hex_start {
                if let Ok(addr) = u64::from_str_radix(&text[hex_start..hex_end], 16) {
                    if addr > 0xFF {
                        tokens.push(ClickableToken {
                            start: abs_pos,
                            end: hex_end,
                            target_addr: addr,
                            kind: TokenKind::HexAddress,
                        });
                    }
                }
            }
            search_from = hex_end.max(abs_pos + 2);
        } else {
            search_from = abs_pos + 2;
        }
    }

    // Remove overlapping tokens
    tokens.sort_by_key(|t| (t.start, std::cmp::Reverse(t.end - t.start)));
    let mut filtered = Vec::new();
    let mut last_end = 0;
    for token in tokens {
        if token.start >= last_end {
            last_end = token.end;
            filtered.push(token);
        }
    }

    filtered
}
