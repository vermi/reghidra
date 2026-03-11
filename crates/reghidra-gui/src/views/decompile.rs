use crate::app::ReghidraApp;
use egui::{RichText, Ui};
use reghidra_core::AnnotatedLine;

pub fn render(app: &mut ReghidraApp, ui: &mut Ui) {
    let Some(ref project) = app.project else {
        return;
    };

    let selected_addr = app.selected_address.unwrap_or(0);
    let hovered_addr = app.hovered_address;
    let mono = egui::TextStyle::Monospace;

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

    // Use cached decompile output if the function hasn't changed
    let needs_decompile = match &app.decompile_cache {
        Some((cached_entry, _)) => *cached_entry != func_entry,
        None => true,
    };
    if needs_decompile {
        if let Some(lines) = project.decompile_annotated(func_entry) {
            app.decompile_cache = Some((func_entry, lines));
        } else {
            app.decompile_cache = None;
        }
    }

    let Some((_, ref annotated_lines)) = app.decompile_cache else {
        ui.label("Could not decompile this function.");
        return;
    };

    ui.label(RichText::new(format!("Decompiled: {func_name}")).strong());
    ui.separator();

    let theme = app.theme.clone();
    let annotated_lines = annotated_lines.clone();

    // Build a reverse map: function name -> address
    let func_name_to_addr: std::collections::HashMap<String, u64> = project
        .analysis
        .functions
        .iter()
        .map(|f| {
            let name = project
                .renamed_functions
                .get(&f.entry_address)
                .cloned()
                .unwrap_or_else(|| f.name.clone());
            (name, f.entry_address)
        })
        .collect();

    // Build address-to-block mapping for the current function's IR so we can
    // map any instruction address to its block start address, which is what the
    // annotated lines carry.
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

    let mut navigate_to = None;
    let mut new_hovered: Option<u64> = None;

    egui::ScrollArea::vertical()
        .id_salt("decompile_scroll")
        .auto_shrink([false, false])
        .show(ui, |ui| {
            for line in &annotated_lines {
                // Determine highlighting for this line:
                // 1. Selected: line's block matches the selected instruction's block
                // 2. Hover: line's block matches the hovered instruction's block
                let line_block = line.addr;
                let is_selected_block =
                    selected_block.is_some() && line_block == selected_block;
                let is_hovered_block = hovered_block.is_some()
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
                            &mut navigate_to,
                        );
                    })
                    .response;

                // Track hover: when hovering a decomp line, broadcast its
                // source address so the disasm view can highlight it
                if resp.hovered() {
                    if let Some(addr) = line.addr {
                        new_hovered = Some(addr);
                    }
                }
            }
        });

    // Only update hovered_address if the mouse is actually in this view
    // (new_hovered will be None if mouse isn't over any line)
    if new_hovered.is_some() {
        app.hovered_address = new_hovered;
    }

    if let Some(addr) = navigate_to {
        app.navigate_to(addr);
    }
}

/// Render a single decompile line with clickable function names and addresses.
fn render_interactive_line(
    ui: &mut Ui,
    line: &AnnotatedLine,
    mono: &egui::TextStyle,
    theme: &crate::theme::Theme,
    func_name_to_addr: &std::collections::HashMap<String, u64>,
    navigate_to: &mut Option<u64>,
) {
    let text = &line.text;
    let trimmed = text.trim();

    let mut tokens = tokenize_line(text, func_name_to_addr);

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
            };

            ui.spacing_mut().item_spacing.x = 0.0;
            if ui
                .link(
                    RichText::new(token_text)
                        .text_style(mono.clone())
                        .color(color),
                )
                .clicked()
            {
                *navigate_to = Some(token.target_addr);
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

#[derive(Debug)]
enum TokenKind {
    FuncCall,
    GotoLabel,
    HexAddress,
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
