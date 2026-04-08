use crate::app::ReghidraApp;
use crate::theme::Theme;
use egui::{Color32, RichText, Ui};
use reghidra_ir::op::IrOp;

static IR_LAST_GEN: std::sync::Mutex<[(u64, u64); 2]> =
    std::sync::Mutex::new([(0, 0); 2]);

pub fn reset_scroll_gen() {
    *IR_LAST_GEN.lock().unwrap() = [(0, 0); 2];
}

/// Render the IR (intermediate representation) for the selected function.
pub fn render(app: &mut ReghidraApp, ui: &mut Ui) {
    let Some(ref project) = app.project else {
        return;
    };

    let code_addr = app.code_address.unwrap_or(0);
    let selected_addr = app.selected_address.unwrap_or(0);
    let hovered_addr = app.hovered_address;
    let mono = egui::TextStyle::Monospace;
    let theme = &app.theme;

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
        ui.label("Select a function to view its IR.");
        return;
    };

    let func_entry = func.entry_address;
    let func_name = func.name.clone();

    let Some(ir) = project.analysis.ir_for(func_entry) else {
        ui.label("No IR available for this function.");
        return;
    };

    ui.label(
        RichText::new(format!(
            "{} -- {} blocks, {} IR ops",
            func_name,
            ir.blocks.len(),
            ir.instruction_count(),
        ))
        .strong(),
    );
    ui.separator();

    // Per-pane scroll tracking
    let pane_key = ui.id().value();
    let should_scroll = {
        let mut gens = IR_LAST_GEN.lock().unwrap();
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

    // Build flat display list: block headers, instructions, spacers
    enum IrLine {
        BlockHeader(usize),       // index into ir.blocks
        Instruction(usize, usize), // (block_idx, insn_idx)
        Spacer,
    }

    let mut display_lines: Vec<IrLine> = Vec::new();
    let mut scroll_to_row: Option<usize> = None;

    for (bi, block) in ir.blocks.iter().enumerate() {
        display_lines.push(IrLine::BlockHeader(bi));
        for (ii, insn) in block.instructions.iter().enumerate() {
            if should_scroll && insn.address == selected_addr {
                scroll_to_row = Some(display_lines.len());
            }
            display_lines.push(IrLine::Instruction(bi, ii));
        }
        display_lines.push(IrLine::Spacer);
    }

    let mut navigate_to = None;
    let mut new_hovered: Option<u64> = None;
    let theme = theme.clone();

    let row_height = 18.0;
    let total_rows = display_lines.len();

    let scroll_area = egui::ScrollArea::vertical()
        .id_salt("ir_scroll")
        .auto_shrink([false, false]);

    let visible_height = ui.available_height();
    let spacing_y = ui.spacing().item_spacing.y;
    let scroll_area = if let Some(row_idx) = scroll_to_row {
        let target_offset =
            (row_idx as f32 * (row_height + spacing_y) - visible_height / 2.0).max(0.0);
        scroll_area.vertical_scroll_offset(target_offset)
    } else {
        scroll_area
    };

    scroll_area.show_rows(ui, row_height, total_rows, |ui, row_range| {
        for display_idx in row_range {
            match &display_lines[display_idx] {
                IrLine::BlockHeader(bi) => {
                    let block = &ir.blocks[*bi];
                    ui.label(
                        RichText::new(format!("  block_0x{:x}:", block.address))
                            .text_style(mono.clone())
                            .color(theme.ir_block)
                            .strong(),
                    );
                }
                IrLine::Instruction(bi, ii) => {
                    let insn = &ir.blocks[*bi].instructions[*ii];
                    let is_selected = insn.address == selected_addr;
                    let is_hovered_cross =
                        hovered_addr == Some(insn.address) && !is_selected;

                    let frame = if is_selected {
                        egui::Frame::new().fill(theme.bg_selected)
                    } else if is_hovered_cross {
                        egui::Frame::new().fill(theme.bg_hover)
                    } else {
                        egui::Frame::NONE
                    };

                    let resp = frame
                        .show(ui, |ui| {
                            ui.horizontal(|ui| {
                                let addr_color = if is_selected {
                                    theme.addr_selected
                                } else {
                                    theme.text_dim
                                };
                                if ui
                                    .link(
                                        RichText::new(format!(
                                            "    0x{:08x}.{:02}",
                                            insn.address, insn.sub_index
                                        ))
                                        .text_style(mono.clone())
                                        .color(addr_color),
                                    )
                                    .clicked()
                                {
                                    navigate_to = Some(insn.address);
                                }

                                let (text, color) = format_ir_op(&insn.op, &theme);
                                ui.label(
                                    RichText::new(format!("  {text}"))
                                        .text_style(mono.clone())
                                        .color(color),
                                );
                            });
                        })
                        .response;

                    if resp.hovered() {
                        new_hovered = Some(insn.address);
                    }
                }
                IrLine::Spacer => {
                    ui.add_space(row_height);
                }
            }
        }
    });

    if new_hovered.is_some() {
        app.hovered_address_next = new_hovered;
    }

    if let Some(addr) = navigate_to {
        app.navigate_to(addr);
    }
}

fn format_ir_op(op: &IrOp, theme: &Theme) -> (String, Color32) {
    let text = format!("{op}");
    let color = match op {
        IrOp::Copy { .. } | IrOp::Load { .. } | IrOp::Store { .. } => theme.ir_data,
        IrOp::IntAdd { .. }
        | IrOp::IntSub { .. }
        | IrOp::IntMul { .. }
        | IrOp::IntDiv { .. }
        | IrOp::IntRem { .. }
        | IrOp::IntSMul { .. }
        | IrOp::IntSDiv { .. }
        | IrOp::IntSRem { .. }
        | IrOp::IntNeg { .. }
        | IrOp::IntAnd { .. }
        | IrOp::IntOr { .. }
        | IrOp::IntXor { .. }
        | IrOp::IntNot { .. }
        | IrOp::IntShl { .. }
        | IrOp::IntShr { .. }
        | IrOp::IntSar { .. } => theme.ir_arith,
        IrOp::IntEqual { .. }
        | IrOp::IntNotEqual { .. }
        | IrOp::IntLess { .. }
        | IrOp::IntLessEqual { .. }
        | IrOp::IntSLess { .. }
        | IrOp::IntSLessEqual { .. } => theme.ir_cmp,
        IrOp::Branch { .. }
        | IrOp::CBranch { .. }
        | IrOp::Call { .. }
        | IrOp::CallInd { .. }
        | IrOp::Return { .. }
        | IrOp::BranchInd { .. } => theme.ir_control,
        IrOp::IntZext { .. } | IrOp::IntSext { .. } | IrOp::Subpiece { .. } => theme.ir_ext,
        IrOp::Nop => theme.ir_nop,
        IrOp::Unimplemented { .. } => theme.ir_unimpl,
        IrOp::Phi { .. } => theme.ir_phi,
    };
    (text, color)
}
