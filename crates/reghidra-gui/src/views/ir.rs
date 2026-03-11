use crate::app::ReghidraApp;
use crate::theme::Theme;
use egui::{Color32, RichText, Ui};
use reghidra_ir::op::IrOp;

/// Render the IR (intermediate representation) for the selected function.
pub fn render(app: &mut ReghidraApp, ui: &mut Ui) {
    let Some(ref project) = app.project else {
        return;
    };

    let selected_addr = app.selected_address.unwrap_or(0);
    let hovered_addr = app.hovered_address;
    let mono = egui::TextStyle::Monospace;
    let theme = &app.theme;

    let func = project
        .analysis
        .function_containing(selected_addr)
        .or_else(|| project.analysis.function_at(selected_addr));

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

    let mut navigate_to = None;
    let mut new_hovered: Option<u64> = None;
    let theme = theme.clone();

    egui::ScrollArea::vertical()
        .id_salt("ir_scroll")
        .auto_shrink([false, false])
        .show(ui, |ui| {
            for block in &ir.blocks {
                ui.label(
                    RichText::new(format!("  block_0x{:x}:", block.address))
                        .text_style(mono.clone())
                        .color(theme.ir_block)
                        .strong(),
                );

                for insn in &block.instructions {
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

                ui.add_space(4.0);
            }
        });

    if new_hovered.is_some() {
        app.hovered_address = new_hovered;
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
