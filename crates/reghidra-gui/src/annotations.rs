use egui::{Align2, Area, Id, Key, Order, RichText, Stroke};

use crate::theme::Theme;
use crate::undo::{Action, UndoHistory};
use reghidra_core::Project;

/// What kind of annotation dialog is open.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AnnotationKind {
    Comment,
    RenameFunction,
    RenameLabel,
    /// Variable rename. Carries the function entry and the displayed name
    /// (post-heuristic, e.g. "arg0") so the action can target the right key.
    RenameVariable {
        func_entry: u64,
        displayed_name: String,
    },
}

/// State for the annotation editing popup.
pub struct AnnotationPopup {
    pub open: bool,
    pub kind: AnnotationKind,
    pub address: u64,
    pub text: String,
    pub needs_focus: bool,
}

impl AnnotationPopup {
    pub fn new() -> Self {
        Self {
            open: false,
            kind: AnnotationKind::Comment,
            address: 0,
            text: String::new(),
            needs_focus: false,
        }
    }

    /// Open a comment dialog for the given address.
    pub fn open_comment(&mut self, address: u64, existing: Option<&str>) {
        self.open = true;
        self.kind = AnnotationKind::Comment;
        self.address = address;
        self.text = existing.unwrap_or("").to_string();
        self.needs_focus = true;
    }

    /// Open a rename-function dialog for the given function entry address.
    pub fn open_rename_function(&mut self, address: u64, existing: Option<&str>) {
        self.open = true;
        self.kind = AnnotationKind::RenameFunction;
        self.address = address;
        self.text = existing.unwrap_or("").to_string();
        self.needs_focus = true;
    }

    /// Open a rename-label dialog for the given block address.
    pub fn open_rename_label(&mut self, address: u64, existing: Option<&str>) {
        self.open = true;
        self.kind = AnnotationKind::RenameLabel;
        self.address = address;
        self.text = existing.unwrap_or("").to_string();
        self.needs_focus = true;
    }

    /// Open a rename-variable dialog. The "address" is set to the function
    /// entry so the title still shows a meaningful location.
    pub fn open_rename_variable(
        &mut self,
        func_entry: u64,
        displayed_name: String,
        existing: Option<&str>,
    ) {
        self.open = true;
        self.address = func_entry;
        self.text = existing.unwrap_or("").to_string();
        self.kind = AnnotationKind::RenameVariable {
            func_entry,
            displayed_name,
        };
        self.needs_focus = true;
    }

    pub fn close(&mut self) {
        self.open = false;
        self.text.clear();
    }

    /// Render the popup. Returns true if an action was committed.
    pub fn show(
        &mut self,
        ctx: &egui::Context,
        theme: &Theme,
        project: &mut Project,
        undo: &mut UndoHistory,
    ) -> bool {
        if !self.open {
            return false;
        }

        let mut committed = false;

        // Handle keyboard
        ctx.input(|i| {
            if i.key_pressed(Key::Escape) {
                self.open = false;
            }
        });

        if !self.open {
            return false;
        }

        let title = match &self.kind {
            AnnotationKind::Comment => format!("Comment @ 0x{:08x}", self.address),
            AnnotationKind::RenameFunction => {
                format!("Rename Function @ 0x{:08x}", self.address)
            }
            AnnotationKind::RenameLabel => format!("Rename Label @ 0x{:08x}", self.address),
            AnnotationKind::RenameVariable { displayed_name, .. } => {
                format!("Rename Variable '{displayed_name}'")
            }
        };

        let mut close_after = false;

        Area::new(Id::new("annotation_popup"))
            .order(Order::Foreground)
            .anchor(Align2::CENTER_CENTER, [0.0, 0.0])
            .show(ctx, |ui| {
                egui::Frame::new()
                    .fill(theme.palette_bg)
                    .stroke(Stroke::new(1.0, theme.palette_border))
                    .corner_radius(8.0)
                    .inner_margin(12.0)
                    .show(ui, |ui| {
                        ui.set_width(350.0);

                        ui.label(RichText::new(&title).strong());
                        ui.separator();

                        let hint = match self.kind {
                            AnnotationKind::Comment => "Enter comment (empty to remove)...",
                            _ => "Enter new name (empty to reset)...",
                        };

                        let response = ui.add(
                            egui::TextEdit::singleline(&mut self.text)
                                .hint_text(hint)
                                .desired_width(330.0)
                                .font(egui::TextStyle::Monospace),
                        );
                        if self.needs_focus {
                            response.request_focus();
                            self.needs_focus = false;
                        }

                        // Enter to confirm
                        if response.lost_focus()
                            && ui.input(|i| i.key_pressed(Key::Enter))
                        {
                            let action = build_action(&self.kind, self.address, &self.text, project);
                            undo.execute(action, project);
                            committed = true;
                            close_after = true;
                        }

                        ui.add_space(6.0);
                        ui.horizontal(|ui| {
                            if ui.button("OK (Enter)").clicked() {
                                let action = build_action(&self.kind, self.address, &self.text, project);
                                undo.execute(action, project);
                                committed = true;
                                close_after = true;
                            }
                            if ui.button("Cancel (Esc)").clicked() {
                                close_after = true;
                            }
                        });
                    });
            });

        if close_after {
            self.close();
        }

        committed
    }
}

fn opt_string(text: &str) -> Option<String> {
    if text.is_empty() {
        None
    } else {
        Some(text.to_string())
    }
}

fn build_action(
    kind: &AnnotationKind,
    address: u64,
    text: &str,
    project: &Project,
) -> Action {
    match kind {
        AnnotationKind::Comment => Action::SetComment {
            address,
            old_value: project.comments.get(&address).cloned(),
            new_value: opt_string(text),
        },
        AnnotationKind::RenameFunction => Action::RenameFunction {
            address,
            old_name: project.renamed_functions.get(&address).cloned(),
            new_name: opt_string(text),
        },
        AnnotationKind::RenameLabel => Action::RenameLabel {
            address,
            old_name: project.label_names.get(&address).cloned(),
            new_name: opt_string(text),
        },
        AnnotationKind::RenameVariable {
            func_entry,
            displayed_name,
        } => Action::RenameVariable {
            func_entry: *func_entry,
            displayed_name: displayed_name.clone(),
            old_name: project
                .variable_names
                .get(&(*func_entry, displayed_name.clone()))
                .cloned(),
            new_name: opt_string(text),
        },
    }
}
