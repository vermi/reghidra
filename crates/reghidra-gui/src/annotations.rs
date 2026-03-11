use egui::{Align2, Area, Id, Key, Order, RichText, Stroke};

use crate::theme::Theme;
use crate::undo::{Action, UndoHistory};
use reghidra_core::Project;

/// What kind of annotation dialog is open.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AnnotationKind {
    Comment,
    Rename,
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

    /// Open a rename dialog for the given address.
    pub fn open_rename(&mut self, address: u64, existing: Option<&str>) {
        self.open = true;
        self.kind = AnnotationKind::Rename;
        self.address = address;
        self.text = existing.unwrap_or("").to_string();
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

        let title = match self.kind {
            AnnotationKind::Comment => format!("Comment @ 0x{:08x}", self.address),
            AnnotationKind::Rename => format!("Rename @ 0x{:08x}", self.address),
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
                            AnnotationKind::Rename => "Enter new name (empty to reset)...",
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
                            let action = match self.kind {
                                AnnotationKind::Comment => {
                                    let old = project.comments.get(&self.address).cloned();
                                    let new_val = if self.text.is_empty() {
                                        None
                                    } else {
                                        Some(self.text.clone())
                                    };
                                    Action::SetComment {
                                        address: self.address,
                                        old_value: old,
                                        new_value: new_val,
                                    }
                                }
                                AnnotationKind::Rename => {
                                    let old =
                                        project.renamed_functions.get(&self.address).cloned();
                                    let new_name = if self.text.is_empty() {
                                        None
                                    } else {
                                        Some(self.text.clone())
                                    };
                                    Action::RenameFunction {
                                        address: self.address,
                                        old_name: old,
                                        new_name,
                                    }
                                }
                            };
                            undo.execute(action, project);
                            committed = true;
                            close_after = true;
                        }

                        ui.add_space(6.0);
                        ui.horizontal(|ui| {
                            if ui.button("OK (Enter)").clicked() {
                                let action = match self.kind {
                                    AnnotationKind::Comment => {
                                        let old =
                                            project.comments.get(&self.address).cloned();
                                        let new_val = if self.text.is_empty() {
                                            None
                                        } else {
                                            Some(self.text.clone())
                                        };
                                        Action::SetComment {
                                            address: self.address,
                                            old_value: old,
                                            new_value: new_val,
                                        }
                                    }
                                    AnnotationKind::Rename => {
                                        let old = project
                                            .renamed_functions
                                            .get(&self.address)
                                            .cloned();
                                        let new_name = if self.text.is_empty() {
                                            None
                                        } else {
                                            Some(self.text.clone())
                                        };
                                        Action::RenameFunction {
                                            address: self.address,
                                            old_name: old,
                                            new_name,
                                        }
                                    }
                                };
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
