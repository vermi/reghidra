//! Right-click context menu for symbol/address actions.
//!
//! Mirrors the keyboard shortcuts and Edit menu so any action available on a
//! symbol (rename, comment, bookmark, navigate, xrefs, copy) is also reachable
//! via right-click on its row/token in any view.

use crate::app::{MainView, ReghidraApp};

/// Deferred action emitted from a context menu, applied after the borrow on
/// `app.project` has been released.
#[derive(Debug, Clone)]
pub enum ContextAction {
    Navigate(u64),
    AddComment(u64),
    RenameFunction(u64),
    RenameLabel(u64),
    RenameVariable {
        func_entry: u64,
        displayed_name: String,
    },
    /// Phase 5c PR 5: "Set Type..." on a local variable. Opens a
    /// text-entry popup where the user types a C type name (e.g.
    /// `HANDLE`, `uint32_t`, `char*`). The string is parsed at
    /// decompile time via `parse_user_ctype` and applied to the
    /// matching `VarDecl` by the final typing pass.
    SetVariableType {
        func_entry: u64,
        displayed_name: String,
    },
    ToggleBookmark(u64),
    ShowXrefs(u64),
}

/// Attach a right-click context menu to `response` for the given address.
///
/// `is_function` controls whether the "Rename Function" entry is shown.
/// `is_bookmarked` / `has_comment` toggle the labels for those entries.
/// Selecting an item writes a `ContextAction` into `pending` for the caller
/// to apply once the project borrow has been released.
/// What kind of name (if any) the right-clicked target supports.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RenameKind {
    /// Not renameable.
    None,
    /// A function entry — uses Project::renamed_functions.
    Function,
    /// A label / branch target inside a function — uses Project::label_names.
    Label,
    /// A local variable inside a function. Carries (func_entry, displayed_name)
    /// passed via the rename action.
    Variable,
}

/// Optional context for things attached to the address that can be copied.
#[derive(Debug, Default, Clone)]
pub struct ExtraContext<'a> {
    /// String literal at this address (if any) — enables "Copy String".
    pub string_value: Option<&'a str>,
    /// For variable renames: the function entry and the variable's displayed name.
    pub variable: Option<(u64, String)>,
}

pub fn address_context_menu(
    response: &egui::Response,
    addr: u64,
    rename_kind: RenameKind,
    is_bookmarked: bool,
    has_comment: bool,
    extra: ExtraContext<'_>,
    pending: &mut Option<ContextAction>,
) {
    response.context_menu(|ui| {
        ui.label(egui::RichText::new(format!("0x{addr:08x}")).strong());
        ui.separator();

        if ui.button("Navigate Here").clicked() {
            *pending = Some(ContextAction::Navigate(addr));
            ui.close_menu();
        }

        ui.separator();

        let comment_label = if has_comment {
            "Edit Comment...   ;"
        } else {
            "Add Comment...   ;"
        };
        if ui.button(comment_label).clicked() {
            *pending = Some(ContextAction::AddComment(addr));
            ui.close_menu();
        }

        match rename_kind {
            RenameKind::Function => {
                if ui.button("Rename Function...   r").clicked() {
                    *pending = Some(ContextAction::RenameFunction(addr));
                    ui.close_menu();
                }
            }
            RenameKind::Label => {
                if ui.button("Rename Label...").clicked() {
                    *pending = Some(ContextAction::RenameLabel(addr));
                    ui.close_menu();
                }
            }
            RenameKind::Variable => {
                if let Some((func_entry, ref name)) = extra.variable {
                    if ui.button("Rename Variable...").clicked() {
                        *pending = Some(ContextAction::RenameVariable {
                            func_entry,
                            displayed_name: name.clone(),
                        });
                        ui.close_menu();
                    }
                    if ui.button("Set Type...").clicked() {
                        *pending = Some(ContextAction::SetVariableType {
                            func_entry,
                            displayed_name: name.clone(),
                        });
                        ui.close_menu();
                    }
                }
            }
            RenameKind::None => {}
        }

        let bookmark_label = if is_bookmarked {
            "Remove Bookmark   Cmd+B"
        } else {
            "Add Bookmark   Cmd+B"
        };
        if ui.button(bookmark_label).clicked() {
            *pending = Some(ContextAction::ToggleBookmark(addr));
            ui.close_menu();
        }

        ui.separator();

        if ui.button("Show Cross-References   x").clicked() {
            *pending = Some(ContextAction::ShowXrefs(addr));
            ui.close_menu();
        }

        if ui.button("Copy Address").clicked() {
            ui.ctx().copy_text(format!("0x{addr:x}"));
            ui.close_menu();
        }

        if let Some(s) = extra.string_value {
            if ui.button("Copy String").clicked() {
                ui.ctx().copy_text(s.to_string());
                ui.close_menu();
            }
        }
    });
}

/// Apply a deferred context-menu action to the app.
pub fn apply_context_action(app: &mut ReghidraApp, action: ContextAction) {
    match action {
        ContextAction::Navigate(addr) => {
            app.navigate_to(addr);
        }
        ContextAction::AddComment(addr) => {
            let existing = app
                .project
                .as_ref()
                .and_then(|p| p.comments.get(&addr))
                .cloned();
            app.annotation_popup.open_comment(addr, existing.as_deref());
        }
        ContextAction::RenameFunction(addr) => {
            let existing = app
                .project
                .as_ref()
                .and_then(|p| p.renamed_functions.get(&addr))
                .cloned();
            app.annotation_popup
                .open_rename_function(addr, existing.as_deref());
        }
        ContextAction::RenameLabel(addr) => {
            let existing = app
                .project
                .as_ref()
                .and_then(|p| p.label_names.get(&addr))
                .cloned();
            app.annotation_popup
                .open_rename_label(addr, existing.as_deref());
        }
        ContextAction::RenameVariable {
            func_entry,
            displayed_name,
        } => {
            let existing = app
                .project
                .as_ref()
                .and_then(|p| p.variable_names.get(&(func_entry, displayed_name.clone())))
                .cloned();
            app.annotation_popup.open_rename_variable(
                func_entry,
                displayed_name,
                existing.as_deref(),
            );
        }
        ContextAction::SetVariableType {
            func_entry,
            displayed_name,
        } => {
            let existing = app
                .project
                .as_ref()
                .and_then(|p| p.variable_types.get(&(func_entry, displayed_name.clone())))
                .cloned();
            app.annotation_popup.open_set_variable_type(
                func_entry,
                displayed_name,
                existing.as_deref(),
            );
        }
        ContextAction::ToggleBookmark(addr) => {
            // toggle_bookmark() acts on selected_address; ensure that's the
            // address the user right-clicked, not whatever was previously
            // selected from another view.
            let prev = app.selected_address;
            app.selected_address = Some(addr);
            app.toggle_bookmark();
            // Restore navigation history's notion of selection only if we
            // didn't actually want to move there. Right-click should not
            // hijack the user's current selection.
            if prev.is_some() && prev != Some(addr) {
                app.selected_address = prev;
            }
        }
        ContextAction::ShowXrefs(addr) => {
            app.navigate_to(addr);
            *app.focused_view_mut() = MainView::Xrefs;
        }
    }
}
