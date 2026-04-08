use reghidra_core::Project;

/// A reversible user action.
#[derive(Debug, Clone)]
pub enum Action {
    SetComment {
        address: u64,
        old_value: Option<String>,
        new_value: Option<String>,
    },
    RenameFunction {
        address: u64,
        old_name: Option<String>,
        new_name: Option<String>,
    },
    RenameLabel {
        address: u64,
        old_name: Option<String>,
        new_name: Option<String>,
    },
    RenameVariable {
        func_entry: u64,
        displayed_name: String,
        old_name: Option<String>,
        new_name: Option<String>,
    },
    AddBookmark {
        address: u64,
    },
    RemoveBookmark {
        address: u64,
    },
}

/// Undo/redo history stack.
pub struct UndoHistory {
    undo_stack: Vec<Action>,
    redo_stack: Vec<Action>,
}

impl UndoHistory {
    pub fn new() -> Self {
        Self {
            undo_stack: Vec::new(),
            redo_stack: Vec::new(),
        }
    }

    /// Execute an action on the project and push it to the undo stack.
    pub fn execute(&mut self, action: Action, project: &mut Project) {
        apply_action(&action, project);
        self.undo_stack.push(action);
        self.redo_stack.clear();
    }

    /// Undo the last action.
    pub fn undo(&mut self, project: &mut Project) {
        if let Some(action) = self.undo_stack.pop() {
            let reversed = reverse_action(&action);
            apply_action(&reversed, project);
            self.redo_stack.push(action);
        }
    }

    /// Redo the last undone action.
    pub fn redo(&mut self, project: &mut Project) {
        if let Some(action) = self.redo_stack.pop() {
            apply_action(&action, project);
            self.undo_stack.push(action);
        }
    }

    pub fn can_undo(&self) -> bool {
        !self.undo_stack.is_empty()
    }

    pub fn can_redo(&self) -> bool {
        !self.redo_stack.is_empty()
    }

    pub fn undo_description(&self) -> Option<&str> {
        self.undo_stack.last().map(action_description)
    }

    pub fn redo_description(&self) -> Option<&str> {
        self.redo_stack.last().map(action_description)
    }

    /// Returns true if undoing the next action would change a name that's
    /// rendered into the decompile output (function/label/variable). The GUI
    /// uses this to know when to invalidate the decompile cache.
    pub fn is_next_undo_rename(&self) -> bool {
        self.undo_stack.last().is_some_and(action_affects_decompile)
    }

    pub fn is_next_redo_rename(&self) -> bool {
        self.redo_stack.last().is_some_and(action_affects_decompile)
    }
}

fn action_affects_decompile(a: &Action) -> bool {
    matches!(
        a,
        Action::RenameFunction { .. }
            | Action::RenameLabel { .. }
            | Action::RenameVariable { .. }
    )
}

fn apply_action(action: &Action, project: &mut Project) {
    match action {
        Action::SetComment {
            address, new_value, ..
        } => {
            project.set_comment(
                *address,
                new_value.clone().unwrap_or_default(),
            );
        }
        Action::RenameFunction {
            address, new_name, ..
        } => {
            project.rename_function(
                *address,
                new_name.clone().unwrap_or_default(),
            );
        }
        Action::RenameLabel {
            address, new_name, ..
        } => {
            project.rename_label(
                *address,
                new_name.clone().unwrap_or_default(),
            );
        }
        Action::RenameVariable {
            func_entry,
            displayed_name,
            new_name,
            ..
        } => {
            project.rename_variable(
                *func_entry,
                displayed_name.clone(),
                new_name.clone().unwrap_or_default(),
            );
        }
        Action::AddBookmark { address } => {
            if !project.bookmarks.contains(address) {
                project.bookmarks.push(*address);
            }
        }
        Action::RemoveBookmark { address } => {
            project.bookmarks.retain(|a| a != address);
        }
    }
}

fn reverse_action(action: &Action) -> Action {
    match action {
        Action::SetComment {
            address,
            old_value,
            new_value,
        } => Action::SetComment {
            address: *address,
            old_value: new_value.clone(),
            new_value: old_value.clone(),
        },
        Action::RenameFunction {
            address,
            old_name,
            new_name,
        } => Action::RenameFunction {
            address: *address,
            old_name: new_name.clone(),
            new_name: old_name.clone(),
        },
        Action::RenameLabel {
            address,
            old_name,
            new_name,
        } => Action::RenameLabel {
            address: *address,
            old_name: new_name.clone(),
            new_name: old_name.clone(),
        },
        Action::RenameVariable {
            func_entry,
            displayed_name,
            old_name,
            new_name,
        } => Action::RenameVariable {
            func_entry: *func_entry,
            displayed_name: displayed_name.clone(),
            old_name: new_name.clone(),
            new_name: old_name.clone(),
        },
        Action::AddBookmark { address } => Action::RemoveBookmark { address: *address },
        Action::RemoveBookmark { address } => Action::AddBookmark { address: *address },
    }
}

fn action_description(action: &Action) -> &str {
    match action {
        Action::SetComment { .. } => "Set Comment",
        Action::RenameFunction { .. } => "Rename Function",
        Action::RenameLabel { .. } => "Rename Label",
        Action::RenameVariable { .. } => "Rename Variable",
        Action::AddBookmark { .. } => "Add Bookmark",
        Action::RemoveBookmark { .. } => "Remove Bookmark",
    }
}
