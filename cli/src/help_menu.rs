//! `HelpMenu` — the reedline `Menu` backing the live `?` key. Bound so that
//! the first `?` press (while no menu is active) activates this menu in
//! brief mode, and a second consecutive `?` press (this menu already
//! active) switches it to a fuller, more detailed render — see `main.rs`'s
//! keybinding for `?` and the design notes in the project plan for why
//! `ReedlineEvent::UntilFound(vec![Menu("nos_help"), MenuPageNext])` gives
//! exactly that behavior.
//!
//! Deliberately minimal: at most `MAX_VISIBLE` entries, one terminal row
//! each (long text is truncated rather than wrapped, to sidestep exact
//! multi-row layout accounting that reedline's own menus handle via
//! crate-private helpers this crate can't reach). This menu never edits the
//! buffer — `replace_in_buffer` is a no-op — it exists purely to display
//! information sourced from the same `Completer` Tab-completion uses.

use reedline::{Completer, CompletionResult, Editor, Menu, MenuEvent, Painter, Suggestion};

/// Cap on how many candidates are ever shown at once.
const MAX_VISIBLE: usize = 8;

pub struct HelpMenu {
    active: bool,
    values: Vec<Suggestion>,
    /// Brief (summary) vs detailed (fuller explanation) rendering.
    detail: bool,
    pending: Option<MenuEvent>,
    screen_width: u16,
}

impl Default for HelpMenu {
    fn default() -> Self {
        Self {
            active: false,
            values: Vec::new(),
            detail: false,
            pending: None,
            screen_width: 80,
        }
    }
}

impl HelpMenu {
    pub fn new() -> Self {
        Self::default()
    }

    /// The line to render for one suggestion, given the current `detail` mode.
    fn render_line(&self, suggestion: &Suggestion) -> String {
        let usage = suggestion.extra.as_ref().and_then(|e| e.first());
        let text = if self.detail {
            suggestion
                .extra
                .as_ref()
                .and_then(|e| e.get(1))
                .or(suggestion.description.as_ref())
        } else {
            suggestion.description.as_ref()
        };

        let line = match (usage, text) {
            (Some(usage), Some(text)) => format!("{usage}  \u{2014}  {text}"),
            (Some(usage), None) => usage.clone(),
            (None, Some(text)) => format!("{}  {text}", suggestion.value),
            (None, None) => suggestion.value.clone(),
        };

        // No line-wrap accounting is available to us here (see module docs),
        // so truncate instead of risking a line that visually wraps but was
        // only accounted for as a single row.
        let max = (self.screen_width as usize).saturating_sub(1).max(1);
        if line.chars().count() > max {
            line.chars().take(max.saturating_sub(1)).collect::<String>() + "\u{2026}"
        } else {
            line
        }
    }
}

impl Menu for HelpMenu {
    fn name(&self) -> &'static str {
        "nos_help"
    }

    fn indicator(&self) -> &'static str {
        "? "
    }

    fn is_active(&self) -> bool {
        self.active
    }

    fn set_active(&mut self, active: bool) {
        self.active = active;
    }

    fn clear_input(&mut self) {
        self.values.clear();
        self.detail = false;
    }

    fn menu_event(&mut self, event: MenuEvent) {
        self.handle_menu_event(&event);
        self.pending = Some(event);
    }

    fn can_quick_complete(&self) -> bool {
        // Never auto-accept a lone suggestion — this menu is read-only help,
        // not something that should insert text on its own.
        false
    }

    fn can_partially_complete(
        &mut self,
        _values_updated: bool,
        _editor: &mut Editor,
        _completer: &mut dyn Completer,
    ) -> bool {
        false
    }

    fn update_values(&mut self, editor: &mut Editor, completer: &mut dyn Completer) {
        // There is no public way to read the cursor's insertion point from
        // outside reedline, so this assumes the cursor is at the end of the
        // buffer — true for the overwhelmingly common case of typing
        // forward, which is what `?` is used for.
        let buffer = editor.get_buffer().to_string();
        let pos = buffer.len();
        let result: CompletionResult = completer.complete(&buffer, pos);
        self.values = result.suggestions().to_vec();
    }

    fn reset_position(&mut self) {}

    fn update_working_details(
        &mut self,
        editor: &mut Editor,
        completer: &mut dyn Completer,
        painter: &Painter,
    ) {
        self.screen_width = painter.screen_width();
        if let Some(event) = self.pending.take() {
            match event {
                MenuEvent::Activate(_) | MenuEvent::Edit(_) => {
                    self.detail = false;
                    self.update_values(editor, completer);
                }
                MenuEvent::NextPage => {
                    self.detail = true;
                }
                _ => {}
            }
        }
    }

    fn replace_in_buffer(&self, _editor: &mut Editor) {
        // Read-only: pressing Enter while this menu is active should leave
        // the typed line untouched (the engine deactivates the menu and
        // consumes that Enter; the next Enter submits normally).
    }

    fn menu_required_lines(&self, _terminal_columns: u16) -> u16 {
        u16::try_from(self.values.len().min(MAX_VISIBLE)).unwrap_or(u16::MAX)
    }

    fn menu_string(&self, available_lines: u16, _use_ansi_coloring: bool) -> String {
        let max = (available_lines as usize).min(MAX_VISIBLE);
        let mut out = String::new();
        for suggestion in self.values.iter().take(max) {
            out.push_str(&self.render_line(suggestion));
            out.push_str("\r\n");
        }
        out
    }

    fn min_rows(&self) -> u16 {
        1
    }

    fn get_values(&self) -> &[Suggestion] {
        &self.values
    }
}
