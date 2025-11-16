from __future__ import annotations
from pathlib import Path
from textual.widgets import Static, Button, TextArea
from textual.containers import Vertical, Horizontal
from textual.app import ComposeResult


class RuleEditor(Vertical):
    """
    Simple inline editor for a YARA rule file.
    - Shows file path.
    - Editable TextArea preloaded with content.
    - Cancel / Save buttons.
    """

    def __init__(self, rule_path: Path, on_save, on_cancel):
        super().__init__()
        self.rule_path = Path(rule_path)
        self._on_save = on_save
        self._on_cancel = on_cancel

    def compose(self) -> ComposeResult:
        yield Static(f"[b]Editing:[/b] {self.rule_path}")
        try:
            text = self.rule_path.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            text = ""
        self.editor = TextArea()
        self.editor.load_text(text)
        self.editor.cursor_location = (0, 0)
        yield self.editor

        with Horizontal():
            yield Button("Cancel", id="re_cancel")
            yield Button("Save", id="re_save", variant="success")

    def on_mount(self):
        try:
            self.editor.focus()
        except Exception:
            pass

    def on_button_pressed(self, event: Button.Pressed):
        if event.button.id == "re_cancel":
            self._on_cancel()
        elif event.button.id == "re_save":
            content = self.editor.text or ""
            self._on_save(content)
