# app/views/log.py
from textual.widgets import Static

class LogView(Static):
    """Tiny log widget with replace/append helpers, independent of Static internals."""

    def on_mount(self) -> None:
        # Internal text buffer we control
        self._buf: str = ""
        self.update("")

    def log(self, text: str) -> None:
        """Append a line to the log."""
        if self._buf:
            self._buf += "\n" + text
        else:
            self._buf = text
        self.update(self._buf)

    def clear(self) -> None:
        """Clear the log entirely."""
        self._buf = ""
        self.update("")

    def set_lines(self, lines: list[str]) -> None:
        """Replace the entire log with these lines."""
        self._buf = "\n".join(lines) if lines else ""
        self.update(self._buf)
