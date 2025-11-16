from textual.widgets import Static

class RuleSetView(Static):
    def update_status(self, status):
        if not status:
            self.update("Rules not loaded.")
            return
        errors = "\n".join(status.errors) if status.errors else "None"
        self.update(f"[b]Compiled:[/b] {status.compiled}  |  [b]Count:[/b] {status.count}  |  [b]Digest:[/b] {status.digest}\nErrors: {errors}")
