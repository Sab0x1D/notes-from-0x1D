from textual.app import App, ComposeResult
from textual.widgets import Header, Footer, Button, Static, Select, DirectoryTree, TextArea
from textual.containers import Horizontal, Vertical
from textual import events
from textual.dom import NoMatches
from textual.screen import ModalScreen
from pathlib import Path
import yaml
import webbrowser
from typing import List, Tuple, Any
import types
import sys
import subprocess  # may be used later

from app.controllers.scan import ScanController
from app.views.file_info import FileInfo
from app.views.matches import MatchesView
from app.views.ruleset import RuleSetView
from app.views.log import LogView


# ─────────────────────────────────────────
# Settings
# ─────────────────────────────────────────
def load_settings():
    path = Path("settings.yaml")
    if path.exists():
        return yaml.safe_load(path.read_text())
    return {
        "workspace_path": "workspace",
        "scan_timeout_s": 20,
        "max_file_mb": 100,
        "export_defaults": {"formats": ["json", "md", "html"]},
        "profiles": {"full": {}},
    }


# ─────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────
def discover_rule_files(workspace: Path) -> List[Path]:
    candidates = [
        workspace / "yara_rules",
        Path("yara_rules"),
        workspace / "rules",
        workspace,
    ]
    exts = (".yar", ".yara")
    for root in candidates:
        try:
            root = root.resolve()
        except Exception:
            continue
        if not root.exists() or not root.is_dir():
            continue
        files = sorted([p for p in root.rglob("*") if p.suffix.lower() in exts])
        if files:
            return files
    return []


def _strings_list_from_match(m0: Any) -> List[str]:
    if hasattr(m0, "strings"):
        raw = m0.strings or []
    elif isinstance(m0, dict):
        raw = m0.get("strings") or []
    else:
        raw = []
    out: List[str] = []
    for s in raw:
        if isinstance(s, (tuple, list)) and len(s) >= 3:
            out.append(str(s[2]))
        else:
            out.append(str(s))
    return out


def _dedup_strings(strings: List[str]) -> List[str]:
    seen = set()
    uniq: List[str] = []
    for s in strings:
        k = s.lower()
        if k not in seen:
            seen.add(k)
            uniq.append(s)
    return uniq


def _make_dedup_proxy(last_scan: Any) -> Any:
    """Return a ScanResult-like object whose matches have deduped strings and red rule/ns."""
    if hasattr(last_scan, "matches"):
        matches = last_scan.matches or []
    elif isinstance(last_scan, dict):
        matches = last_scan.get("matches") or []
    else:
        matches = []

    proxy_matches: List[Any] = []
    for m in matches:
        rule_raw = m.get("rule", "") if isinstance(m, dict) else getattr(m, "rule", "")
        ns_raw = m.get("namespace", "") if isinstance(m, dict) else getattr(m, "namespace", "")
        tags = m.get("tags", []) if isinstance(m, dict) else (getattr(m, "tags", []) or [])
        meta = m.get("meta", {}) if isinstance(m, dict) else getattr(m, "meta", {})
        strings = _dedup_strings(_strings_list_from_match(m))
        proxy_matches.append(
            types.SimpleNamespace(
                rule=f"[red]{rule_raw}[/red]" if rule_raw else "",
                namespace=f"[red]{ns_raw}[/red]" if ns_raw else "",
                tags=list(tags) if tags else [],
                strings=strings,
                meta=meta,
            )
        )
    return types.SimpleNamespace(matches=proxy_matches)


def _export_safe_swap(last_scan: Any):
    """
    Build an exporter-friendly 'matches' list:
      • match has: .rule .namespace .tags .meta
      • .strings -> objects with .offset .identifier .text .data_preview
    Returns (converted, original) so caller can restore.
    """
    if not hasattr(last_scan, "matches"):
        return None, None
    original = last_scan.matches
    converted = []
    for m in original or []:
        rule = m.get("rule", "") if isinstance(m, dict) else getattr(m, "rule", "")
        ns = m.get("namespace", "") if isinstance(m, dict) else getattr(m, "namespace", "")
        tags = m.get("tags", []) if isinstance(m, dict) else (getattr(m, "tags", []) or [])
        meta = m.get("meta", {}) if isinstance(m, dict) else (getattr(m, "meta", {}) or {})
        raw_strings = m.get("strings") if isinstance(m, dict) else getattr(m, "strings", [])
        safe_strings = []
        for s in raw_strings or []:
            if isinstance(s, (tuple, list)) and len(s) >= 3:
                text_str = str(s[2])
                safe_strings.append(
                    types.SimpleNamespace(
                        offset=s[0], identifier=s[1], text=text_str, data_preview=text_str[:120]
                    )
                )
            elif isinstance(s, dict):
                text_str = str(s.get("text", ""))
                safe_strings.append(
                    types.SimpleNamespace(
                        offset=s.get("offset", 0),
                        identifier=s.get("identifier", "str"),
                        text=text_str,
                        data_preview=text_str[:120],
                    )
                )
            else:
                text_str = str(s)
                safe_strings.append(
                    types.SimpleNamespace(offset=0, identifier="str", text=text_str, data_preview=text_str[:120])
                )
        converted.append(types.SimpleNamespace(rule=rule, namespace=ns, tags=tags, meta=meta, strings=safe_strings))
    return converted, original


# ─────────────────────────────────────────
# Pickers & Editor
# ─────────────────────────────────────────
class FilePicker(Vertical):
    def __init__(self, on_pick):
        super().__init__()
        self.on_pick = on_pick

    def compose(self) -> ComposeResult:
        yield Static("[b]Select a file to import[/b] (Enter to select)")
        desktop = Path.home() / "Desktop"
        base_path = desktop if desktop.exists() else Path.home()
        self.dir_tree = DirectoryTree(base_path)
        yield self.dir_tree
        yield Button("Close", id="fp_close")

    def on_mount(self):
        try:
            self.dir_tree.focus()
        except Exception:
            pass

    def on_directory_tree_file_selected(self, event: DirectoryTree.FileSelected):
        self.on_pick(event.path)
        self.remove()

    def on_button_pressed(self, event: Button.Pressed):
        if event.button.id == "fp_close":
            self.remove()


class RulePicker(Vertical):
    def __init__(self, options: List[Tuple[str, str]], on_pick):
        super().__init__()
        self._options = options or [("No rules found", "")]
        self.on_pick = on_pick

    def compose(self) -> ComposeResult:
        yield Static("[b]Select a rule to edit[/b] (Enter to choose)")
        self.select = Select(self._options, id="rp_select", prompt="Rules")
        yield self.select
        with Horizontal():
            yield Button("Cancel", id="rp_cancel")
            yield Button("Open", id="rp_open")

    def on_mount(self):
        try:
            self.select.focus()
        except Exception:
            pass

    def on_button_pressed(self, event: Button.Pressed):
        if event.button.id == "rp_cancel":
            self.remove()
        elif event.button.id == "rp_open":
            val = self.select.value or ""
            if val:
                self.on_pick(Path(val))
            self.remove()


class RuleEditor(ModalScreen[None]):
    """In-TUI YARA rule editor with Save/Cancel."""
    def __init__(self, rule_path: Path, on_save):
        super().__init__()
        self.rule_path = Path(rule_path)
        self.on_save = on_save

    def compose(self) -> ComposeResult:
        yield Static(f"[b]Editing:[/b] {self.rule_path}")
        try:
            text = self.rule_path.read_text(encoding="utf-8", errors="replace")
        except Exception:
            text = ""
        self.editor = TextArea(text)
        yield self.editor
        with Horizontal():
            yield Button("Cancel", id="re_cancel")
            yield Button("Save", id="re_save", variant="primary")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "re_cancel":
            self.dismiss()
        elif event.button.id == "re_save":
            try:
                self.rule_path.write_text(self.editor.text, encoding="utf-8")
                self.on_save(self.rule_path)
                self.dismiss()
            except Exception as e:
                self.editor.text += f"\n\n// SAVE ERROR: {e}\n"


# ─────────────────────────────────────────
# App
# ─────────────────────────────────────────
class YaraScanTUI(App):
    CSS = """
    Screen { layout: vertical; }
    #toolbar { height: 3; }
    #main { height: 1fr; }
    #left { width: 38; }
    #right { width: 1fr; }
    #log { height: 4; }
    #matches { height: auto; }
    #strings_detail { height: auto; padding: 0 1; }
    #bottom { height: auto; border-top: solid $surface; }
    #fi { width: 1fr; height: 9; }  /* 9 lines */
    """
    BINDINGS = [
        ("i", "import", "Import"),
        ("r", "rescan", "Rescan"),
        ("e", "export", "Export"),
        ("o", "edit", "Edit Rule"),
        ("h", "copy_sha256", "Copy SHA256"),
        ("v", "open_virustotal", "VirusTotal"),
        ("q", "quit", "Quit"),
    ]

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        with Horizontal(id="toolbar"):
            yield Button("Import", id="btn_import")
            yield Button("Rescan", id="btn_rescan")
            yield Button("Export", id="btn_export")
            yield Button("Edit Rule", id="btn_edit")
        with Horizontal(id="main"):
            with Vertical(id="left"):
                self.ruleset = RuleSetView()
                yield self.ruleset
            with Vertical(id="right"):
                self.log_panel = LogView(id="log")
                yield self.log_panel
                self.matches = MatchesView(id="matches")
                yield self.matches
                self.strings_detail = Static(id="strings_detail")
                yield self.strings_detail

        self.bottom = Horizontal(id="bottom")
        yield self.bottom
        yield Footer()

    @property
    def _toolbar_ids(self):
        return ["btn_import", "btn_rescan", "btn_export", "btn_edit"]

    def _focus_toolbar_index(self, idx: int):
        ids = self._toolbar_ids
        idx = max(0, min(len(ids) - 1, idx))
        try:
            self.query_one(f"#{ids[idx]}").focus()
        except Exception:
            pass
        self._focused_idx = idx

    def on_mount(self):
        self._focused_idx = 0
        self._focus_toolbar_index(0)
        self.settings = load_settings()
        self.controller = ScanController(self.settings)

        try:
            ws = Path(self.settings.get("workspace_path", "workspace"))
            self.controller.compile_rules(ws)
            self.ruleset.update_status(self.controller.state.rules)
            self.log_panel.log("Rules compiled and cached.")
        except Exception as e:
            self.log_panel.log(f"[red]Rule compile error:[/red] {e}")

        self._ensure_file_info()

    async def on_key(self, event: events.Key):
        focused = self.focused
        ids = self._toolbar_ids
        if not focused or getattr(focused, "id", None) not in ids:
            return
        if event.key in ("left", "right"):
            step = -1 if event.key == "left" else 1
            self._focus_toolbar_index((self._focused_idx + step) % len(ids))
            event.stop()
        elif event.key == "enter":
            wid = ids[self._focused_idx]
            getattr(self, f"action_{wid.split('_')[1]}")()
            event.stop()

    # ─────────────────────────────────────
    # Toolbar actions
    # ─────────────────────────────────────
    def action_import(self):
        try:
            self.bottom.remove_children()
        except Exception:
            for c in list(self.bottom.children):
                c.remove()
        picker = FilePicker(self._on_file_picked)
        self.bottom.mount(picker)

    def action_rescan(self):
        sample = getattr(self.controller.state, "current_sample", None)
        if not sample:
            self.log_panel.set_lines(["No file to rescan."])
            return
        try:
            ok, msg = self.controller.import_and_scan(sample.path)
            self._post_scan_update(log=f"[cyan]Rescan:[/cyan] {msg}")
        except Exception as e:
            self.log_panel.set_lines([f"[red]Rescan failed:[/red] {e}"])

    def action_export(self):
        ls = getattr(self.controller.state, "last_scan", None)
        if not ls:
            self.log_panel.set_lines(["[yellow]Nothing to export.[/yellow]"])
            return

        converted, original = _export_safe_swap(ls)
        try:
            if converted is not None:
                ls.matches = converted
            formats = self.settings.get("export_defaults", {}).get("formats", ["json", "md", "html"])
            ok, msg = self.controller.export_current(formats)
            self.log_panel.set_lines([msg])
        except Exception as e:
            self.log_panel.set_lines([f"[red]Export failed:[/red] {e}"])
        finally:
            if converted is not None:
                ls.matches = original

    def action_edit(self):
        self.action_edit_rule()

    def action_edit_rule(self):
        # 🧹 Reset all data when entering Edit Rule
        try:
            self.matches.update_matches(types.SimpleNamespace(matches=[]))
            self.strings_detail.update("")
            self.file_info.update_info(None)
            self.log_panel.set_lines(["Edit Rule mode — previous scan cleared."])
        except Exception:
            pass

        try:
            self.bottom.remove_children()
        except Exception:
            for c in list(self.bottom.children):
                c.remove()

        ws = Path(self.settings.get("workspace_path", "workspace")).resolve()
        files = discover_rule_files(ws)
        options = [(str(p.name), str(p)) for p in files] or [("No rules found", "")]
        picker = RulePicker(options, on_pick=self._on_rule_chosen)
        self.bottom.mount(picker)

    # ─────────────────────────────────────
    # Internal flows
    # ─────────────────────────────────────
    def _ensure_file_info(self):
        try:
            self.file_info = self.query_one("#fi", FileInfo)
        except NoMatches:
            self.file_info = FileInfo(id="fi")
            self.bottom.mount(self.file_info)

    def _show_results(self):
        self._ensure_file_info()

    def _post_scan_update(self, log: str):
        self._ensure_file_info()
        self.file_info.update_info(self.controller.state.current_sample)
        proxy = _make_dedup_proxy(self.controller.state.last_scan)
        self.matches.update_matches(proxy)
        self._update_strings_detail()
        self.ruleset.update_status(self.controller.state.rules)
        self.log_panel.set_lines(["Rules compiled and cached.", log])
        self._show_results()
        self.refresh(layout=True)

    # ==== red strings detail (de-duplicated) ====
    def _update_strings_detail(self):
        try:
            scan = getattr(self.controller.state, "last_scan", None)
            if not scan:
                self.strings_detail.update("")
                return
            if hasattr(scan, "matches"):
                matches = scan.matches or []
            elif isinstance(scan, dict):
                matches = scan.get("matches") or []
            else:
                matches = []
            if not matches:
                self.strings_detail.update("[red]No matches.[/red]")
                return
            uniq = _dedup_strings(_strings_list_from_match(matches[0]))
            if not uniq:
                self.strings_detail.update("")
                return
            lines = ["[bold red]String matches[/bold red]"]
            for i, s in enumerate(uniq, 1):
                lines.append(f"[red]$str{i}[/red]  →  [red]{s}[/red]")
            self.strings_detail.update("\n".join(lines))
        except Exception as err:
            self.strings_detail.update(f"[red]String render error:[/red] {err}")

    # ─────────────────────────────────────
    # Picker callbacks
    # ─────────────────────────────────────
    def _on_file_picked(self, path: Path):
        try:
            ok, msg = self.controller.import_and_scan(path)
            self._post_scan_update(log=msg)
        except Exception as e:
            self.log_panel.set_lines([f"[red]Import/scan failed:[/red] {e}"])

    def _on_rule_chosen(self, rule_path: Path):
        def _after_save(p: Path):
            try:
                ws = Path(self.settings.get("workspace_path", "workspace"))
                self.controller.compile_rules(ws)
                self.ruleset.update_status(self.controller.state.rules)
                self.log_panel.set_lines([f"Saved & recompiled: {p.name}"])
            except Exception as e:
                self.log_panel.set_lines([f"[red]Recompile failed:[/red] {e}"])
        self.push_screen(RuleEditor(rule_path, on_save=_after_save))

    # ─────────────────────────────────────
    # Utilities
    # ─────────────────────────────────────
    def action_copy_sha256(self):
        sample = getattr(self.controller.state, "current_sample", None)
        if not sample:
            self.log_panel.set_lines(["[yellow]No sample loaded.[/yellow]"])
            return
        try:
            self.copy_to_clipboard(sample.sha256)
            self.log_panel.set_lines(["SHA256 copied to clipboard."])
        except Exception as e:
            self.log_panel.set_lines([f"[red]Copy failed:[/red] {e}"])

    def action_open_virustotal(self):
        sample = getattr(self.controller.state, "current_sample", None)
        if not sample:
            self.log_panel.set_lines(["[yellow]No sample loaded.[/yellow]"])
            return
        url = f"https://www.virustotal.com/gui/file/{sample.sha256}"
        try:
            webbrowser.open_new_tab(url)
            self.log_panel.set_lines(["Opened VirusTotal."])
        except Exception as e:
            self.log_panel.set_lines([f"[red]Open VT failed:[/red] {e}"])


if __name__ == "__main__":
    YaraScanTUI().run()
