from pathlib import Path
from typing import Tuple, List
from yara_scan_core.state import AppState
from yara_scan_core.models import RuleStatus
from app.services import staging, rules as rules_service, scanner, export


class ScanController:
    def __init__(self, settings):
        self.settings = settings
        self.state = AppState()

    def set_profile(self, profile: str):
        self.state.profile = profile

    def compile_rules(self, ws: Path):
        """
        Compile or load cached YARA rules from the yara_rules directory.
        Returns compiled rules object and digest.
        """
        compiled, digest, compile_errors = rules_service.load_or_compile("yara_rules", ws / ".cache")
        rule_count = rules_service.estimate_rule_count("yara_rules")
        self.state.rules = RuleStatus(compiled=True, count=rule_count, digest=digest, errors=compile_errors)
        return compiled, digest

    def import_and_scan(self, src_path: str | Path) -> Tuple[bool, str]:
        """
        Stage the incoming sample, compute metadata, compile rules (if needed),
        scan the file, update controller state, and auto-export reports.
        Returns (ok: bool, message: str).
        """
        ws = Path(self.settings.get("workspace_path", "workspace"))
        # ensure workspace layout
        (ws / "samples").mkdir(parents=True, exist_ok=True)
        (ws / ".cache").mkdir(parents=True, exist_ok=True)
        (ws / "reports").mkdir(parents=True, exist_ok=True)

        # Stage file into workspace/samples
        staged = staging.stage_file(src_path, ws / "samples")
        meta = staging.compute_metadata(staged)
        self.state.current_sample = meta

        # Compile rules (or use cached)
        compiled, digest = self.compile_rules(ws)

        # Perform scan
        result = scanner.scan_file(
            staged,
            compiled,
            timeout=int(self.settings.get("scan_timeout_s", 20)),
            rules_digest=digest,
        )
        self.state.last_scan = result

        # AUTO-EXPORT (safe)
        out_dir = ws / "reports" / f"{meta.sha256[:12]}"
        try:
            for fmt in self.settings.get("export_defaults", {}).get("formats", ["json"]):
                export.export_report(meta, result, out_dir, fmt=fmt)
        except Exception as e:
            # don't let export abort the scan; append error to result.errors for visibility
            try:
                result.errors.append(f"export: {e}")
            except Exception:
                # If result.errors isn't writable for some reason, ignore
                pass

        ok = len(result.errors) == 0
        # Build a concise message for the log
        match_count = len(result.matches) if getattr(result, "matches", None) is not None else 0
        msg = f"Scanned {staged.name} in {getattr(result, 'duration_ms', 0)} ms; {match_count} matches"
        return ok, msg

    def export_current(self, formats: List[str]) -> Tuple[bool, str]:
        """
        Export the last scan result for the currently selected sample.
        Returns (ok, message).
        """
        if not getattr(self.state, "current_sample", None) or not getattr(self.state, "last_scan", None):
            return False, "Nothing to export."
        ws = Path(self.settings.get("workspace_path", "workspace"))
        out_dir = ws / "reports" / f"{self.state.current_sample.sha256[:12]}"
        try:
            for fmt in formats:
                export.export_report(self.state.current_sample, self.state.last_scan, out_dir, fmt=fmt)
        except Exception as e:
            return False, f"Export failed: {e}"
        return True, f"Exported to {out_dir} ({', '.join(formats)})"
