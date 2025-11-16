from textual.widgets import Static
from rich.table import Table

class MatchesView(Static):
    def update_matches(self, result):
        # No result or no hits
        if not result or not getattr(result, "matches", None):
            self.update("[bold red]No matches.[/bold red]")
            return

        # Collect families from rule meta (common keys)
        fam_keys = ("family", "malware_family", "threat_family", "family_name")
        families = []
        for m in result.matches:
            meta = getattr(m, "meta", {}) or {}
            fam = next((meta.get(k) for k in fam_keys if meta.get(k)), None)
            if fam and str(fam) not in families:
                families.append(str(fam))

        # Build matches table
        table = Table(title="Matches", expand=True)
        table.add_column("Rule", no_wrap=True)
        table.add_column("NS", no_wrap=True)
        table.add_column("Tags")
        table.add_column("#Strings", justify="right")

        for m in result.matches:
            table.add_row(
                m.rule,
                m.namespace,
                ", ".join(m.tags),
                str(len(m.strings) if getattr(m, "strings", None) else 0),
            )

        # Prepend a bold RED banner with detected family (yaradiff_tui style)
        if families:
            banner = "[bold red]Detected family:[/bold red] " + ", ".join(families)
            # Show banner + table
            self.update(banner + "\n")
            self.update(table)
        else:
            self.update(table)
