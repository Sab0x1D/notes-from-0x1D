from pathlib import Path
from typing import Dict, Any
import json

def export_report(sample, result, out_dir: str | Path, fmt: str = "json"):
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    data = {
        "sample": {
            "path": str(sample.path),
            "size": sample.size,
            "sha256": sample.sha256,
            "sha1": sample.sha1,
            "md5": sample.md5,
            "mime": sample.mime,
            "pe": sample.pe,
        },
        "result": {
            "rules_digest": result.rules_digest,
            "duration_ms": result.duration_ms,
            "errors": result.errors,
            "matches": [{
                "rule": m.rule,
                "namespace": m.namespace,
                "tags": m.tags,
                "meta": m.meta,
                "strings": [{"id": s.identifier, "offset": s.offset, "preview": s.data_preview} for s in m.strings]
            } for m in result.matches]
        }
    }
    if fmt == "json":
        (out_dir / "scan.json").write_text(json.dumps(data, indent=2))
    elif fmt == "md":
        (out_dir / "report.md").write_text(_to_markdown(data))
    elif fmt == "html":
        (out_dir / "report.html").write_text(_to_html(data))
    else:
        raise ValueError(f"Unsupported format: {fmt}")

def _to_markdown(data: Dict[str, Any]) -> str:
    s = data["sample"]
    r = data["result"]
    md = []
    md.append(f"# YaraScan Report")
    md.append("")
    md.append(f"**File:** `{s['path']}`  ")
    md.append(f"**Size:** {s['size']} bytes  ")
    md.append(f"**SHA-256:** `{s['sha256']}`  ")
    md.append("")
    md.append(f"**Rules digest:** `{r['rules_digest']}`  ")
    md.append(f"**Duration:** {r['duration_ms']} ms  ")
    md.append("")
    if r["errors"]:
        md.append("## Errors")
        for e in r["errors"]:
            md.append(f"- {e}")
    md.append("## Matches")
    if not r["matches"]:
        md.append("_No matches_")
    for m in r["matches"]:
        md.append(f"### {m['rule']}  \n*Namespace:* `{m['namespace']}`  \n*Tags:* {', '.join(m['tags']) or '-'}")
        if m["meta"]:
            md.append("**Meta:**")
            for k,v in m["meta"].items():
                md.append(f"- {k}: {v}")
        if m["strings"]:
            md.append("**Strings:**")
            for s in m["strings"][:50]:
                md.append(f"- `{s['id']}` @ 0x{s['offset']:X}: {s['preview']}")
        md.append("")
    return "\n".join(md)

def _to_html(data: Dict[str, Any]) -> str:
    import html
    md = _to_markdown(data)
    return "<pre>" + html.escape(md) + "</pre>"
