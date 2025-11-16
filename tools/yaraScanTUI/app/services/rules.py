from pathlib import Path
import hashlib
from typing import Dict, List, Iterable

# ---------------------------
# Rule file discovery helpers
# ---------------------------

def _iter_rule_files(root: Path) -> Iterable[Path]:
    """Yield all .yar / .yara files under root (case-insensitive)."""
    root = Path(root)
    for p in root.rglob("*"):
        if p.is_file() and p.suffix.lower() in (".yar", ".yara"):
            yield p

def _collect_filepaths(root: Path) -> Dict[str, str]:
    """
    Build a mapping for yara.compile(filepaths=...).
    Keys become the namespace (path-ish), values are absolute file paths.
    Using filepaths preserves 'include' handling in YARA.
    """
    filepaths: Dict[str, str] = {}
    for p in _iter_rule_files(root):
        ns = str(p.parent.relative_to(root)).replace("\\", "/") or "root"
        key = f"{ns}/{p.name}"
        filepaths[key] = str(p.resolve())
    return filepaths

def _rules_digest(root: Path) -> str:
    """Stable digest over rule set (names + mtimes + sizes)."""
    h = hashlib.sha256()
    files = sorted(_iter_rule_files(root), key=lambda x: str(x).lower())
    for p in files:
        st = p.stat()
        h.update(p.name.encode("utf-8", "ignore"))
        h.update(str(st.st_mtime_ns).encode())
        h.update(str(st.st_size).encode())
    return h.hexdigest()[:16]

# ---------------------------
# Compile / load with cache
# ---------------------------

def load_or_compile(root: str | Path, cache_dir: str | Path):
    """
    Load a compiled rules cache if available; otherwise compile from sources.
    Returns (compiled_rules, digest, compile_errors).
    """
    import yara  # local import to avoid hard dep when not scanning

    root = Path(root)
    cache_dir = Path(cache_dir)
    cache_dir.mkdir(parents=True, exist_ok=True)

    digest = _rules_digest(root)
    cache_path = cache_dir / f"rules.{digest}.yarac"

    # Try cached compiled rules
    if cache_path.exists():
        compiled = yara.load(str(cache_path))
        return compiled, digest, []

    # Compile from files (preserves 'include' semantics)
    filepaths = _collect_filepaths(root)
    errors: List[str] = []
    try:
        compiled = yara.compile(filepaths=filepaths)
        compiled.save(str(cache_path))
    except yara.Error as e:
        errors.append(str(e))
        raise
    return compiled, digest, errors

# ---------------------------
# Rule count (for UI only)
# ---------------------------

def estimate_rule_count(root: str | Path) -> int:
    """
    Approximate number of rules by scanning .yar/.yara sources.
    (yara.Rules has no __len__, so this is for display only.)
    """
    root = Path(root)
    count = 0
    for p in _iter_rule_files(root):
        try:
            for line in p.read_text(errors="ignore").splitlines():
                s = line.strip()
                if not s or s.startswith("//") or s.startswith("#"):
                    continue
                if s.startswith("rule ") or s.startswith("global rule ") or s.startswith("private rule "):
                    count += 1
        except Exception:
            pass
    return count
