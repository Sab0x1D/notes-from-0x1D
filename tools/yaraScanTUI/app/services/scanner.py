from pathlib import Path
from dataclasses import dataclass
from typing import List, Dict, Tuple
import time
import hashlib

@dataclass
class Match:
    rule: str
    namespace: str
    tags: List[str]
    # normalized strings: list of (offset:int, identifier:str, data:bytes)
    strings: List[Tuple[int, str, bytes]]
    meta: Dict[str, object]

@dataclass
class ScanResult:
    matches: List[Match]
    errors: List[str]
    duration_ms: int
    rules_digest: str

def _hashes(p: Path) -> Dict[str, str]:
    h_sha256 = hashlib.sha256()
    h_sha1   = hashlib.sha1()
    h_md5    = hashlib.md5()
    with p.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h_sha256.update(chunk)
            h_sha1.update(chunk)
            h_md5.update(chunk)
    return {"sha256": h_sha256.hexdigest(),
            "sha1":   h_sha1.hexdigest(),
            "md5":    h_md5.hexdigest()}

def _normalize_strings(yara_strings) -> List[Tuple[int, str, bytes]]:
    """
    Normalize python-yara string matches to tuples:
    (offset:int, identifier:str, data:bytes)

    Handles both legacy tuple style and new object style with .instances.
    """
    out: List[Tuple[int, str, bytes]] = []
    for s in yara_strings:
        # Legacy tuple style: (offset, identifier, data)
        if isinstance(s, tuple) and len(s) >= 3:
            off, ident, data = s[0], s[1], s[2]
            try:
                b = bytes(data)
            except Exception:
                b = data if isinstance(data, (bytes, bytearray)) else bytes(str(data), "utf-8", "ignore")
            out.append((int(off), str(ident), b))
            continue

        # Object style
        ident = getattr(s, "identifier", "")
        instances = getattr(s, "instances", None)
        if instances is not None:
            for inst in instances:
                off = getattr(inst, "offset", 0)
                d   = getattr(inst, "matched_data", b"")
                try:
                    b = bytes(d)
                except Exception:
                    b = d if isinstance(d, (bytes, bytearray)) else bytes(str(d), "utf-8", "ignore")
                out.append((int(off), str(ident), b))
        else:
            # Fallback if the object exposes .offset/.data directly
            off = getattr(s, "offset", 0)
            d   = getattr(s, "data", b"")
            try:
                b = bytes(d)
            except Exception:
                b = d if isinstance(d, (bytes, bytearray)) else bytes(str(d), "utf-8", "ignore")
            out.append((int(off), str(ident), b))
    return out

def scan_file(path: str | Path, compiled, timeout: int = 20, rules_digest: str = "") -> ScanResult:
    p = Path(path)
    stat = p.stat()
    externals = {
        "filename": p.name,
        "filepath": str(p),
        "extension": p.suffix.lower().lstrip("."),
        "filesize": stat.st_size,
    }
    externals.update(_hashes(p))

    t0 = time.perf_counter()
    errors: List[str] = []
    matches: List[Match] = []
    try:
        res = compiled.match(str(p), timeout=timeout, externals=externals)
        for m in res:
            strings = _normalize_strings(getattr(m, "strings", []))
            meta    = dict(getattr(m, "meta", {}))
            matches.append(Match(
                rule=m.rule,
                namespace=m.namespace,
                tags=list(m.tags),
                strings=strings,
                meta=meta,
            ))
    except Exception as e:
        errors.append(str(e))

    duration_ms = int((time.perf_counter() - t0) * 1000)
    return ScanResult(matches=matches, errors=errors, duration_ms=duration_ms, rules_digest=rules_digest)
