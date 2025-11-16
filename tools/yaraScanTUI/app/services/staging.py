import hashlib, shutil
from pathlib import Path
from datetime import datetime

def _hash_file(path: Path, algo="sha256", block_size=1024*1024):
    h = hashlib.new(algo)
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(block_size), b""):
            h.update(chunk)
    return h.hexdigest()

def stage_file(src: str | Path, dest_root: str | Path) -> Path:
    src = Path(src)
    dest_root = Path(dest_root)
    date = datetime.utcnow().strftime("%Y%m%d")
    dest_dir = dest_root / date
    dest_dir.mkdir(parents=True, exist_ok=True)
    sha256 = _hash_file(src, "sha256")
    staged = dest_dir / f"{sha256[:8]}_{src.name}"
    shutil.copy2(src, staged)
    return staged

def compute_metadata(staged: Path):
    from yara_scan_core.models import SampleInfo
    size = staged.stat().st_size
    sha256 = _hash_file(staged, "sha256")
    sha1 = _hash_file(staged, "sha1")
    md5 = _hash_file(staged, "md5")
    mime = "application/octet-stream"
    pe = None
    try:
        import pefile
        pe = _pe_summary(staged)
    except Exception:
        pe = None
    return SampleInfo(path=staged, size=size, sha256=sha256, sha1=sha1, md5=md5, mime=mime, pe=pe)

def _pe_summary(path: Path):
    import pefile
    try:
        pe = pefile.PE(str(path), fast_load=True)
        return {
            "is_pe": True,
            "machine": hex(pe.FILE_HEADER.Machine),
            "timestamp": int(pe.FILE_HEADER.TimeDateStamp),
            "sections": len(pe.sections),
        }
    except Exception:
        return None
