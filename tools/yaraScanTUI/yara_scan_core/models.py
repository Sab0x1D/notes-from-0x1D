from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Dict, Any, Optional
from datetime import datetime

@dataclass
class SampleInfo:
    path: Path
    size: int
    sha256: str
    sha1: str
    md5: str
    mime: Optional[str] = None
    pe: Optional[Dict[str, Any]] = None

@dataclass
class MatchString:
    identifier: str
    offset: int
    data_preview: str

@dataclass
class RuleMatch:
    rule: str
    namespace: str
    tags: List[str]
    meta: Dict[str, Any]
    strings: List[MatchString]

@dataclass
class ScanResult:
    matches: List[RuleMatch] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    started_at: datetime = field(default_factory=datetime.utcnow)
    finished_at: Optional[datetime] = None
    duration_ms: Optional[int] = None
    rules_digest: Optional[str] = None

@dataclass
class RuleStatus:
    compiled: bool
    count: int
    digest: str
    errors: List[str] = field(default_factory=list)
