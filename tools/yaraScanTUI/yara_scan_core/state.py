from dataclasses import dataclass
from typing import Optional
from .models import SampleInfo, ScanResult, RuleStatus

@dataclass
class AppState:
    profile: str = "full"
    current_sample: Optional[SampleInfo] = None
    last_scan: Optional[ScanResult] = None
    rules: Optional[RuleStatus] = None
