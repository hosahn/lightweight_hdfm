from dataclasses import dataclass
from typing import Dict, List, Optional


@dataclass
class VulnerabilityDTO:
    """DTO for vulnerability output"""
    id: str
    component: str
    cvss_score: float
    hdfm_score: float
    priority: str
    tcs: float
    epss: float
    kev: bool
    description: str

@dataclass
class AnalysisResultDTO:
    """DTO for analysis result output"""
    sbom_id: str
    timestamp: str
    total_components: int
    total_vulnerabilities: int
    critical_findings: int
    hub_components: int
    max_depth: int
    vulnerabilities: List[VulnerabilityDTO]
    entropy_weights: Dict[str, float]