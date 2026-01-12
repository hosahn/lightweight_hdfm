from dataclasses import dataclass, field
from typing import List, Dict, Optional
from datetime import datetime
from enum import Enum


class Priority(Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


@dataclass
class Component:
    """Domain entity representing a software component"""
    bom_ref: str
    name: str
    version: str
    purl: Optional[str] = None
    vulnerabilities: List['Vulnerability'] = field(default_factory=list)
    published_at: Optional[datetime] = None
    is_deprecated: bool = False
    maintenance_risk_score: float = 0.0  # 0.0 (New) to 1.0 (Obsolete)
    def __hash__(self):
        return hash(self.bom_ref)


@dataclass
class Vulnerability:
    """Domain entity representing a vulnerability"""
    id: str
    component_ref: str
    component_name: str
    cvss_score: float
    cvss_vector: str
    description: str
    
    # HDFM Metrics
    severity: float = 0.0
    tcs: float = 0.0
    vei: float = 0.0
    epss: float = 0.0
    kev: bool = False
    exploitability: float = 0.0
    
    hdfm_score: float = 0.0
    priority: Priority = Priority.LOW
    
    def __hash__(self):
        return hash(self.id)
    def __post_init__(self):
        """
        Force conversion of numeric fields to floats/bools 
        to handle data coming in as strings (e.g. from JSON/CSV).
        """
        # Convert floats
        float_fields = [
            'cvss_score', 'severity', 'tcs', 'vei', 
            'epss', 'exploitability', 'hdfm_score'
        ]
        
        for field_name in float_fields:
            value = getattr(self, field_name)
            if isinstance(value, str):
                try:
                    # Convert to float
                    setattr(self, field_name, float(value))
                except ValueError:
                    # Handle empty strings or bad data by defaulting to 0.0
                    setattr(self, field_name, 0.0)

        # Convert bools (special handling usually required for strings like "false")
        if isinstance(self.kev, str):
            self.kev = self.kev.lower() in ('true', '1', 't', 'yes')

@dataclass
class AnalysisResult:
    """Aggregate root for analysis results"""
    sbom_id: str
    timestamp: datetime
    total_components: int
    total_vulnerabilities: int
    critical_findings: int
    hub_components: int
    max_depth: int
    vulnerabilities: List[Vulnerability]
    entropy_weights: Dict[str, float]
