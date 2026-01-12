from abc import ABC, abstractmethod
from typing import List, Dict, Tuple, Optional

from core.entities import AnalysisResult, Component


class IGraphAnalyzer(ABC):
    """Port: Graph topology analysis"""
    
    @abstractmethod
    def calculate_tcs(self, components: List[Component], 
                     dependencies: List[Dict]) -> Dict[str, float]:
        pass
    
    @abstractmethod
    def calculate_max_depth(self, dependencies: List[Dict]) -> int:
        pass


class IThreatIntelligence(ABC):
    """Port: External threat intelligence sources"""
    
    @abstractmethod
    def get_epss_score(self, cve_id: str) -> float:
        pass
    
    @abstractmethod
    def is_kev(self, cve_id: str) -> bool:
        pass
    
    @abstractmethod
    def sync_data(self) -> None:
        pass


class IVulnerabilityLookup(ABC):
    """Port: Vulnerability database lookup"""
    
    @abstractmethod
    def lookup_vulnerability(self, cve_id: str) -> Optional[Dict]:
        pass
    
    @abstractmethod
    def batch_lookup(self, cve_ids: List[str]) -> Dict[str, Dict]:
        pass

class IMetadataProvider(ABC):
    """Port: External component metadata registry (e.g., Deps.dev, Libraries.io)"""
    
    @abstractmethod
    def get_metadata(self, components: List[Component]) -> Dict[str, Dict]:
        """
        Returns metadata for a list of components.
        Key: bom_ref
        Value: {'published_at': datetime, 'is_deprecated': bool}
        """
        pass
    
class IRepository(ABC):
    """Port: Data persistence"""
    
    @abstractmethod
    def save_sbom(self, sbom_data: Dict, source: str) -> str:
        pass
    
    @abstractmethod
    def get_sbom(self, sbom_id: str) -> Optional[Dict]:
        pass
    
    @abstractmethod
    def list_sboms(self, limit: int = 10) -> List[Dict]:
        pass
    
    @abstractmethod
    def save_analysis(self, sbom_id: str, result: AnalysisResult) -> None:
        pass
    
    @abstractmethod
    def get_latest_analysis(self, sbom_id: str) -> Optional[AnalysisResult]:
        pass
    
    @abstractmethod
    def get_all_analyses(self, sbom_id: str) -> List[AnalysisResult]:
        pass
