import json
from sqlalchemy.orm import Session
from sqlalchemy import select, desc
from typing import Optional, List, Dict
from datetime import datetime

from core.entities import AnalysisResult, Vulnerability, Priority
from core.interface import IRepository


from infrastructure.graph.models import SBOMModel, AnalysisModel, VulnerabilityModel


class SQLAlchemyRepository(IRepository):
    """Adapter: SQLAlchemy-based persistence (SQLAlchemy 2.x compatible)"""
    
    def __init__(self, session: Session):
        self.session = session
    
    def save_sbom(self, sbom_data: Dict, source: str) -> str:
        """Save SBOM to database"""
        sbom_id = f"sbom_{datetime.now().timestamp()}"
        
        sbom = SBOMModel(
            id=sbom_id,
            name=sbom_data.get('metadata', {}).get('component', {}).get('name', 'Unknown'),
            version=sbom_data.get('metadata', {}).get('component', {}).get('version', 'Unknown'),
            source=source,
            raw_data=json.dumps(sbom_data),
            created_at=datetime.now(),
            updated_at=datetime.now()
        )
        
        self.session.add(sbom)
        self.session.commit()
        
        return sbom_id
    
    def get_sbom(self, sbom_id: str) -> Optional[Dict]:
        """Retrieve SBOM from database"""
        # SQLAlchemy 2.x style
        stmt = select(SBOMModel).where(SBOMModel.id == sbom_id)
        sbom = self.session.execute(stmt).scalar_one_or_none()
        
        if not sbom:
            return None
        
        return {
            'id': sbom.id,
            'name': sbom.name,
            'version': sbom.version,
            'source': sbom.source,
            'data': json.loads(sbom.raw_data),
            'created_at': sbom.created_at.isoformat(),
            'updated_at': sbom.updated_at.isoformat()
        }
    
    def list_sboms(self, limit: int = 10) -> List[Dict]:
        """List recent SBOMs"""
        # SQLAlchemy 2.x style
        stmt = select(SBOMModel).order_by(desc(SBOMModel.created_at)).limit(limit)
        sboms = self.session.execute(stmt).scalars().all()
        
        return [{
            'id': s.id,
            'name': s.name,
            'version': s.version,
            'source': s.source,
            'created_at': s.created_at.isoformat()
        } for s in sboms]
    
    def save_analysis(self, sbom_id: str, result: AnalysisResult) -> None:
        """Save analysis result to database"""
        analysis = AnalysisModel(
            sbom_id=sbom_id,
            timestamp=result.timestamp,
            total_components=result.total_components,
            total_vulnerabilities=result.total_vulnerabilities,
            critical_findings=result.critical_findings,
            hub_components=result.hub_components,
            max_depth=result.max_depth,
            entropy_weights=json.dumps(result.entropy_weights)
        )
        
        self.session.add(analysis)
        self.session.flush()  # Get analysis.id
        
        # Save vulnerabilities
        for vuln in result.vulnerabilities:
            vuln_model = VulnerabilityModel(
                analysis_id=analysis.id,
                cve_id=vuln.id,
                component_ref=vuln.component_ref,
                component_name=vuln.component_name,
                cvss_score=vuln.cvss_score,
                cvss_vector=vuln.cvss_vector,
                description=vuln.description,
                severity=vuln.severity,
                tcs=vuln.tcs,
                vei=vuln.vei,
                epss=vuln.epss,
                kev=vuln.kev,
                exploitability=vuln.exploitability,
                hdfm_score=vuln.hdfm_score,
                priority=vuln.priority.value
            )
            self.session.add(vuln_model)
        
        self.session.commit()
    
    def get_latest_analysis(self, sbom_id: str) -> Optional[AnalysisResult]:
        """Get most recent analysis for SBOM"""
        # SQLAlchemy 2.x style
        stmt = (
            select(AnalysisModel)
            .where(AnalysisModel.sbom_id == sbom_id)
            .order_by(desc(AnalysisModel.timestamp))
            .limit(1)
        )
        analysis = self.session.execute(stmt).scalar_one_or_none()
        
        if not analysis:
            return None
        
        return self._convert_to_domain(analysis)
    
    def get_all_analyses(self, sbom_id: str) -> List[AnalysisResult]:
        """Get all analyses for SBOM (for trend analysis)"""
        # SQLAlchemy 2.x style
        stmt = (
            select(AnalysisModel)
            .where(AnalysisModel.sbom_id == sbom_id)
            .order_by(desc(AnalysisModel.timestamp))
        )
        analyses = self.session.execute(stmt).scalars().all()
        
        return [self._convert_to_domain(a) for a in analyses]
    
    def _convert_to_domain(self, analysis: AnalysisModel) -> AnalysisResult:
        """Convert ORM model to domain entity"""
        vulnerabilities = []
        
        for v in analysis.vulnerabilities:
            vuln = Vulnerability(
                id=v.cve_id,
                component_ref=v.component_ref,
                component_name=v.component_name,
                cvss_score=v.cvss_score,
                cvss_vector=v.cvss_vector,
                description=v.description,
                severity=v.severity,
                tcs=v.tcs,
                vei=v.vei,
                epss=v.epss,
                kev=v.kev,
                exploitability=v.exploitability,
                hdfm_score=v.hdfm_score,
                priority=Priority(v.priority)
            )
            vulnerabilities.append(vuln)
        
        return AnalysisResult(
            sbom_id=analysis.sbom_id,
            timestamp=analysis.timestamp,
            total_components=analysis.total_components,
            total_vulnerabilities=analysis.total_vulnerabilities,
            critical_findings=analysis.critical_findings,
            hub_components=analysis.hub_components,
            max_depth=analysis.max_depth,
            vulnerabilities=vulnerabilities,
            entropy_weights=json.loads(analysis.entropy_weights)
        )