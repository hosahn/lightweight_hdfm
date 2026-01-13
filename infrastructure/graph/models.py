from sqlalchemy import Column, String, Integer, Float, Boolean, Text, DateTime, ForeignKey
from sqlalchemy.orm import relationship
from infrastructure.persistence.database import Base  

# 또는 database.py가 없다면:
# from sqlalchemy.orm import declarative_base
# Base = declarative_base()


class SBOMModel(Base):
    """ORM model for SBOM storage"""
    __tablename__ = 'sboms'
    
    id = Column(String, primary_key=True)
    name = Column(String)
    version = Column(String)
    source = Column(String)
    raw_data = Column(Text)
    created_at = Column(DateTime)
    updated_at = Column(DateTime)
    
    analyses = relationship("AnalysisModel", back_populates="sbom", cascade="all, delete-orphan")


class AnalysisModel(Base):
    """ORM model for analysis results"""
    __tablename__ = 'analyses'
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    sbom_id = Column(String, ForeignKey('sboms.id'))
    timestamp = Column(DateTime)
    total_components = Column(Integer)
    total_vulnerabilities = Column(Integer)
    critical_findings = Column(Integer)
    hub_components = Column(Integer)
    max_depth = Column(Integer)
    entropy_weights = Column(Text)
    
    sbom = relationship("SBOMModel", back_populates="analyses")
    vulnerabilities = relationship("VulnerabilityModel", back_populates="analysis", cascade="all, delete-orphan")


class VulnerabilityModel(Base):
    """ORM model for vulnerability findings"""
    __tablename__ = 'vulnerabilities'
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    analysis_id = Column(Integer, ForeignKey('analyses.id'))
    cve_id = Column(String)
    component_ref = Column(String)
    component_name = Column(String)
    cvss_score = Column(Float)
    cvss_vector = Column(String)
    description = Column(Text)
    severity = Column(Float)
    tcs = Column(Float)
    vei = Column(Float)
    epss = Column(Float)
    kev = Column(Boolean)
    exploitability = Column(Float)
    hdfm_score = Column(Float)
    priority = Column(String)
    
    analysis = relationship("AnalysisModel", back_populates="vulnerabilities")