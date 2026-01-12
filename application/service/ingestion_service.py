from datetime import datetime
from typing import Tuple, List, Dict
from core.entities import Component, Vulnerability
from core.interface import IVulnerabilityLookup
from core.exceptions import InvalidSBOMException


class IngestionService:
    
    def __init__(self, vuln_lookup: IVulnerabilityLookup, metadata_provider):
        self.vuln_lookup = vuln_lookup
        self.metadata_provider = metadata_provider
        
    def parse_sbom(self, sbom_data: Dict) -> Tuple[List[Component], List[Dict]]:
        """
        Parse CycloneDX SBOM into domain entities
        Automatically scans for vulnerabilities using OSV.dev PURL lookup
        """
        if not sbom_data.get('components'):
            raise InvalidSBOMException("SBOM must contain components")
        
        components = []
        
        # Step 1: Parse all components first (without vulnerabilities)
        for comp_data in sbom_data.get('components', []):
            bom_ref = comp_data.get('bom-ref') or comp_data.get('purl') or comp_data.get('name')
            
            if not bom_ref:
                continue
            
            component = Component(
                bom_ref=bom_ref,
                name=comp_data.get('name', 'Unknown'),
                version=comp_data.get('version', 'Unknown'),
                purl=comp_data.get('purl')  # This is critical for OSV lookup!
            )
            
            # Check if SBOM already has vulnerabilities (VEX data)
            for vuln_data in comp_data.get('vulnerabilities', []):
                cve_id = vuln_data.get('id', 'UNKNOWN')
                ratings = vuln_data.get('ratings', [])
                cvss_score = ratings[0].get('score', 0) if ratings else 0
                cvss_vector = ratings[0].get('vector', '') if ratings else ''
                
                vulnerability = Vulnerability(
                    id=cve_id,
                    component_ref=bom_ref,
                    component_name=component.name,
                    cvss_score=cvss_score,
                    cvss_vector=cvss_vector,
                    description=vuln_data.get('description', 'No description'),
                    severity=cvss_score / 10.0
                )
                
                component.vulnerabilities.append(vulnerability)
            
            components.append(component)
        
        # Step 2: Batch scan ALL components for vulnerabilities using PURL
        print(f"🔍 Scanning {len(components)} components via OSV.dev PURL lookup...")
        
        if hasattr(self.vuln_lookup, 'batch_lookup_by_purl'):
            # Use the new PURL-based batch lookup
            osv_results = self.vuln_lookup.batch_lookup_by_purl(components)
            
            # Merge OSV results into components
            for comp in components:
                if comp.bom_ref in osv_results:
                    osv_vulns = osv_results[comp.bom_ref]
                    # Only add vulnerabilities not already in SBOM
                    existing_ids = {v.id for v in comp.vulnerabilities}
                    
                    for osv_vuln in osv_vulns:
                        if osv_vuln.id not in existing_ids:
                            comp.vulnerabilities.append(osv_vuln)
            
            total_vulns = sum(len(comp.vulnerabilities) for comp in components)
            affected_comps = len([c for c in components if c.vulnerabilities])
            print(f"Found {total_vulns} vulnerabilities in {affected_comps}/{len(components)} components")
        else:
            # Fallback: Legacy CVE-based lookup (not recommended)
            print("Using legacy CVE lookup - PURL batch lookup not available")
            for comp in components:
                for vuln in comp.vulnerabilities:
                    if vuln.cvss_score == 0 and vuln.id.startswith('CVE-'):
                        osv_data = self.vuln_lookup.lookup_vulnerability(vuln.id)
                        if osv_data:
                            vuln.cvss_score = osv_data.get('cvss_score', 0)
                            vuln.cvss_vector = osv_data.get('cvss_vector', '')
        
        dependencies = sbom_data.get('dependencies', [])
        
        print(f"Checking maintenance status via Deps.dev...")
        metadata_map = self.metadata_provider.get_metadata(components)
        
        for comp in components:
            if comp.bom_ref in metadata_map:
                meta = metadata_map[comp.bom_ref]
                comp.published_at = meta.get('published_at')
                comp.is_deprecated = meta.get('is_deprecated', False)
                
                risk = 0.0
                if comp.is_deprecated:
                    risk += 0.7
                
                if comp.published_at:
                    age_years = (datetime.now(comp.published_at.tzinfo) - comp.published_at).days / 365.0
                    if age_years > 3: risk += 0.3
                    elif age_years > 2: risk += 0.1
                comp.maintenance_risk_score = min(risk, 1.0)
                
        return components, dependencies