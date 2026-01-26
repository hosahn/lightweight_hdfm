import requests
import logging
from typing import Optional, Dict, List, Set
from core.entities import Component, Vulnerability
from core.interface import IVulnerabilityLookup

class OSVVulnerabilityLookup(IVulnerabilityLookup):
    
    def __init__(self, base_url: str = "https://api.osv.dev/v1"):
        self.base_url = base_url
        self.cache = {}
        self.logger = logging.getLogger(__name__)
    
    def lookup_vulnerability(self, vuln_id: str) -> Optional[Dict]:
        """Lookup with OSV.dev by ID (returns FULL details)"""
        if vuln_id in self.cache:
            return self.cache[vuln_id]
        
        try:
            response = requests.get(
                f"{self.base_url}/vulns/{vuln_id}",
                timeout=10
            )
            
            if response.status_code != 200:
                return None
            vuln = response.json()
            self.cache[vuln_id] = vuln
            return vuln
            
        except Exception as e:
            self.logger.error(f"Error looking up {vuln_id}: {e}")
            return None
    
    def batch_lookup(self, cve_ids: List[str]) -> Dict[str, Dict]:
        """Batch lookup multiple CVEs (legacy support)"""
        results = {}
        for cve_id in cve_ids:
            result = self.lookup_vulnerability(cve_id)
            if result:
                results[cve_id] = self._extract_vulnerability_data(result)
        return results
    
    def batch_lookup_by_purl(self, components: List[Component]) -> Dict[str, List[Vulnerability]]:
        """
        Batch lookup vulnerabilities by PURL
        Step 1: Query Batch API to get list of IDs
        Step 2: If details (aliases) are missing, fetch full record individually
        Step 3: Deduplicate and prioritize CVEs
        """
        # Build Query ---
        queries = []
        component_map = {}
        
        for comp in components:
            purl = comp.purl or self._construct_purl_from_component(comp)
            if purl:
                query = {"package": {"purl": purl}}
                queries.append(query)
                component_map[len(queries) - 1] = comp
        
        if not queries:
            return {}
        
        # Process in Chunks ---
        chunk_size = 1000
        all_results = {}
        
        for i in range(0, len(queries), chunk_size):
            chunk = queries[i:i + chunk_size]
            
            try:
                response = requests.post(
                    f"{self.base_url}/querybatch",
                    json={"queries": chunk},
                    timeout=30
                )
                
                if response.status_code != 200:
                    self.logger.error(f"OSV batch query failed: {response.status_code}")
                    continue
                
                batch_results = response.json()
                
                for idx, result in enumerate(batch_results.get('results', [])):
                    global_idx = i + idx
                    comp = component_map.get(global_idx)
                    if not comp: continue
                    
                    raw_vulns = result.get('vulns', [])
                    hydrated_vulns = []
                    
                    # Hydrate Data (The Fix) ---
                    for v in raw_vulns:
                        v_id = v.get('id', '')
                        
                        if not v.get('aliases'):
                            full_record = self.lookup_vulnerability(v_id)
                            if full_record:
                                hydrated_vulns.append(full_record)
                            else:
                                hydrated_vulns.append(v) # Fallback to slim
                        else:
                            hydrated_vulns.append(v)
                    
                    if hydrated_vulns:
                        # Deduplicate & Convert ---
                        comp_vulns = self._deduplicate_vulnerabilities(hydrated_vulns, comp)
                        if comp_vulns:
                            all_results[comp.bom_ref] = comp_vulns
                            
            except Exception as e:
                self.logger.error(f"Error in batch lookup: {e}")
                continue
    
        return all_results

    def _deduplicate_vulnerabilities(self, osv_vulns: List[Dict], comp: Component) -> List[Vulnerability]:
        """Deduplicate and prioritize CVE over GHSA"""
        vuln_groups = {} 
        seen_ids = set()

        for osv_data in osv_vulns:
            vuln_id = osv_data.get('id', 'UNKNOWN')
            aliases = set(osv_data.get('aliases', []))
            
            found_group = None
            
            # Check overlap via ID
            if vuln_id in seen_ids:
                for gid, g_vulns in vuln_groups.items():
                    for v in g_vulns:
                        if v['id'] == vuln_id or vuln_id in v.get('aliases', []):
                            found_group = gid
                            break
                    if found_group: break
            
            # Check overlap via Aliases
            if not found_group:
                for gid, g_vulns in vuln_groups.items():
                    group_ids = set()
                    for v in g_vulns:
                        group_ids.add(v['id'])
                        group_ids.update(v.get('aliases', []))
                    
                    if vuln_id in group_ids or not aliases.isdisjoint(group_ids):
                        found_group = gid
                        break
            
            if found_group:
                vuln_groups[found_group].append(osv_data)
            else:
                vuln_groups[vuln_id] = [osv_data]
            
            seen_ids.add(vuln_id)
            seen_ids.update(aliases)
        
        # Pick winners
        deduplicated = []
        for group_id, group_vulns in vuln_groups.items():
            best_vuln = self._pick_best_vulnerability(group_vulns)
            if best_vuln:
                vuln_entity = self._convert_osv_to_vulnerability(best_vuln, comp)
                deduplicated.append(vuln_entity)
        
        return deduplicated

    def _pick_best_vulnerability(self, osv_group: List[Dict]) -> Dict:
        """Pick the best representative: CVE > GHSA > others"""
        cve_vulns = []
        ghsa_vulns = []
        
        for osv_data in osv_group:
            vuln_id = osv_data.get('id', '')
            if vuln_id.startswith('CVE-'):
                cve_vulns.append(osv_data)
            elif vuln_id.startswith('GHSA-'):
                ghsa_vulns.append(osv_data)
        
        if cve_vulns: return cve_vulns[0]
        if ghsa_vulns: return ghsa_vulns[0]
        return osv_group[0] if osv_group else None
    
    def _construct_purl_from_component(self, comp: Component) -> Optional[str]:
        if comp.bom_ref and comp.bom_ref.startswith('pkg:'):
            return comp.bom_ref
        if 'npm' in comp.bom_ref or '@' in comp.name:
            return f"pkg:npm/{comp.name}@{comp.version}"
        elif 'pypi' in comp.bom_ref or 'python' in comp.bom_ref:
            return f"pkg:pypi/{comp.name}@{comp.version}"
        elif 'maven' in comp.bom_ref or '.' in comp.name:
            return f"pkg:maven/{comp.name}@{comp.version}"
        return None
    
    def _convert_osv_to_vulnerability(self, osv_data: Dict, comp: Component) -> Vulnerability:
        vuln_id = osv_data.get('id', 'UNKNOWN')
        aliases = osv_data.get('aliases', [])
        
        cve_id = next((a for a in aliases if a.startswith('CVE-')), None)
        if cve_id:
            vuln_id = cve_id
        
        # Parse CVSS
        cvss_score = 0.0
        cvss_vector = ""
        
        if 'severity' in osv_data:
            for severity_item in osv_data['severity']:
                sev_type = severity_item.get('type', '').upper()
                if 'CVSS_V3' in sev_type:
                    score_str = severity_item.get('score', '')
                    if score_str.startswith('CVSS:'):
                        cvss_vector = score_str
                        cvss_score = self._parse_cvss_score(score_str)
                    break
        
        if cvss_score == 0.0:
            db_specific = osv_data.get('database_specific', {})
            severity_str = db_specific.get('severity', '').upper()
            severity_map = {'CRITICAL': 9.5, 'HIGH': 7.5, 'MODERATE': 5.0, 'MEDIUM': 5.0, 'LOW': 2.5}
            if severity_str in severity_map:
                cvss_score = severity_map[severity_str]
        
        summary = osv_data.get('summary', '')
        details = osv_data.get('details', '')
        description = summary or details or 'No description available'
        
        return Vulnerability(
            id=vuln_id,
            component_ref=comp.bom_ref,
            component_name=comp.name,
            cvss_score=cvss_score,
            cvss_vector=cvss_vector,
            description=description[:500],
            severity=cvss_score / 10.0
        )

    def _parse_cvss_score(self, cvss_vector: str) -> float:
        if not cvss_vector: return 0.0
        risk_score = 0.0
        if 'AV:N' in cvss_vector: risk_score += 3.0
        elif 'AV:A' in cvss_vector: risk_score += 2.0
        elif 'AV:L' in cvss_vector: risk_score += 1.0
        if 'AC:L' in cvss_vector: risk_score += 2.0
        if 'PR:N' in cvss_vector: risk_score += 2.0
        if 'C:H' in cvss_vector: risk_score += 1.0
        if 'I:H' in cvss_vector: risk_score += 1.0
        if 'A:H' in cvss_vector: risk_score += 1.0
        return min(risk_score, 10.0)

    def _extract_vulnerability_data(self, vuln: Dict) -> Dict:
        """Legacy helper"""
        return {
            'cvss_score': 0.0,
            'summary': vuln.get('summary', ''),
            'details': vuln.get('details', '')
        }