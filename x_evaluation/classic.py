import json
import requests
import logging
import csv
import sys
import time
from dataclasses import dataclass, field
from typing import Optional, Dict, List, Set

# --- CONFIGURATION ---
logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')
logger = logging.getLogger("ClassicEval")

# --- 1. CORE ENTITIES ---

@dataclass
class Component:
    name: str
    version: str
    bom_ref: str
    purl: Optional[str] = None

@dataclass
class Vulnerability:
    id: str              # The main ID (Preferred: CVE)
    original_id: str     # The ID we found first (e.g., GHSA)
    component_ref: str
    component_name: str
    cvss_score: float
    cvss_vector: str
    epss_score: float = 0.0
    description: str = ""
    severity: float = 0.0 # Normalized 0-1 (Impact/10)

# --- 2. THREAT INTEL CLIENT ---

class ThreatIntelClient:
    EPSS_API_URL = "https://api.first.org/data/v1/epss"

    def __init__(self):
        self.logger = logging.getLogger("ThreatIntel")
        self._epss_cache: Dict[str, float] = {}

    def prefetch_epss(self, cve_ids: List[str]):
        """
        Batch fetch EPSS scores from FIRST.org.
        Only queries CVEs that are NOT already in the cache.
        """
        # Filter: Must be CVE, and not already cached (e.g. from Mock data)
        to_fetch = list(set([c for c in cve_ids if c.startswith("CVE-") and c not in self._epss_cache]))
        
        if not to_fetch:
            return

        self.logger.info(f"Batch fetching EPSS for {len(to_fetch)} CVEs...")
        
        chunk_size = 30
        for i in range(0, len(to_fetch), chunk_size):
            chunk = to_fetch[i:i+chunk_size]
            cve_str = ",".join(chunk)
            try:
                response = requests.get(f"{self.EPSS_API_URL}?cve={cve_str}", timeout=10)
                if response.status_code == 200:
                    data = response.json().get("data", [])
                    for entry in data:
                        cve = entry.get("cve")
                        score = float(entry.get("epss", 0.0))
                        self._epss_cache[cve] = score
            except Exception as e:
                self.logger.error(f"EPSS Batch failed: {e}")
            time.sleep(0.1)

    def get_epss_score(self, cve_id: str) -> float:
        return self._epss_cache.get(cve_id, 0.0)
        
    def manual_cache_entry(self, cve_id: str, score: float):
        """Allows injecting mock EPSS scores directly"""
        self._epss_cache[cve_id] = score

# --- 3. OSV LOOKUP CLASS ---

class OSVVulnerabilityLookup:
    
    def __init__(self, base_url: str = "https://api.osv.dev/v1"):
        self.base_url = base_url
        self.cache = {}
        self.logger = logging.getLogger("OSVLookup")
    
    def lookup_vulnerability(self, vuln_id: str) -> Optional[Dict]:
        if vuln_id in self.cache: return self.cache[vuln_id]
        try:
            response = requests.get(f"{self.base_url}/vulns/{vuln_id}", timeout=10)
            if response.status_code == 200:
                data = response.json()
                self.cache[vuln_id] = data
                return data
        except Exception:
            pass
        return None
    
    def batch_lookup_by_purl(self, components: List[Component]) -> Dict[str, List[Vulnerability]]:
        queries = []
        # Use ONE consistent map
        global_comp_map = {} 
        
        for comp in components:
            purl = self._construct_purl(comp)
            if purl:
                # Map the index in the 'queries' list to the actual component object
                global_comp_map[len(queries)] = comp
                queries.append({"package": {"purl": purl}})
            else:
                self.logger.warning(f"Skipping {comp.name}@{comp.version}: No PURL found.")
        
        if not queries: return {}
        
        self.logger.info(f"Querying OSV for {len(queries)} components...")
        all_results = {}
        chunk_size = 500
        
        for i in range(0, len(queries), chunk_size):
            chunk = queries[i:i+chunk_size]
            try:
                resp = requests.post(f"{self.base_url}/querybatch", json={"queries": chunk}, timeout=30)
                if resp.status_code != 200: continue
                
                batch_results = resp.json().get('results', [])
                
                for idx, result in enumerate(batch_results):
                    # Use the correct map and correct global index
                    global_idx = i + idx
                    comp = global_comp_map.get(global_idx)
                    
                    if not comp: continue
                    
                    raw_vulns = result.get('vulns', [])
                    hydrated_vulns = []
                    
                    for v in raw_vulns:
                        v_id = v.get('id', '')
                        # Fetch full data to get CVSS and Aliases
                        full_record = self.lookup_vulnerability(v_id)
                        
                        # Use _to_vuln_obj to convert the JSON into your class instance
                        if full_record:
                            hydrated_vulns.append(self._to_vuln_obj(full_record, comp))
                        else:
                            hydrated_vulns.append(self._to_vuln_obj(v, comp))
                    
                    if hydrated_vulns:
                        # Deduplicate based on ID (CVE prioritized in _to_vuln_obj)
                        deduped = self._deduplicate(hydrated_vulns)
                        # Ensure key is unique to prevent overwriting
                        key = comp.bom_ref if comp.bom_ref else f"{comp.name}@{comp.version}"
                        all_results[key] = deduped
                            
            except Exception as e:
                self.logger.error(f"OSV Batch Error: {e}")
        
        return all_results

    def _deduplicate(self, vulns: List[Vulnerability]) -> List[Vulnerability]:
        unique = {}
        for v in vulns:
            if v.id not in unique:
                unique[v.id] = v
        return list(unique.values())

    def _to_vuln_obj(self, data: Dict, comp: Component) -> Vulnerability:
        original_id = data.get("id", "UNKNOWN")
        vid = original_id
        aliases = data.get("aliases", [])
        
        cve = next((x for x in aliases if x.startswith("CVE-")), None)
        if cve: vid = cve
        
        score = 0.0
        vector = ""
        
        if "severity" in data:
            for s in data["severity"]:
                if s.get("type") in ["CVSS_V3", "CVSS_V3.1"]:
                    vector = s.get("score", "")
                    score = self._parse_vector(vector)
                    break
        
        if score == 0.0:
            sev = data.get("database_specific", {}).get("severity", "").upper()
            severity_map = {"CRITICAL": 9.5, "HIGH": 7.5, "MODERATE": 5.0, "LOW": 2.5}
            score = severity_map.get(sev, 0.0)
            
        return Vulnerability(
            id=vid, original_id=original_id, component_ref=comp.bom_ref,
            component_name=comp.name, cvss_score=score, cvss_vector=vector,
            severity=score/10.0
        )

    def _parse_vector(self, vector: str) -> float:
        if not vector: return 0.0
        val = 0.0
        if "AV:N" in vector: val = 8.0
        elif "AV:A" in vector: val = 6.0
        elif "AV:L" in vector: val = 4.0
        elif "AV:P" in vector: val = 2.0
        if "C:H" in vector: val += 0.7
        if "I:H" in vector: val += 0.7
        if "A:H" in vector: val += 0.6
        return min(val, 10.0)

    def _construct_purl(self, comp: Component) -> Optional[str]:
            if comp.purl:
                print(comp.purl)
            if comp.purl: return comp.purl
            
            name = comp.name or ""
            bom_ref = comp.bom_ref or ""
            
            if 'npm' in bom_ref or '@' in name: 
                return f"pkg:npm/{name}@{comp.version}"
            elif 'pypi' in bom_ref or 'python' in bom_ref:
                return f"pkg:pypi/{name}@{comp.version}"
            elif name:
                # Generic fallback: Guess Maven for everything else (Catches Ghidra's Java pkgs)
                return f"pkg:maven/{name}@{comp.version}"
            print(comp.purl)
            return None
    

# --- 4. MOCK DATA PARSER ---

def _extract_mock_vulnerabilities(data: Dict, comps: List[Component]) -> Dict[str, List[Vulnerability]]:
    """
    Parses the custom 'vulnerabilities' dict used in our Test Cases.
    Returns a map of bom_ref -> List[Vulnerability].
    """
    mock_map = {}
    
    # Check if 'vulnerabilities' exists and is a dictionary (Our Test Case Format)
    raw_mocks = data.get("vulnerabilities", {})
    if not isinstance(raw_mocks, dict):
        return {}

    # Quick lookup for component names
    comp_lookup = {c.bom_ref: c.name for c in comps}

    for vuln_id, meta in raw_mocks.items():
        pkg_id = meta.get("package_id")
        if not pkg_id or pkg_id not in comp_lookup:
            continue
            
        # Parse Vector if available to get Score
        vector = meta.get("cvss_vector", "")
        # Use helper from OSV class logic to parse score
        # Or look for 'impact_score' or 'base_score' in mock
        score = meta.get("impact_score") or meta.get("base_score")
        
        if score is None and vector:
            # Quick parse
            helper = OSVVulnerabilityLookup()
            score = helper._parse_vector(vector)
        
        if score is None: score = 0.0
        
        epss = meta.get("epss", 0.0)
        
        v_obj = Vulnerability(
            id=vuln_id,
            original_id=vuln_id,
            component_ref=pkg_id,
            component_name=comp_lookup[pkg_id],
            cvss_score=float(score),
            cvss_vector=vector,
            epss_score=float(epss),
            description="Mock Vulnerability from Test Case",
            severity=float(score)/10.0
        )
        
        if pkg_id not in mock_map:
            mock_map[pkg_id] = []
        mock_map[pkg_id].append(v_obj)
        
    return mock_map

# --- 5. MAIN ---

def run_classic_eval(sbom_path: str, output_csv: str):
    logger.info(f"Loading SBOM: {sbom_path}")
    try:
        with open(sbom_path) as f:
            data = json.load(f)
    except Exception as e:
        logger.error(f"Failed to open SBOM: {e}")
        return

    # 1. Parse Components
    comps = []
    for c in data.get("components", []):
        comps.append(Component(
            name=c.get("name"), 
            version=c.get("version"), 
            bom_ref=c.get("bom-ref"),
            purl=c.get("purl")
        ))
    
    # 2. Extract MOCK Vulnerabilities (Test Case Injection)
    mock_vuln_map = _extract_mock_vulnerabilities(data, comps)
    covered_components = set(mock_vuln_map.keys())
    
    if mock_vuln_map:
        logger.info(f"Found {len(mock_vuln_map)} components with Mock/Pre-filled vulnerabilities.")

    # 3. Identify Components needing OSV lookup (Not in Mock)
    comps_to_query = [c for c in comps if c.bom_ref not in covered_components]
    
    # 4. OSV Lookup (Only for non-mocked)
    osv = OSVVulnerabilityLookup()
    osv_map = osv.batch_lookup_by_purl(comps_to_query)
    
    # 5. Merge Maps
    # Start with mocks, update with OSV results
    full_vuln_map = {**mock_vuln_map, **osv_map}
    
    # 6. EPSS Handling
    ti_client = ThreatIntelClient()
    
    # Populate EPSS Cache with Mock Data first
    for v_list in mock_vuln_map.values():
        for v in v_list:
            if v.epss_score > 0:
                ti_client.manual_cache_entry(v.id, v.epss_score)
                
    # Collect IDs needed for Fetch (those without EPSS yet)
    cves_to_fetch = set()
    for v_list in full_vuln_map.values():
        for v in v_list:
            # If it's a CVE and we don't have a score yet (and it's not in mock cache)
            if v.id.startswith("CVE-") and ti_client.get_epss_score(v.id) == 0.0:
                cves_to_fetch.add(v.id)
    
    if cves_to_fetch:
        ti_client.prefetch_epss(list(cves_to_fetch))
    
    # 7. Calculate, Deduplicate & Sort
    logger.info("Calculating Scores...")
    
    final_rows = [] # Will hold tuples of (score, row_data)

    for comp_ref, vulns in full_vuln_map.items():
        if not vulns: continue
        
        best_vuln_row = None
        highest_score = -1.0
        
        for v in vulns:
            # Get EPSS (From Mock Cache OR API Cache)
            epss = ti_client.get_epss_score(v.id)
            if epss == 0.0 and v.epss_score > 0: # Fallback to object property
                epss = v.epss_score
            
            # CLASSIC FORMULA: 0.5 * Sev + 0.5 * EPSS
            classic_score = (0.5 * v.severity) + (0.5 * epss)
            
            if classic_score >= 0.8: prio = "Critical"
            elif classic_score >= 0.6: prio = "High"
            elif classic_score >= 0.4: prio = "Medium"
            else: prio = "Low"
            
            # Logic: Keep only the highest score for this component
            if classic_score > highest_score:
                highest_score = classic_score
                best_vuln_row = [
                    v.component_name, 
                    v.id, 
                    f"{v.cvss_score:.1f}", 
                    f"{epss:.4f}", 
                    f"{classic_score:.3f}", 
                    prio
                ]
        
        if best_vuln_row:
            final_rows.append((highest_score, best_vuln_row))
    
    # Sort by Score (Descending)
    final_rows.sort(key=lambda x: x[0], reverse=True)
    
    # 8. Write to CSV
    print(f"[*] Writing results to {output_csv}...")
    with open(output_csv, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(["Component", "VulnID", "CVSS_Base", "EPSS_Prob", "Classic_Score", "Priority"])
        
        for score, row in final_rows:
            writer.writerow(row)
                
    logger.info(f"Done. Processed {len(final_rows)} unique components. Results in {output_csv}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python classic_eval_final.py <sbom.json> <output.csv>")
    else:
        run_classic_eval(sys.argv[1], sys.argv[2])