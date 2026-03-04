# ============================================================================
# infrastructure/clients/threat_intel_client.py - ADAPTER
# ============================================================================
import requests
import logging
from typing import Set, Dict, Optional

from core.interface import IThreatIntelligence


class ThreatIntelClient(IThreatIntelligence):

    # API Endpoints
    EPSS_API_URL = "https://api.first.org/data/v1/epss"
    CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

    def __init__(self):
        """
        Args:
            sbom_vulnerabilities: Optional dictionary of mock vulnerabilities from the SBOM.
                                  Used for evaluation test cases to override real API data.
        """
        self.logger = logging.getLogger(__name__)
        # O(1)
        self.kev_cache: Set[str] = set()
        self.sync_data()

    def get_epss_score(self, cve_id: str) -> float:
        """
        Fetches the EPSS probability score.
        Priority: 1. Mock Data (SBOM), 2. FIRST.org API
        """
        # 1. Manual Lookup (Mock Data)
        if cve_id in self.mock_data:
            mock_epss = self.mock_data[cve_id].get("epss")
            if mock_epss is not None:
                return float(mock_epss)

        # 2. API Lookup
        try:
            params = {'cve': cve_id}
            
            response = requests.get(self.EPSS_API_URL, params=params, timeout=5)
            # We don't raise_for_status immediately to handle empty data gracefully
            if response.status_code != 200:
                return 0.0
            
            data = response.json()
            
            if data.get('data') and len(data['data']) > 0:
                return float(data['data'][0].get('epss', 0.0))
            
            return 0.0

        except requests.RequestException as e:
            self.logger.error(f"Error fetching EPSS for {cve_id}: {e}")
            return 0.0

    def is_kev(self, cve_id: str) -> bool:
        """
        Checks if the CVE exists in the locally cached CISA KEV list.
        """
        return cve_id in self.kev_cache

    def sync_data(self) -> None:
        """
        Downloads the CISA KEV catalog and refreshes the local cache.
        Also merges in any manual KEV entries from the SBOM mock data.
        """
        new_cache = set()

        # 1. Download Real Data
        try:
            self.logger.info("Syncing CISA KEV data...")
            response = requests.get(self.CISA_KEV_URL, timeout=10)
            if response.status_code == 200:
                data = response.json()
                vulnerabilities = data.get('vulnerabilities', [])
                for vuln in vulnerabilities:
                    cve = vuln.get('cveID')
                    if cve:
                        new_cache.add(cve)
                self.logger.info(f"CISA KEV synced. Loaded {len(new_cache)} vulnerabilities from feed.")
            else:
                self.logger.error(f"Failed to sync CISA KEV: {response.status_code}")

        except requests.RequestException as e:
            self.logger.error(f"Failed to sync CISA KEV data: {e}")

        # 2. Manual Lookup (Merge Mock Data)
        # If our test case says "kev": true, we force it into the cache.
        mock_count = 0
        for cve_id, meta in self.mock_data.items():
            if meta.get('kev') is True:
                new_cache.add(cve_id)
                mock_count += 1
        
        if mock_count > 0:
            self.logger.info(f"Injected {mock_count} mock KEV entries from SBOM.")

        self.kev_cache = new_cache