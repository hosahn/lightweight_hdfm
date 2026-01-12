# ============================================================================
# infrastructure/clients/threat_intel_client.py - ADAPTER
# ============================================================================
import requests
import logging
from typing import Set

from core.interface import IThreatIntelligence


class ThreatIntelClient (IThreatIntelligence):

    # API Endpoints
    EPSS_API_URL = "https://api.first.org/data/v1/epss"
    CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

    def __init__(self):
        self.logger = logging.getLogger(__name__)
        # Cache for KEV CVE IDs for O(1) lookups
        self.kev_cache: Set[str] = set()
        
        # Initialize KEV data on startup
        self.sync_data()

    def get_epss_score(self, cve_id: str) -> float:
        """
        Fetches the EPSS probability score from FIRST.org API.
        Returns 0.0 if not found or on error.
        """
        try:
            # Define parameters
            params = {'cve': cve_id}
            
            # Make the request (timeout is important for external calls)
            response = requests.get(self.EPSS_API_URL, params=params, timeout=5)
            response.raise_for_status()
            
            data = response.json()
            
            # API Response structure: 
            # { "status": "OK", "data": [{ "cve": "...", "epss": "0.95", ... }] }
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
        """
        try:
            self.logger.info("Syncing CISA KEV data...")
            response = requests.get(self.CISA_KEV_URL, timeout=10)
            response.raise_for_status()
            
            data = response.json()
            
            # Create a new set to store IDs
            new_cache = set()
            
            # Parse CISA JSON structure
            vulnerabilities = data.get('vulnerabilities', [])
            for vuln in vulnerabilities:
                cve = vuln.get('cveID')
                if cve:
                    new_cache.add(cve)
            
            # Update the class cache
            self.kev_cache = new_cache
            self.logger.info(f"CISA KEV synced. Loaded {len(self.kev_cache)} vulnerabilities.")

        except requests.RequestException as e:
            self.logger.error(f"Failed to sync CISA KEV data: {e}")
            # Note: We do NOT clear the cache on failure; we keep the stale data 
            # so the app continues to function.