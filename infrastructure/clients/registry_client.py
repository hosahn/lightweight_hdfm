import requests
import logging
from typing import List, Dict, Optional
from datetime import datetime
from urllib.parse import quote_plus

from core.entities import Component
from core.interface import IMetadataProvider

class DepsDevClient(IMetadataProvider):
    """
    Adapter: Google Deps.dev API for component metadata
    """
    BASE_URL = "https://api.deps.dev/v3alpha"
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)

    def get_metadata(self, components: List[Component]) -> Dict[str, Dict]:
        """Fetch deprecation and timestamp data"""
        results = {}
        
        # Deps.dev doesn't support batching well, so we do individual lookups.
        # In prod, use asyncio/aiohttp. For this MVP, we use sequential requests.
        for comp in components:
            if not comp.purl:
                continue
                
            system, name, version = self._parse_purl(comp.purl)
            if not system or not name or not version:
                continue

            try:
                # URL Encode parts (important for scoped packages like @angular/core)
                safe_name = quote_plus(name)
                url = f"{self.BASE_URL}/systems/{system}/packages/{safe_name}/versions/{version}"
                
                response = requests.get(url, timeout=2)
                
                if response.status_code == 200:
                    data = response.json()
                    
                    # ✅ PARSING LOGIC
                    # 1. Published Date
                    published_str = data.get('publishedAt')
                    published_at = None
                    if published_str:
                        # Format: 2020-10-01T12:00:00Z
                        try:
                            published_at = datetime.fromisoformat(published_str.replace('Z', '+00:00'))
                        except ValueError:
                            pass

                    # 2. Deprecated Status
                    # Deps.dev often puts this in the version info or advisory list
                    is_deprecated = data.get('isDeprecated', False)
                    
                    results[comp.bom_ref] = {
                        'published_at': published_at,
                        'is_deprecated': is_deprecated
                    }
                    
            except Exception as e:
                self.logger.error(f"Error fetching metadata for {comp.name}: {e}")
                
        return results

    def _parse_purl(self, purl: str) -> tuple[Optional[str], Optional[str], Optional[str]]:
        """
        Extract system, name, version from PURL.
        Example: pkg:npm/axios@0.21.1 -> ('npm', 'axios', '0.21.1')
        """
        try:
            # Simple heuristic parser
            if not purl.startswith('pkg:'): return None, None, None
            
            parts = purl[4:].split('/', 1)
            type_part = parts[0]  # 'npm'
            rest = parts[1]       # 'axios@0.21.1' or '@scope/pkg@1.0'
            
            # Map PURL type to Deps.dev system
            system_map = {
                'npm': 'npm',
                'pypi': 'pypi',
                'maven': 'maven',
                'go': 'go',
                'cargo': 'cargo',
                'nuget': 'nuget'
            }
            system = system_map.get(type_part)
            if not system: return None, None, None

            if '@' in rest:
                # Handle scoped packages vs version separator
                # Last @ is usually version
                name_part, version_part = rest.rsplit('@', 1)
            else:
                return None, None, None
                
            return system, name_part, version_part
            
        except Exception:
            return None, None, None