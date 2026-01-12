import json
import uuid
from datetime import datetime

FILENAME = "sbom_scenario_A_realworld.json"

def create_base_sbom():
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.4",
        "serialNumber": f"urn:uuid:{str(uuid.uuid4())}",
        "version": 1,
        "metadata": {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "component": {
                "type": "application",
                "name": "Production-App-Scenario-A",
                "version": "2.0.0",
                "bom-ref": "root-app"
            }
        },
        "components": [],
        "dependencies": []
    }

def create_component(group, name, version, type="library"):
    if group:
        purl = f"pkg:pypi/{name}@{version}" # Simplified PURL for OSV
        full_name = name
    else:
        purl = f"pkg:npm/{name}@{version}"
        full_name = name
        
    return {
        "type": type,
        "name": full_name,
        "version": version,
        "bom-ref": purl,
        "purl": purl
    }

def generate_scenario_A_real():
    sbom = create_base_sbom()
    root_ref = "root-app"
    deps_map = {root_ref: []}

    # --- 1. THE "REAL" FALSE ALARM CHAIN ---
    # We bury a real, critical vulnerability deep in the graph.
    # Chain: Root -> internal-analytics -> report-generator -> Django 3.2.0
    
    # Layer 1: Internal Tool (Safe)
    c1 = create_component(None, "internal-analytics", "1.0.0")
    sbom['components'].append(c1)
    deps_map[root_ref].append(c1['bom-ref'])
    
    # Layer 2: Utility (Safe)
    c2 = create_component(None, "report-generator", "2.5.0")
    sbom['components'].append(c2)
    deps_map[c1['bom-ref']] = [c2['bom-ref']]
    
    # Layer 3: THE VULNERABLE LIB (Django 3.2.0)
    # OSV will find CVE-2022-28346 (CVSS 10.0) here.
    c3 = create_component("Django", "django", "3.2.0")
    sbom['components'].append(c3)
    deps_map[c2['bom-ref']] = [c3['bom-ref']]
    deps_map[c3['bom-ref']] = [] # Leaf node

    # --- 2. THE NOISE (Real, Healthy Components) ---
    # These distractors ensure the algorithm isn't just flagging everything.
    # We use common, modern versions that OSV will likely mark as clean.
    
    safe_libs = [
        ("express", "4.18.2"), # Clean
        ("lodash", "4.17.21"), # Clean
        ("axios", "1.6.0"),    # Clean
        ("chalk", "4.1.2"),    # Clean
        ("debug", "4.3.4"),    # Clean
        ("commander", "9.4.1"),# Clean
        ("uuid", "9.0.0"),     # Clean
        ("rxjs", "7.8.0"),     # Clean
        ("tslib", "2.5.0"),    # Clean
        ("zone.js", "0.13.0")  # Clean
    ]

    for name, version in safe_libs:
        comp = create_component(None, name, version)
        sbom['components'].append(comp)
        
        # Connect directly to root (High Visibility, Low Risk)
        deps_map[root_ref].append(comp['bom-ref'])
        deps_map[comp['bom-ref']] = []

    # --- BUILD DEPENDENCIES BLOCK ---
    for parent, children in deps_map.items():
        sbom['dependencies'].append({"ref": parent, "dependsOn": children})

    return sbom

# --- EXECUTE ---
data = generate_scenario_A_real()
with open(FILENAME, "w") as f:
    json.dump(data, f, indent=2)
print(f"Generated {FILENAME}")
print("Contains 'django@3.2.0' (Real CVSS 10.0) nested 3 levels deep.")