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

    c1 = create_component(None, "internal-analytics", "1.0.0")
    sbom['components'].append(c1)
    deps_map[root_ref].append(c1['bom-ref'])

    c2 = create_component(None, "report-generator", "2.5.0")
    sbom['components'].append(c2)
    deps_map[c1['bom-ref']] = [c2['bom-ref']]
    
    c3 = create_component("Django", "django", "3.2.0")
    sbom['components'].append(c3)
    deps_map[c2['bom-ref']] = [c3['bom-ref']]
    deps_map[c3['bom-ref']] = [] # Leaf node

    
    safe_libs = [
        ("express", "4.18.2"), 
        ("lodash", "4.17.21"), 
        ("axios", "1.6.0"),    
        ("chalk", "4.1.2"),    
        ("debug", "4.3.4"),    
        ("commander", "9.4.1"),
        ("uuid", "9.0.0"),     
        ("rxjs", "7.8.0"),     
        ("tslib", "2.5.0"),    
        ("zone.js", "0.13.0")  
    ]

    for name, version in safe_libs:
        comp = create_component(None, name, version)
        sbom['components'].append(comp)

        deps_map[root_ref].append(comp['bom-ref'])
        deps_map[comp['bom-ref']] = []

    for parent, children in deps_map.items():
        sbom['dependencies'].append({"ref": parent, "dependsOn": children})

    return sbom

# --- EXECUTE ---
data = generate_scenario_A_real()
with open(FILENAME, "w") as f:
    json.dump(data, f, indent=2)
print(f"Generated {FILENAME}")
print("Contains 'django@3.2.0' (Real CVSS 10.0) nested 3 levels deep.")