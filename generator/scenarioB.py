import json
import uuid
from datetime import datetime

FILENAME = "sbom_scenario_B_real.json"

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
                "name": "Scenario-B-Real-World-App",
                "version": "1.0.0",
                "bom-ref": "root-app"
            }
        },
        "components": [],
        "dependencies": []
    }

def create_component(name, version, scope="required", type="library", group=None):
    if group:
        purl = f"pkg:maven/{group}/{name}@{version}"
        full_name = f"{group}.{name}"
    else:
        purl = f"pkg:pypi/{name}@{version}"
        full_name = name
        
    return {
        "type": type,
        "name": full_name,
        "version": version,
        "scope": scope, 
        "bom-ref": purl,
        "purl": purl
    }

def generate_scenario_B():
    sbom = create_base_sbom()
    root_ref = "root-app"
    deps_map = {root_ref: []}

    mocha = create_component("mocha", "10.2.0", scope="excluded", type="library")
    vm2 = create_component("vm2", "3.9.17", scope="excluded", type="library")
    
    sbom['components'].extend([mocha, vm2])
    
    # Topology: Root -> Mocha -> VM2
    deps_map[root_ref].append(mocha['bom-ref'])
    deps_map[mocha['bom-ref']] = [vm2['bom-ref']]
    deps_map[vm2['bom-ref']] = []


    requests_lib = create_component("requests", "2.29.0", scope="required")
    
    sbom['components'].append(requests_lib)
    
    deps_map[root_ref].append(requests_lib['bom-ref'])
    deps_map[requests_lib['bom-ref']] = []

    prod_stack = [
        ("flask", "2.3.2"),
        ("werkzeug", "2.3.6"),
        ("gunicorn", "20.1.0"),
        ("sqlalchemy", "2.0.15")
    ]
    
    for name, ver in prod_stack:
        c = create_component(name, ver, scope="required")
        sbom['components'].append(c)
        deps_map[root_ref].append(c['bom-ref'])
        deps_map[c['bom-ref']] = []

    for parent, children in deps_map.items():
        sbom['dependencies'].append({"ref": parent, "dependsOn": children})

    return sbom

# --- EXECUTE ---
data = generate_scenario_B()
with open(FILENAME, "w") as f:
    json.dump(data, f, indent=2)

print(f"Generated {FILENAME}")
print("1. 'vm2@3.9.17' (CVSS 10.0): Hidden in test scope (Expected HDFM: Low).")
print("2. 'requests@2.29.0' (CVSS 6.1): Direct production usage (Expected HDFM: High).")