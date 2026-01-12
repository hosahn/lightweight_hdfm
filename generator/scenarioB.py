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
        # Default to PyPI for this python-centric example
        purl = f"pkg:pypi/{name}@{version}"
        full_name = name
        
    return {
        "type": type,
        "name": full_name,
        "version": version,
        "scope": scope,  # <--- HDFM uses this to demote/promote
        "bom-ref": purl,
        "purl": purl
    }

def generate_scenario_B():
    sbom = create_base_sbom()
    root_ref = "root-app"
    deps_map = {root_ref: []}

    # --- 1. THE FALSE PANIC (VM2 - CVSS 10.0) ---
    # Real World Context: A testing tool uses 'vm2' to sandbox code during tests.
    # It is NOT in the production build.
    
    # Parent: Mocha (Test Runner) - Scope: Excluded
    mocha = create_component("mocha", "10.2.0", scope="excluded", type="library")
    # Child: VM2 (Vulnerable) - Scope: Excluded (Inherited conceptually)
    vm2 = create_component("vm2", "3.9.17", scope="excluded", type="library")
    
    sbom['components'].extend([mocha, vm2])
    
    # Topology: Root -> Mocha -> VM2
    deps_map[root_ref].append(mocha['bom-ref'])
    deps_map[mocha['bom-ref']] = [vm2['bom-ref']]
    deps_map[vm2['bom-ref']] = []

    # --- 2. THE SILENT KILLER (Requests - CVSS 6.1) ---
    # Real World Context: The main app uses 'requests' to talk to APIs.
    # CVE-2023-32681 leaks credentials. This is HIGH risk for this app.
    
    # Direct Dependency - Scope: Required
    requests_lib = create_component("requests", "2.29.0", scope="required")
    
    sbom['components'].append(requests_lib)
    
    # Topology: Root -> Requests (Direct)
    deps_map[root_ref].append(requests_lib['bom-ref'])
    deps_map[requests_lib['bom-ref']] = []

    # --- 3. THE NOISE (Healthy Production Libs) ---
    # Add standard Flask stack to make it look like a real web app
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

    # Build Dependencies Block
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