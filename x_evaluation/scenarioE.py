import json
import uuid
from datetime import datetime

FILENAME = "TC05_VexFiltered.json"

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
                "name": "Production-App-Scenario-E",
                "version": "1.0.0",
                "bom-ref": "root-app"
            }
        },
        "components": [],
        "dependencies": [],
        # This block is for HDFM / Classic Eval parsing
        "vulnerabilities": {}
    }

def create_component(group, name, version):
    if group:
        purl = f"pkg:{group}/{name}@{version}"
        full_name = f"{group}/{name}"
    else:
        # Defaulting to golang for this scenario
        purl = f"pkg:golang/{name}@{version}"
        full_name = name
        
    return {
        "type": "library",
        "name": full_name,
        "version": version,
        "bom-ref": purl,
        "purl": purl
    }

def generate_scenario_E_real():
    sbom = create_base_sbom()
    root_ref = "root-app"
    deps_map = {root_ref: []}

    # 1. The "False Positive" Target Component
    # High profile lib, often flagged but not always used dangerously
    target_comp = create_component("golang", "crypto", "1.0.0")
    sbom['components'].append(target_comp)
    deps_map[root_ref].append(target_comp['bom-ref'])
    deps_map[target_comp['bom-ref']] = []

    # 2. Add "Noise" (Safe/Standard Libraries)
    # This makes the project look real, ensuring the algo has to FILTER the bad one.
    safe_libs = [
        ("github.com/gin-gonic", "gin", "1.9.1"),
        ("github.com/sirupsen", "logrus", "1.9.3"),
        ("github.com/spf13", "viper", "1.16.0"),
        ("github.com/stretchr", "testify", "1.8.4"),
        ("golang.org/x", "net", "0.17.0"),
        ("golang.org/x", "sys", "0.13.0"),
        ("golang.org/x", "text", "0.13.0"),
        ("gopkg.in", "yaml.v3", "3.0.1"),
        ("github.com/google", "uuid", "1.3.1"),
        ("github.com/pkg", "errors", "0.9.1")
    ]

    for group, name, version in safe_libs:
        # Construct proper Go PURL format
        # e.g., pkg:golang/github.com/gin-gonic/gin@1.9.1
        full_name = f"{group}/{name}"
        comp = create_component("golang", full_name, version)
        
        sbom['components'].append(comp)
        
        # Link Root -> Lib (Direct dependency noise)
        deps_map[root_ref].append(comp['bom-ref'])
        deps_map[comp['bom-ref']] = []

    # 3. Construct Dependencies Array
    for parent, children in deps_map.items():
        sbom['dependencies'].append({"ref": parent, "dependsOn": children})

    # 4. Inject the Mock Vulnerability
    # SCENARIO: Critical Metrics, but VEX says "No".
    vuln_id = "CVE-2023-FALSE-ALARM"
    
    sbom["vulnerabilities"][vuln_id] = {
        "package_id": target_comp['bom-ref'],
        
        # Threat Data: Looks terrifying (10.0 Critical, KEV=True)
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
        "base_score": 10.0,
        "epss": 0.99,
        "kev": True,
        
        # --- THE KEY FACTOR ---
        # The VEX status should force HDFM to discard this immediately
        "vex_status": "not_affected",
        "status_justification": "vulnerable_code_not_in_execute_path"
    }

    return sbom

# --- EXECUTE ---
if __name__ == "__main__":
    data = generate_scenario_E_real()
    with open(FILENAME, "w") as f:
        json.dump(data, f, indent=2)
    print(f"Generated {FILENAME}")
    print("Scenario: Critical Vulnerability (CVE-2023-FALSE-ALARM) with VEX status 'not_affected'.")
    print("Context: Embedded among 10 safe Golang libraries.")