import json
import uuid
from datetime import datetime

FILENAME = "TC09_TieBreaker.json"

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
                "name": "Tie-Breaker-App-Scenario-I",
                "version": "1.0.0",
                "bom-ref": "root-app@1.0.0"
            }
        },
        "components": [],
        "dependencies": [],
        # Custom Mock Dictionary Format for Classic Eval Script
        "vulnerabilities": {}
    }

def generate_scenario_I_real():
    sbom = create_base_sbom()
    root_ref = "root-app@1.0.0"
    
    # 1. Define Components
    # Two identical libraries, different purposes
    net_ref = "pkg:npm/net-lib@1.0.0"
    local_ref = "pkg:npm/local-lib@1.0.0"
    
    components = [
        {"name": "root-app", "bom-ref": root_ref, "type": "application"},
        {"name": "net-lib", "bom-ref": net_ref, "type": "library"},
        {"name": "local-lib", "bom-ref": local_ref, "type": "library"}
    ]
    sbom["components"] = components
    
    # 2. Define Graph Topology
    # Both are direct dependencies (Flat graph) to isolate the Vector variable.
    sbom["dependencies"] = [
        {"ref": root_ref, "dependsOn": [net_ref, local_ref]},
        {"ref": net_ref, "dependsOn": []},
        {"ref": local_ref, "dependsOn": []}
    ]

    # 3. Inject Vulnerabilities (Mock Dictionary Format)
    # Identical Scores (7.5) and EPSS (0.1).
    # Difference: Attack Vector (AV:N vs AV:L).
    
    # Target A: Network Accessible
    sbom["vulnerabilities"]["CVE-NET"] = {
        "package_id": net_ref,
        # AV:N, High Complexity, High Confidentiality -> 7.5 Base
        "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N", 
        "impact_score": 7.5,
        "base_score": 7.5,
        "epss": 0.1,
        "kev": False,
        "vex_status": "affected"
    }

    # Target B: Local Access Required
    sbom["vulnerabilities"]["CVE-LOCAL"] = {
        "package_id": local_ref,
        # AV:L, Low Complexity, High C/I/A -> 7.5 Base
        "cvss_vector": "CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 
        "impact_score": 7.5,
        "base_score": 7.5,
        "epss": 0.1,
        "kev": False,
        "vex_status": "affected"
    }

    return sbom

if __name__ == "__main__":
    data = generate_scenario_I_real()
    with open(FILENAME, "w") as f:
        json.dump(data, f, indent=2)
    print(f"Generated {FILENAME}")
    print("Scenario: Identical Score (7.5), Different Vectors (Network vs Local).")