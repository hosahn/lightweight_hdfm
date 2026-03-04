import json
import uuid
from datetime import datetime

FILENAME = "TC09_TieBreaker1.json"

def generate_tc09_standard():
    # 1. Setup Base SBOM
    sbom = {
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
        "vulnerabilities": [] # Standard List Format
    }
    
    # 2. Define Components
    root_ref = "root-app@1.0.0"
    net_ref = "pkg:npm/net-lib@1.0.0"
    local_ref = "pkg:npm/local-lib@1.0.0"
    
    components = [
        {"name": "root-app", "bom-ref": root_ref, "type": "application"},
        {"name": "net-lib", "bom-ref": net_ref, "type": "library"},
        {"name": "local-lib", "bom-ref": local_ref, "type": "library"}
    ]
    sbom["components"] = components
    
    # 3. Define Graph Topology (Flat)
    sbom["dependencies"] = [
        {"ref": root_ref, "dependsOn": [net_ref, local_ref]},
        {"ref": net_ref, "dependsOn": []},
        {"ref": local_ref, "dependsOn": []}
    ]

    # 4. Inject Vulnerabilities (Standard Format)
    
    # Vuln A (Network)
    vuln_net = {
        "id": "CVE-NET",
        "source": { "name": "TEST" },
        "ratings": [{
            "source": { "name": "TEST" },
            "score": 7.5,
            "severity": "high",
            "method": "CVSSv31",
            "vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N"
        }],
        "description": "Network accessible vulnerability",
        "affects": [{ "ref": net_ref }],
        "properties": [
            { "name": "epss", "value": "0.1" },
            { "name": "kev", "value": "false" }
        ],
        "analysis": { "state": "affected" }
    }
    
    # Vuln B (Local)
    vuln_local = {
        "id": "CVE-LOCAL",
        "source": { "name": "TEST" },
        "ratings": [{
            "source": { "name": "TEST" },
            "score": 7.5,
            "severity": "high",
            "method": "CVSSv31",
            "vector": "CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        }],
        "description": "Local access required vulnerability",
        "affects": [{ "ref": local_ref }],
        "properties": [
            { "name": "epss", "value": "0.1" },
            { "name": "kev", "value": "false" }
        ],
        "analysis": { "state": "affected" }
    }

    sbom["vulnerabilities"] = [vuln_net, vuln_local]

    return sbom

if __name__ == "__main__":
    data = generate_tc09_standard()
    with open(FILENAME, "w") as f:
        json.dump(data, f, indent=2)
    print(f"Generated {FILENAME} (Standard CycloneDX 1.4 Format)")
    print("Contains CVE-NET (AV:N) and CVE-LOCAL (AV:L) with identical score 7.5")