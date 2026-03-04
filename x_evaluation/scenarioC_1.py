import json
import uuid
from datetime import datetime

FILENAME = "./generator/TC03_ExposedPeripheral2.json"

def generate_tc03_standard():
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
                "name": "Production-App-Scenario-C",
                "version": "1.0.0",
                "bom-ref": "root-app@1.0.0"
            }
        },
        "components": [],
        "dependencies": [],
        "vulnerabilities": []
    }
    
    # 2. Define Components
    root_ref = "root-app@1.0.0"
    parent_ref = "pkg:pypi/requests@2.0.0"
    target_ref = "pkg:pypi/idna@3.0" # Leaf node (The Peripheral)
    
    components_list = [
        {"name": "root-app", "bom-ref": root_ref, "type": "application"},
        {"name": "requests", "bom-ref": parent_ref, "type": "library"},
        {"name": "idna", "bom-ref": target_ref, "type": "library"}
    ]
    
    sbom["components"] = components_list
    
    # 3. Define Graph Topology (Linear Chain)
    # Structure: Root -> Requests -> IDNA
    # IDNA is at the bottom. No other component depends on it.
    # In-Degree Centrality = 0 (or 1 depending on normalization logic). Very Low.
    sbom["dependencies"] = [
        {"ref": root_ref, "dependsOn": [parent_ref]},
        {"ref": parent_ref, "dependsOn": [target_ref]},
        {"ref": target_ref, "dependsOn": []} # No dependents = Leaf Node
    ]

    # 4. Inject Vulnerability (Standard Format)
    # Structural Score is Low, but Exposure is High.
    vuln = {
        "id": "CVE-2023-EXPOSED",
        "source": { "name": "NVD", "url": "https://nvd.nist.gov" },
        "ratings": [
            {
                "source": { "name": "NVD" },
                "score": 6.5,
                "severity": "medium",
                "method": "CVSSv31",
                # AV:N (Network) is critical here. It means it's reachable remotely.
                "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N"
            }
        ],
        "description": "Exposed Peripheral - Low Structure, High Reachability",
        "affects": [
            { "ref": target_ref }
        ],
        # Custom HDFM Data
        "properties": [
            { "name": "epss", "value": "0.85" }, # High probability
            { "name": "kev", "value": "false" }
        ],
        "analysis": {
            "state": "affected"
        }
    }
    
    sbom["vulnerabilities"].append(vuln)

    return sbom

if __name__ == "__main__":
    data = generate_tc03_standard()
    with open(FILENAME, "w") as f:
        json.dump(data, f, indent=2)
    print(f"Generated {FILENAME} (Standard CycloneDX 1.4 Format)")