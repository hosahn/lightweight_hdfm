import json
import uuid
from datetime import datetime

FILENAME = "./generator/TC04_PaperTiger2.json"

def generate_tc04_standard():
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
                "name": "Hardware-Interface-App-Scenario-D",
                "version": "1.0.0",
                "bom-ref": "root-app@1.0.0"
            }
        },
        "components": [],
        "dependencies": [],
        "vulnerabilities": []
    }
    
    # 2. Define Key Components
    root_ref = "root-app@1.0.0"
    mid_ref = "pkg:npm/hardware-interface@2.0.0"
    target_ref = "pkg:npm/usb-driver@1.0.0" # The Paper Tiger Target
    
    # Standard Components List
    components = [
        {"name": "root-app", "bom-ref": root_ref, "type": "application"},
        {"name": "hardware-interface", "bom-ref": mid_ref, "type": "library"},
        {"name": "usb-driver", "bom-ref": target_ref, "type": "library"}
    ]
    
    # 3. Add Noise Components (Safe libraries)
    # This prevents the TCS from being artificially high by diluting the graph
    noise_refs = []
    for i in range(8):
        ref = f"pkg:npm/safe-lib-{i}@1.0.0"
        components.append({"name": f"safe-lib-{i}", "bom-ref": ref, "type": "library"})
        noise_refs.append(ref)
        
    sbom["components"] = components
    
    # 4. Define Graph Topology
    # Main Chain: Root -> Hardware -> USB Driver
    deps = [
        {"ref": root_ref, "dependsOn": [mid_ref] + noise_refs}, # Root uses everything
        {"ref": mid_ref, "dependsOn": [target_ref]},
        {"ref": target_ref, "dependsOn": []} # Leaf node
    ]
    
    # Add dependencies for noise (leaf nodes)
    for ref in noise_refs:
        deps.append({"ref": ref, "dependsOn": []})
        
    sbom["dependencies"] = deps

    # 5. Inject Vulnerability (Standard Format)
    # High Impact (7.6), but Physical Vector.
    vuln = {
        "id": "CVE-2023-PAPER-TIGER",
        "source": { "name": "NVD", "url": "https://nvd.nist.gov" },
        "ratings": [
            {
                "source": { "name": "NVD" },
                "score": 7.6, # High Severity
                "severity": "high",
                "method": "CVSSv31",
                # AV:P = Physical Access Required (The demotion factor)
                # S:C = Scope Changed (Increases score)
                # C:H/I:H/A:H = Total compromise
                "vector": "CVSS:3.1/AV:P/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"
            }
        ],
        "description": "Paper Tiger - High Impact but requires Physical Access",
        "affects": [
            { "ref": target_ref }
        ],
        # Custom HDFM Data (EPSS is low)
        "properties": [
            { "name": "epss", "value": "0.01" },
            { "name": "kev", "value": "false" }
        ],
        "analysis": {
            "state": "affected"
        }
    }
    
    sbom["vulnerabilities"].append(vuln)

    return sbom

if __name__ == "__main__":
    data = generate_tc04_standard()
    with open(FILENAME, "w") as f:
        json.dump(data, f, indent=2)
    print(f"Generated {FILENAME} (Standard CycloneDX 1.4 Format)")