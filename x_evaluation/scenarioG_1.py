import json
import uuid
from datetime import datetime

FILENAME = "./generator/TC08_StructuralBottleneck2.json"

def generate_tc08_standard():
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
                "name": "Legacy-Monolith-Scenario-H",
                "version": "5.0.0",
                "bom-ref": "root-app@5.0.0"
            }
        },
        "components": [],
        "dependencies": [],
        "vulnerabilities": []
    }
    
    # 2. Define Components
    root_ref = "root-app@5.0.0"
    target_ref = "pkg:npm/common-utils@1.0.0" # The Bottleneck
    
    components = [
        {"name": "root-app", "bom-ref": root_ref, "type": "application"},
        {"name": "common-utils", "bom-ref": target_ref, "type": "library"}
    ]
    
    # 3. Define Graph Topology
    # Start dependencies list
    # Root depends on Target directly
    root_deps = [target_ref]
    target_deps = [] # Target is a leaf, depends on nothing
    
    other_dependencies = []

    # Generate 20 Feature Modules that ALL depend on the Target
    for i in range(20):
        feat_name = f"feature-module-{i}"
        feat_ref = f"pkg:npm/{feat_name}@2.1.0"
        
        components.append({
            "name": feat_name, 
            "bom-ref": feat_ref, 
            "type": "library"
        })
        
        # Link: Root -> Feature Module
        root_deps.append(feat_ref)
        
        # Link: Feature Module -> Common Utils (The Bottleneck)
        other_dependencies.append({
            "ref": feat_ref,
            "dependsOn": [target_ref]
        })

    sbom["components"] = components

    # Construct final dependencies list
    # 1. Root Node
    sbom["dependencies"].append({"ref": root_ref, "dependsOn": root_deps})
    # 2. The Bottleneck Node
    sbom["dependencies"].append({"ref": target_ref, "dependsOn": target_deps})
    # 3. The Feature Modules
    sbom["dependencies"].extend(other_dependencies)

    # 4. Inject Vulnerability (Standard Format)
    # Scenario: Medium CVSS, Low EPSS, but Max Centrality.
    vuln = {
        "id": "CVE-2023-BOTTLENECK",
        "source": { "name": "NVD", "url": "https://nvd.nist.gov" },
        "ratings": [
            {
                "source": { "name": "NVD" },
                "score": 6.0,
                "severity": "medium",
                "method": "CVSSv31",
                # Vector: Local access (AV:L), Low Complexity, Low Impact
                "vector": "CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L"
            }
        ],
        "description": "Structural Bottleneck - Low Threat, Critical Architecture",
        "affects": [
            { "ref": target_ref }
        ],
        # Custom HDFM Data
        "properties": [
            { "name": "epss", "value": "0.05" }, # Low EPSS
            { "name": "kev", "value": "false" }
        ],
        "analysis": {
            "state": "affected"
        }
    }
    
    sbom["vulnerabilities"].append(vuln)

    return sbom

if __name__ == "__main__":
    data = generate_tc08_standard()
    with open(FILENAME, "w") as f:
        json.dump(data, f, indent=2)
    print(f"Generated {FILENAME} (Standard CycloneDX 1.4 Format)")
    print("Topology: 'common-utils' has 21 incoming edges (Max Centrality).")