import json
import uuid
from datetime import datetime

FILENAME = "./generator/TC02_LatentGiant2.json"

def generate_tc02_standard():
    # 1. Setup Base SBOM with standard 'vulnerabilities' list
    sbom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.4",
        "serialNumber": f"urn:uuid:{str(uuid.uuid4())}",
        "version": 1,
        "metadata": {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "component": {
                "type": "application",
                "name": "Production-App-Scenario-B",
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
    middleware_ref = "pkg:npm/middleware@2.0.0"
    target_ref = "pkg:npm/core-parser@1.0.0" # The Giant (High Centrality)
    
    components_list = [
        {"name": "root-app", "bom-ref": root_ref, "type": "application"},
        {"name": "middleware", "bom-ref": middleware_ref, "type": "library"},
        {"name": "core-parser", "bom-ref": target_ref, "type": "library"}
    ]
    
    # 3. Define Graph Topology
    # Structure: Root -> Middleware -> Core-Parser (Transitive depth)
    deps_map = {
        root_ref: [middleware_ref],
        middleware_ref: [target_ref],
        target_ref: []
    }
    
    # High Centrality Logic:
    # Create 15 'Plugin' components that ALL depend on 'core-parser'.
    for i in range(15):
        plugin_ref = f"pkg:npm/plugin-{i}@1.0"
        components_list.append({"name": f"plugin-{i}", "bom-ref": plugin_ref, "type": "library"})
        
        # Link Plugin -> Core-Parser
        deps_map[plugin_ref] = [target_ref]
        # Link Root -> Plugin (to make plugins reachable)
        deps_map[root_ref].append(plugin_ref)

    sbom["components"] = components_list
    
    # Flatten dependencies
    for parent, children in deps_map.items():
        sbom["dependencies"].append({"ref": parent, "dependsOn": children})

    # 4. Inject Vulnerability (Standard CycloneDX Format)
    vuln = {
        "id": "CVE-2023-LATENT",
        "source": { "name": "NVD", "url": "https://nvd.nist.gov" },
        "ratings": [
            {
                "source": { "name": "NVD" },
                "score": 4.1,
                "severity": "medium",
                "method": "CVSSv31",
                "vector": "CVSS:3.1/AV:L/AC:H/PR:H/UI:N/S:U/C:H/I:N/A:N" # Local Access
            }
        ],
        "description": "Latent Giant Vulnerability - Low Threat, High Structure",
        "affects": [
            {
                "ref": target_ref
            }
        ],
        # Using 'properties' to store our custom HDFM data in a standard way
        "properties": [
            { "name": "epss", "value": "0.001" }, # Low EPSS
            { "name": "kev", "value": "false" }
        ],
        # VEX Status goes in 'analysis'
        "analysis": {
            "state": "affected"
        }
    }
    
    sbom["vulnerabilities"].append(vuln)

    return sbom

if __name__ == "__main__":
    data = generate_tc02_standard()
    with open(FILENAME, "w") as f:
        json.dump(data, f, indent=2)
    print(f"Generated {FILENAME} (Standard CycloneDX 1.4 Format)")
    print("Contains root-level 'vulnerabilities' list with 'ratings' and 'affects'.")