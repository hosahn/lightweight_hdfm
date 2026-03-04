import json
import uuid
from datetime import datetime

FILENAME = "./generator/TC_ScopeDiscriminator2.json"

def generate_scope_test_standard():
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
                "name": "Scope-Discriminator-App",
                "version": "1.0.0",
                "bom-ref": "root-app@1.0.0"
            }
        },
        "components": [],
        "dependencies": [],
        "vulnerabilities": []
    }
    
    # 2. Define Components with SCOPE
    root_ref = "root-app@1.0.0"
    direct_ref = "pkg:npm/direct-lib@1.0.0"
    transitive_ref = "pkg:npm/transitive-lib@1.0.0"
    
    components = [
        {
            "name": "root", 
            "bom-ref": root_ref, 
            "type": "application"
            # No scope needed for root
        },
        {
            "name": "direct-lib", 
            "bom-ref": direct_ref, 
            "type": "library", 
            "scope": "required"  # <--- HDFM reads this as Direct (S_v = 1.0)
        },
        {
            "name": "transitive-lib", 
            "bom-ref": transitive_ref, 
            "type": "library", 
            "scope": "optional"  # <--- HDFM reads this as Transitive (S_v = 0.5)
        }
    ]
    sbom["components"] = components
    
    # 3. Define Graph Topology
    # Root -> Direct -> Transitive
    deps = [
        {"ref": root_ref, "dependsOn": [direct_ref]},
        {"ref": direct_ref, "dependsOn": [transitive_ref]},
        {"ref": transitive_ref, "dependsOn": []}
    ]
    sbom["dependencies"] = deps

    # 4. Inject Vulnerabilities (Standard Format)
    # Identical metadata, different targets.
    
    common_vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N" # Score 7.5 (High)
    common_epss = "0.1"
    
    # Vuln A (Affects Direct Lib)
    vuln_direct = {
        "id": "CVE-DIRECT",
        "source": { "name": "TEST", "url": "http://localhost" },
        "ratings": [{
            "source": { "name": "TEST" },
            "score": 7.5,
            "severity": "high",
            "method": "CVSSv31",
            "vector": common_vector
        }],
        "description": "Direct Dependency Vulnerability (Should score higher)",
        "affects": [{ "ref": direct_ref }],
        "properties": [
            { "name": "epss", "value": common_epss },
            { "name": "kev", "value": "false" }
        ],
        "analysis": { "state": "affected" }
    }
    
    # Vuln B (Affects Transitive Lib)
    vuln_transitive = {
        "id": "CVE-TRANSITIVE",
        "source": { "name": "TEST", "url": "http://localhost" },
        "ratings": [{
            "source": { "name": "TEST" },
            "score": 7.5,
            "severity": "high",
            "method": "CVSSv31",
            "vector": common_vector
        }],
        "description": "Transitive Dependency Vulnerability (Should score lower)",
        "affects": [{ "ref": transitive_ref }],
        "properties": [
            { "name": "epss", "value": common_epss },
            { "name": "kev", "value": "false" }
        ],
        "analysis": { "state": "affected" }
    }

    sbom["vulnerabilities"] = [vuln_direct, vuln_transitive]
    
    return sbom

if __name__ == "__main__":
    with open(FILENAME, "w") as f:
        json.dump(generate_scope_test_standard(), f, indent=2)
    print(f"Generated {FILENAME} (Standard CycloneDX 1.4 Format)")
    print("Components marked with 'scope': 'required' vs 'optional'.")