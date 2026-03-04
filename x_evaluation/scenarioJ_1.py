import json
import uuid
from datetime import datetime

FILENAME = "TC10_EntropyAdapter1.json"

def generate_tc10_standard():
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
                "name": "Entropy-Test-App-Scenario-J",
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
    components = [{"name": "root-app", "bom-ref": root_ref, "type": "application"}]
    
    root_deps = []
    
    for i in range(50):
        comp_name = f"comp-{i}"
        ref = f"pkg:npm/{comp_name}@1.0.0"
        
        components.append({
            "name": comp_name,
            "bom-ref": ref,
            "type": "library"
        })
        
        root_deps.append(ref)

        # 3. Inject Vulnerability (Standard Format)
        if i == 25:
            vuln_id = "CVE-2023-THE-ONE"
            epss_val = "0.95"
            desc = "The actual threat hidden in noise"
        else:
            vuln_id = f"CVE-2023-NOISE-{i}"
            epss_val = "0.01"
            desc = "High severity noise"

        vuln = {
            "id": vuln_id,
            "source": { "name": "TEST" },
            "ratings": [{
                "source": { "name": "TEST" },
                "score": 8.0,
                "severity": "high",
                "method": "CVSSv31",
                # Consistent High Severity Vector
                "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
            }],
            "description": desc,
            "affects": [{ "ref": ref }],
            "properties": [
                { "name": "epss", "value": epss_val },
                { "name": "kev", "value": "false" }
            ],
            "analysis": { "state": "affected" }
        }
        
        sbom["vulnerabilities"].append(vuln)

    sbom["components"] = components
    
    # 4. Define Graph
    dependencies = [{"ref": root_ref, "dependsOn": root_deps}]
    for dep in root_deps:
        dependencies.append({"ref": dep, "dependsOn": []})
        
    sbom["dependencies"] = dependencies

    return sbom

if __name__ == "__main__":
    data = generate_tc10_standard()
    with open(FILENAME, "w") as f:
        json.dump(data, f, indent=2)
    print(f"Generated {FILENAME} (Standard CycloneDX 1.4 Format)")
    print("Contains 50 items. All CVSS 8.0. One has High EPSS.")