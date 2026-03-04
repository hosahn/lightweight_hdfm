import json
import uuid
from datetime import datetime

FILENAME = "TC10_EntropyAdapter.json"

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
                "name": "Entropy-Test-App-Scenario-J",
                "version": "1.0.0",
                "bom-ref": "root-app@1.0.0"
            }
        },
        "components": [],
        "dependencies": [],
        # Custom Mock Dictionary Format for Classic Eval Script
        "vulnerabilities": {}
    }

def generate_scenario_J_real():
    sbom = create_base_sbom()
    root_ref = "root-app@1.0.0"
    
    # 1. Define Components (50 items)
    components = [{"name": "root-app", "bom-ref": root_ref, "type": "application"}]
    
    # Root depends on all of them
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
        
        # 2. Inject Vulnerabilities (Mock Dictionary Format)
        # SCENARIO: 
        # All 50 have Severity 8.0 (High).
        # Variance of Severity = 0.
        # Entropy Weighting should drop Severity weight to 0.
        
        # 49 are Noise (Low EPSS)
        # 1 is "The One" (High EPSS)
        
        if i == 25:
            vuln_id = "CVE-2023-THE-ONE"
            epss_val = 0.95
        else:
            vuln_id = f"CVE-2023-NOISE-{i}"
            epss_val = 0.01
            
        sbom["vulnerabilities"][vuln_id] = {
            "package_id": ref,
            # AV:N, High Impact -> 8.0 Base
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "impact_score": 8.0,
            "base_score": 8.0,
            "epss": epss_val,
            "kev": False,
            "vex_status": "affected"
        }

    sbom["components"] = components
    
    # 3. Define Graph (Flat)
    dependencies = [{"ref": root_ref, "dependsOn": root_deps}]
    for dep in root_deps:
        dependencies.append({"ref": dep, "dependsOn": []})
        
    sbom["dependencies"] = dependencies

    return sbom

if __name__ == "__main__":
    data = generate_scenario_J_real()
    with open(FILENAME, "w") as f:
        json.dump(data, f, indent=2)
    print(f"Generated {FILENAME}")
    print("Scenario: 50 Vulns. All Base Score 8.0.")
    print("Context: 1 has EPSS 0.95, 49 have EPSS 0.01.")