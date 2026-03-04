import json
import uuid
from datetime import datetime

FILENAME = "./generator/TC08_StructuralBottleneck.json"

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
                "name": "Legacy-Monolith-Scenario-H",
                "version": "5.0.0",
                "bom-ref": "root-app"
            }
        },
        "components": [],
        "dependencies": [],
        "vulnerabilities": {}
    }

def create_component(name, version):
    purl = f"pkg:npm/{name}@{version}"
    return {
        "type": "library",
        "name": name,
        "version": version,
        "bom-ref": purl,
        "purl": purl
    }

def generate_scenario_H_real():
    sbom = create_base_sbom()
    root_ref = "root-app"
    deps_map = {root_ref: []}

    # 1. The Target: A low-level utility (e.g., 'left-pad' style)
    # It seems unimportant, but it is a "Bottleneck".
    target_comp = create_component("common-utils", "1.0.0")
    sbom['components'].append(target_comp)
    # The root uses it
    deps_map[root_ref].append(target_comp['bom-ref'])
    deps_map[target_comp['bom-ref']] = []

    # 2. The "Heavy Load": 20 other components that ALL depend on Target
    # This forces In-Degree Centrality to be Maximum (100% of libs use it).
    for i in range(20):
        comp_name = f"feature-module-{i}"
        comp = create_component(comp_name, "2.1.0")
        sbom['components'].append(comp)
        
        # Link: Root -> Feature -> Target
        deps_map[root_ref].append(comp['bom-ref'])
        deps_map[comp['bom-ref']] = [target_comp['bom-ref']]

    # 3. Construct Dependencies
    for parent, children in deps_map.items():
        sbom['dependencies'].append({"ref": parent, "dependsOn": children})

    # 4. Inject Vulnerability
    # SCENARIO: 
    # CVSS is 6.0 (Medium).
    # EPSS is Low (0.05).
    # Standard Tool: Ranks LOW/MEDIUM.
    # HDFM: Should recognize High Centrality -> Branch A -> HIGH priority.
    vuln_id = "CVE-2023-BOTTLENECK"
    
    sbom["vulnerabilities"][vuln_id] = {
        "package_id": target_comp['bom-ref'],
        "cvss_vector": "CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L", # Base 6.0
        "impact_score": 6.0,
        "epss": 0.05,
        "kev": False,
        "vex_status": "affected"
    }

    return sbom

if __name__ == "__main__":
    data = generate_scenario_H_real()
    with open(FILENAME, "w") as f:
        json.dump(data, f, indent=2)
    print(f"Generated {FILENAME}")
    print("Scenario: Medium Sev (6.0), Low EPSS (0.05).")
    print("Context: 'common-utils' is used by ALL 20 feature modules (Max Centrality).")