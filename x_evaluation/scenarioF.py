import json
import uuid
from datetime import datetime

FILENAME = "TC06_PaperTiger.json"

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
                "name": "Hardware-Interface-App-Scenario-F",
                "version": "1.0.0",
                "bom-ref": "root-app"
            }
        },
        "components": [],
        "dependencies": [],
        "vulnerabilities": {}
    }

def create_component(group, name, version):
    if group:
        purl = f"pkg:npm/{group}/{name}@{version}"
        full_name = f"{group}/{name}"
    else:
        purl = f"pkg:npm/{name}@{version}"
        full_name = name
        
    return {
        "type": "library",
        "name": full_name,
        "version": version,
        "bom-ref": purl,
        "purl": purl
    }

def generate_scenario_F_real():
    sbom = create_base_sbom()
    root_ref = "root-app"
    deps_map = {root_ref: []}

    # 1. The "Paper Tiger" Target Component
    # A driver library that implies hardware interaction
    target_comp = create_component(None, "usb-driver", "1.0.0")
    sbom['components'].append(target_comp)
    deps_map[root_ref].append(target_comp['bom-ref'])
    deps_map[target_comp['bom-ref']] = []

    # 2. Add "Noise" (Safe/Standard NPM Libraries)
    # Makes the graph look populated
    safe_libs = [
        (None, "serialport", "10.5.0"),
        (None, "johnny-five", "2.1.0"),
        (None, "firmata", "2.3.0"),
        (None, "chalk", "4.1.2"),
        (None, "debug", "4.3.4"),
        (None, "commander", "9.4.1"),
        (None, "eventemitter3", "4.0.7"),
        (None, "lodash", "4.17.21"),
        (None, "mkdirp", "1.0.4"),
        (None, "yargs", "17.7.2")
    ]

    for group, name, version in safe_libs:
        comp = create_component(group, name, version)
        sbom['components'].append(comp)
        
        # Link Root -> Lib (Direct dependencies)
        deps_map[root_ref].append(comp['bom-ref'])
        deps_map[comp['bom-ref']] = []

    # 3. Construct Dependencies Array
    for parent, children in deps_map.items():
        sbom['dependencies'].append({"ref": parent, "dependsOn": children})

    # 4. Inject the Mock Vulnerability
    # SCENARIO: High Impact Score (7.6), typically flagging "High" priority.
    # BUT Attack Vector is Physical (AV:P).
    vuln_id = "CVE-2023-PAPER-TIGER"
    
    sbom["vulnerabilities"][vuln_id] = {
        "package_id": target_comp['bom-ref'],
        
        # Threat Data: 
        # AV:P = Physical Access Required (The demotion factor)
        # S:C = Scope Changed (Increases score)
        # C:H/I:H/A:H = High Confidentiality, Integrity, Availability Impact
        "cvss_vector": "CVSS:3.1/AV:P/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
        
        # Resulting Base Score for this vector is 7.6 (High)
        "base_score": 7.6, 
        
        "epss": 0.01, # Low probability of exploitation
        "kev": False,
        "vex_status": "affected"
    }

    return sbom

# --- EXECUTE ---
if __name__ == "__main__":
    data = generate_scenario_F_real()
    with open(FILENAME, "w") as f:
        json.dump(data, f, indent=2)
    print(f"Generated {FILENAME}")
    print("Scenario: High Severity (7.6) due to Impact, but Physical Vector (AV:P).")
    print("Context: Embedded among 10 safe NPM hardware/utility libraries.")