import json
import uuid
from datetime import datetime

FILENAME = "TC07_SilentKiller.json"

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
                "name": "Web-Backend-App-Scenario-G",
                "version": "2.1.0",
                "bom-ref": "root-app"
            }
        },
        "components": [],
        "dependencies": [],
        # Custom Mock Dictionary Format for Classic Eval Script
        "vulnerabilities": {}
    }

def create_component(group, name, version):
    if group:
        purl = f"pkg:pypi/{group}/{name}@{version}"
        full_name = f"{group}/{name}"
    else:
        purl = f"pkg:pypi/{name}@{version}"
        full_name = name
        
    return {
        "type": "library",
        "name": full_name,
        "version": version,
        "bom-ref": purl,
        "purl": purl
    }

def generate_scenario_G_classic():
    sbom = create_base_sbom()
    root_ref = "root-app"
    deps_map = {root_ref: []}

    # 1. The Target: 'requests' (Ubiquitous HTTP library)
    target_comp = create_component(None, "requests", "2.0.0")
    sbom['components'].append(target_comp)
    
    # Root uses it directly
    deps_map[root_ref].append(target_comp['bom-ref'])
    deps_map[target_comp['bom-ref']] = []

    # 2. Add "Noise" (Standard Python Web Stack)
    safe_libs = [
        (None, "flask", "2.3.2"),
        (None, "werkzeug", "2.3.6"),
        (None, "jinja2", "3.1.2"),
        (None, "click", "8.1.3"),
        (None, "gunicorn", "20.1.0"),
        (None, "sqlalchemy", "2.0.16")
    ]

    for group, name, version in safe_libs:
        comp = create_component(group, name, version)
        sbom['components'].append(comp)
        
        # Link: Root -> Lib
        deps_map[root_ref].append(comp['bom-ref'])
        deps_map[comp['bom-ref']] = []

    # 3. Construct Dependencies Array
    for parent, children in deps_map.items():
        sbom['dependencies'].append({"ref": parent, "dependsOn": children})

    # 4. Inject Vulnerability (Mock Dictionary Format)
    # SCENARIO: Medium Severity (5.3) but High EPSS (0.96)
    vuln_id = "CVE-2023-SILENT-KILLER"
    
    sbom["vulnerabilities"][vuln_id] = {
        "package_id": target_comp['bom-ref'],
        
        # Vector: Network access, Low Impact -> Base 5.3
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", 
        "impact_score": 5.3,
        "base_score": 5.3,
        
        # The key differentiator
        "epss": 0.96,       
        "kev": False,       
        "vex_status": "affected"
    }

    return sbom

if __name__ == "__main__":
    data = generate_scenario_G_classic()
    with open(FILENAME, "w") as f:
        json.dump(data, f, indent=2)
    print(f"Generated {FILENAME} (Mock Dictionary Format for Classic Eval)")