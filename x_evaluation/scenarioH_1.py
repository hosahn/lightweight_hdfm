import json
import uuid
from datetime import datetime

FILENAME = "TC07_SilentKiller1.json"

def generate_tc07_standard():
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
                "name": "Web-Backend-App-Scenario-G",
                "version": "2.1.0",
                "bom-ref": "root-app@2.1.0"
            }
        },
        "components": [],
        "dependencies": [],
        "vulnerabilities": [] # Standard List Format
    }
    
    # 2. Define Components
    root_ref = "root-app@2.1.0"
    target_ref = "pkg:pypi/requests@2.0.0" # The Silent Killer Target
    
    components = [
        {"name": "root-app", "bom-ref": root_ref, "type": "application"},
        {"name": "requests", "bom-ref": target_ref, "type": "library"}
    ]
    
    # 3. Add Noise Components (Standard Python Web Stack)
    safe_libs = [
        ("flask", "2.3.2"),
        ("werkzeug", "2.3.6"),
        ("jinja2", "3.1.2"),
        ("click", "8.1.3"),
        ("itsdangerous", "2.1.2"),
        ("gunicorn", "20.1.0"),
        ("sqlalchemy", "2.0.16"),
        ("alembic", "1.11.1"),
        ("pydantic", "1.10.9"),
        ("greenlet", "2.0.2")
    ]
    
    # Root depends on everything (Direct dependencies)
    root_deps = [target_ref]
    
    for name, version in safe_libs:
        ref = f"pkg:pypi/{name}@{version}"
        components.append({"name": name, "bom-ref": ref, "type": "library"})
        root_deps.append(ref)
        
    sbom["components"] = components
    
    # 4. Define Graph Topology
    # Flat structure: Root depends on everything. Libraries are leaves.
    dependencies = [{"ref": root_ref, "dependsOn": root_deps}]
    
    # Add empty dependency entries for all libraries
    for dep in root_deps:
        dependencies.append({"ref": dep, "dependsOn": []})
        
    sbom["dependencies"] = dependencies

    # 5. Inject Vulnerability (Standard Format)
    # Scenario: Medium CVSS (5.3), Extreme EPSS (0.96)
    vuln = {
        "id": "CVE-2023-SILENT-KILLER",
        "source": { "name": "NVD", "url": "https://nvd.nist.gov" },
        "ratings": [
            {
                "source": { "name": "NVD" },
                "score": 5.3,
                "severity": "medium",
                "method": "CVSSv31",
                # Vector: Network access (AV:N), but Low Impact on CIA -> 5.3 Base
                "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"
            }
        ],
        "description": "Silent Killer - Medium Severity but Active Exploitation",
        "affects": [
            { "ref": target_ref }
        ],
        # Custom HDFM Data
        "properties": [
            { "name": "epss", "value": "0.96" }, # Extreme Probability
            { "name": "kev", "value": "false" }  # Not yet in KEV (Predictive)
        ],
        "analysis": {
            "state": "affected"
        }
    }
    
    sbom["vulnerabilities"].append(vuln)

    return sbom

if __name__ == "__main__":
    data = generate_tc07_standard()
    with open(FILENAME, "w") as f:
        json.dump(data, f, indent=2)
    print(f"Generated {FILENAME} (Standard CycloneDX 1.4 Format)")
    print("Vulnerability: CVSS 5.3 (Medium) vs EPSS 0.96 (Critical Threat).")