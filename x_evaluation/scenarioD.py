import json

FILENAME = "TC04_PaperTiger.json"

def generate_tc04():
    # 1. Setup Base SBOM
    sbom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.4",
        "components": [],
        "dependencies": [],
        "vulnerabilities": {} 
    }
    
    # 2. Define Components
    # A standard dependency chain (Root -> Middleware -> USB-Driver)
    root_ref = "root-app@1.0"
    mid_ref = "pkg:npm/hardware-interface@2.0"
    target_ref = "pkg:npm/usb-driver@1.0" 
    
    sbom["components"] = [
        {"name": "root-app", "bom-ref": root_ref, "type": "application"},
        {"name": "hardware-interface", "bom-ref": mid_ref, "type": "library"},
        {"name": "usb-driver", "bom-ref": target_ref, "type": "library"}
    ]
    
    # 3. Define Graph Topology
    # Moderate depth, nothing special structurally.
    sbom["dependencies"] = [
        {"ref": root_ref, "dependsOn": [mid_ref]},
        {"ref": mid_ref, "dependsOn": [target_ref]},
        {"ref": target_ref, "dependsOn": []}
    ]

    # 4. Inject Vulnerability Metadata (The "Paper Tiger")
    # The Trap: High Impact metrics (High Confidentiality/Integrity/Availability)
    # causing a high Base Score (7.6).
    # The Reality: Attack Vector is Physical (AV:P).
    
    sbom["vulnerabilities"]["CVE-2023-PAPER-TIGER"] = {
        "package_id": target_ref,
        # Vector Explanation:
        # AV:P = Physical (Requires plugging in a device)
        # S:C = Scope Changed (increases score)
        # C:H/I:H/A:H = Total compromise
        # Resulting Base Score: 7.6 (High)
        "cvss_vector": "CVSS:3.1/AV:P/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 
        "impact_score": 7.6, 
        "epss": 0.01, # Low probability
        "kev": False,
        "vex_status": "affected",
        "dependency_scope": "optional"
    }

    return sbom

if __name__ == "__main__":
    data = generate_tc04()
    with open(FILENAME, "w") as f:
        json.dump(data, f, indent=2)
    print(f"Generated {FILENAME}")
    print("Graph Characteristics: Standard Transitive Dependency")
    print("Vulnerability Characteristics: High CVSS (7.6) but Physical Vector (AV:P)")