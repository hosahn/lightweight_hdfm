import json

FILENAME = "TC03_ExposedPeripheral.json"

def generate_tc03():
    # 1. Setup Base SBOM
    sbom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.4",
        "components": [],
        "dependencies": [],
        "vulnerabilities": {} 
    }
    
    # 2. Define Components
    root_ref = "root-app@1.0"
    parent_ref = "pkg:pypi/requests@2.0"
    target_ref = "pkg:pypi/idna@3.0" # Leaf node (The Peripheral)
    
    sbom["components"] = [
        {"name": "root", "bom-ref": root_ref, "type": "application"},
        {"name": "requests", "bom-ref": parent_ref, "type": "library"},
        {"name": "idna", "bom-ref": target_ref, "type": "library"}
    ]
    
    # 3. Define Graph Topology (Linear Chain)
    # Structure: Root -> Requests -> IDNA
    # IDNA is at the bottom. No other component depends on it.
    # In-Degree Centrality = 0 (or 1 depending on normalization). Very Low.
    sbom["dependencies"] = [
        {"ref": root_ref, "dependsOn": [parent_ref]},
        {"ref": parent_ref, "dependsOn": [target_ref]},
        {"ref": target_ref, "dependsOn": []} # No dependents = Leaf Node
    ]

    # 4. Inject Vulnerability Metadata (The "Exposed" aspect)
    # Structural Score is Low, but Exposure is High.
    sbom["vulnerabilities"]["CVE-2023-EXPOSED"] = {
        "package_id": target_ref,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N", # Base ~6.5 (Medium)
        "impact_score": 6.5,
        "epss": 0.85,       # High probability of exploitation
        "kev": False,
        "vex_status": "affected",
        "dependency_scope": "optional" # Transitive
    }

    return sbom

if __name__ == "__main__":
    data = generate_tc03()
    with open(FILENAME, "w") as f:
        json.dump(data, f, indent=2)
    print(f"Generated {FILENAME}")
    print("Graph Characteristics: Leaf Node (Low Structure)")
    print("Vulnerability Characteristics: Network Vector (AV:N), High EPSS (0.85)")