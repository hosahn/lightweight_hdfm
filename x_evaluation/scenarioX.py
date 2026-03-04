import json

FILENAME = "./generator/TC_ScopeDiscriminator.json"

def generate_scope_test():
    sbom = {"bomFormat": "CycloneDX", "components": [], "dependencies": [], "vulnerabilities": {}}
    
    root = "root-app@1.0"
    direct_lib = "pkg:npm/direct-lib@1.0"
    transitive_lib = "pkg:npm/transitive-lib@1.0"
    
    # 1. Define Components
    sbom["components"] = [
        {"name": "root", "bom-ref": root},
        {"name": "direct-lib", "bom-ref": direct_lib},
        {"name": "transitive-lib", "bom-ref": transitive_lib}
    ]
    
    # 2. Define Graph
    # Root depends on Direct Lib.
    # Direct Lib depends on Transitive Lib.
    # This makes Direct Lib "Depth 0" (relative to deps) and Transitive "Depth 1"
    sbom["dependencies"] = [
        {"ref": root, "dependsOn": [direct_lib]},
        {"ref": direct_lib, "dependsOn": [transitive_lib]},
        {"ref": transitive_lib, "dependsOn": []}
    ]

    # 3. Identical Vulnerabilities
    # We give them the EXACT same scores. The only difference is their position in the graph.
    common_vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N" # 7.5 High
    common_epss = 0.1
    
    # Vuln A (Direct)
    sbom["vulnerabilities"]["CVE-DIRECT"] = {
        "package_id": direct_lib,
        "cvss_vector": common_vector,
        "impact_score": 7.5,
        "vex_status": "affected",
        "scope": "required" # This flag helps your algo set S_v = 1.0
    }

    # Vuln B (Transitive)
    sbom["vulnerabilities"]["CVE-TRANSITIVE"] = {
        "package_id": transitive_lib,
        "cvss_vector": common_vector,
        "impact_score": 7.5,
        "vex_status": "affected",
        "scope": "optional" # This flag helps your algo set S_v = 0.5
    }

    return sbom

if __name__ == "__main__":
    with open(FILENAME, "w") as f:
        json.dump(generate_scope_test(), f, indent=2)