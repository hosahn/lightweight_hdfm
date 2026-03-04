import json

FILENAME = "TC02_LatentGiant.json"

def generate_tc02():
    # 1. Setup Base SBOM Structure
    sbom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.4",
        "components": [],
        "dependencies": [],
        # Custom block for HDFM / Classic Eval script
        "vulnerabilities": {} 
    }
    
    # 2. Define Components
    root_ref = "root-app@1.0.0"
    middleware_ref = "pkg:npm/middleware@2.0.0"
    target_ref = "pkg:npm/core-parser@1.0.0" # This is the 'Giant'
    
    components_list = [
        {"name": "root-app", "bom-ref": root_ref, "type": "application"},
        {"name": "middleware", "bom-ref": middleware_ref, "type": "library"},
        {"name": "core-parser", "bom-ref": target_ref, "type": "library"}
    ]
    
    # 3. Define Graph Topology
    # Structure: Root -> Middleware -> Core-Parser (Transitive depth)
    deps_map = {
        root_ref: [middleware_ref],
        middleware_ref: [target_ref],
        target_ref: []
    }
    
    # High Centrality Logic:
    # Create 15 'Plugin' components that ALL depend on 'core-parser'.
    # This spikes the In-Degree Centrality.
    for i in range(15):
        plugin_ref = f"pkg:npm/plugin-{i}@1.0"
        components_list.append({"name": f"plugin-{i}", "bom-ref": plugin_ref, "type": "library"})
        
        # Link Plugin -> Core-Parser
        deps_map[plugin_ref] = [target_ref]
        # Link Root -> Plugin (to make plugins reachable)
        deps_map[root_ref].append(plugin_ref)

    sbom["components"] = components_list
    
    # Flatten dependencies for JSON
    for parent, children in deps_map.items():
        sbom["dependencies"].append({"ref": parent, "dependsOn": children})

    # 4. Inject Vulnerability Metadata (The "Latent" aspect)
    # Low Severity, Local Access, Low Probability.
    # Standard tools usually rate this 'Low' or 'Medium'.
    sbom["vulnerabilities"]["CVE-2023-LATENT"] = {
        "package_id": target_ref,
        # AV:L (Local) keeps the score moderate/low
        "cvss_vector": "CVSS:3.1/AV:L/AC:H/PR:H/UI:N/S:U/C:H/I:N/A:N", 
        "impact_score": 4.1, # Medium/Low base score
        "epss": 0.001,       # Very low probability
        "kev": False,
        "vex_status": "affected",
        "dependency_scope": "optional" # Indicates transitive
    }

    return sbom

if __name__ == "__main__":
    data = generate_tc02()
    with open(FILENAME, "w") as f:
        json.dump(data, f, indent=2)
    print(f"Generated {FILENAME}")
    print("Graph Characteristics: 15 dependents on 'core-parser' (High Centrality)")
    print("Vulnerability Characteristics: CVSS 4.1 (Local), EPSS 0.001")