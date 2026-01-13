
from typing import Dict, List
import networkx as nx
from collections import defaultdict

from core.entities import Component
from core.interface import IGraphAnalyzer


class NetworkXGraphAnalyzer(IGraphAnalyzer):
    """Adapter: NetworkX graph analysis"""
    
    def calculate_tcs(self, components: List[Component], dependencies: List[Dict]) -> Dict[str, float]:
        """Calculate TCS using NetworkX"""
        in_degree = defaultdict(int)
                
        for dep in dependencies:
            depends_on = dep.get('dependsOn', [])
            for target in depends_on:
                in_degree[target] += 1

        max_in_degree = max(in_degree.values()) if in_degree else 1
        
        tcs_scores = {}
        
        for comp in components:
            # --- Factor 1: Normalized Centrality (D) ---
            # How many other components depend on this one?
            degree_count = in_degree.get(comp.bom_ref, 0)
            normalized_degree = degree_count / max_in_degree
            
            # --- Factor 2: Scope Priority (S) ---
            # 'required' = Direct (1.0)
            # 'optional' = Transitive (0.5)
            # None/Missing = Uncertainty Penalty (0.6)
            
            scope_val = getattr(comp, 'scope', None)
            
            if scope_val == 'required':
                scope_priority = 1.0
            elif scope_val == 'optional':
                scope_priority = 0.5
            else:
                scope_priority = 0.6
            
            # Final Average
            tcs_scores[comp.bom_ref] = (normalized_degree + scope_priority) / 2
        
        return tcs_scores
    
    def calculate_max_depth(self, dependencies: List[Dict]) -> int:
        """Max depth calculation using BFS"""
        G = nx.DiGraph()
        
        for dep in dependencies:
            ref = dep.get('ref')
            depends_on = dep.get('dependsOn', [])
            
            for target in depends_on:
                G.add_edge(ref, target)
        
        if len(G.nodes) == 0:
            return 0
        
        try:
            roots = [n for n in G.nodes if G.in_degree(n) == 0]
            if not roots:
                return 0
            
            max_depth = 0
            for root in roots:
                try:
                    depths = nx.single_source_shortest_path_length(G, root)
                    max_depth = max(max_depth, max(depths.values()) if depths else 0)
                except:
                    continue
            
            return max_depth
        except:
            return 0