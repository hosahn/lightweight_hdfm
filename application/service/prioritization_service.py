from datetime import datetime
from typing import Dict, List

import numpy as np
import pandas as pd
from core.entities import AnalysisResult, Component, Priority, Vulnerability
from core.hdfm_model import HDFMModel
from core.interface import IGraphAnalyzer, IRepository, IThreatIntelligence


class PrioritizationService:
    """Use Case: Orchestrate the HDFM analysis pipeline"""
    
    def __init__(
        self,
        graph_analyzer: IGraphAnalyzer,
        threat_intel: IThreatIntelligence,
        repository: IRepository
    ):
        self.graph_analyzer = graph_analyzer
        self.threat_intel = threat_intel
        self.repository = repository
        self.hdfm = HDFMModel()
    
    def analyze(self, sbom_id: str, components: List[Component], dependencies: List[Dict]) -> AnalysisResult:
        """Execute complete HDFM analysis pipeline"""
        try:
        # Step 1: Calculate TCS
            tcs_scores = self.graph_analyzer.calculate_tcs(components, dependencies)
            
            # Step 2: Collect all vulnerabilities
            all_vulns = []
            for comp in components:
                if comp.vulnerabilities:
                    for vuln in comp.vulnerabilities:
                        vuln.tcs = tcs_scores.get(comp.bom_ref, 0.0)
                        vuln.vei = self.hdfm.calculate_vei(vuln.cvss_vector)
                        vuln.epss = self.threat_intel.get_epss_score(vuln.id)
                        vuln.kev = self.threat_intel.is_kev(vuln.id)
                        vuln.exploitability = self.hdfm.calculate_exploitability_fusion(vuln.epss, vuln.kev)
                        all_vulns.append(vuln)
                else :
                    status = "DEPRECATED" if getattr(comp, 'is_deprecated', False) else "HEALTHY"
                    dummy_vuln = Vulnerability(
                        id=status,
                        component_name=comp.name,
                        description=f"Component is {status.lower()}",
                        cvss_score=0.0,
                        cvss_vector="",
                        severity="INFO",
                        component_ref=comp.bom_ref,
                    )
                    all_vulns.append(dummy_vuln)
                    comp.vulnerabilities = [dummy_vuln]
            
            
            if not all_vulns:
                result = AnalysisResult(
                    sbom_id=sbom_id,
                    timestamp=datetime.now(),
                    total_components=len(components),
                    total_vulnerabilities=0,
                    critical_findings=0,
                    hub_components=len([s for s in tcs_scores.values() if s > 0.7]),
                    max_depth=self.graph_analyzer.calculate_max_depth(dependencies),
                    vulnerabilities=[],
                    entropy_weights={}
                )
                self.repository.save_analysis(sbom_id, result)
                return result
            
            # Step 3: Calculate entropy-based weights
            metrics_df = pd.DataFrame([{
                'severity': v.severity,
                'tcs': v.tcs,
                'vei': v.vei,
                'exploitability': v.exploitability
            } for v in all_vulns])
            
            weights = self.hdfm.calculate_entropy_weights(metrics_df)
            
            # Step 4: Calculate Dynamic Baseline (Eta)
            eta = self.hdfm.calculate_epss_median(all_vulns)
            
            # Step 5: Calculate Raw HDFM Scores (Phase 3)
            for vuln in all_vulns:
                # Pass eta to strict scoring function
                vuln.hdfm_score = self.hdfm.calculate_hdfm_score(vuln, weights, eta)
                # Clip score to 1.0 max just in case
                vuln.hdfm_score = min(vuln.hdfm_score, 1.0)

            if all_vulns:
                max_vuln_map = {}
                for vuln in all_vulns:
                    current_best = max_vuln_map.get(vuln.component_name)
                    
                    if current_best is None:
                        # First time seeing this component
                        max_vuln_map[vuln.component_name] = vuln
                    else:
                        if vuln.hdfm_score > current_best.hdfm_score:
                            max_vuln_map[vuln.component_name] = vuln
                
                # 2. Replace the original list with just the winners
                all_vulns = list(max_vuln_map.values())
            # Step 6: Quantile Ranking (Phase 4)
            if all_vulns:
                # Sort by score descending
                all_vulns.sort(key=lambda v: v.hdfm_score, reverse=True)
                # 1. Filter out zero scores for threshold calculation
                #    We only want to benchmark "risky" items against other "risky" items.
                risky_scores = [v.hdfm_score for v in all_vulns if v.hdfm_score > 0.0]
                
                if not risky_scores:
                    # Fallback: If 100% of items are healthy, set standard static thresholds
                    tau_crit = 9.0
                    tau_high = 7.0
                else:
                    # Calculate dynamic thresholds on RISK population only
                    p90 = np.percentile(risky_scores, 90) # Top 10% of risks
                    p70 = np.percentile(risky_scores, 70) # Top 30% of risks
                    
                    # 2. Enforce Static Floors (Crucial Fix)
                    #    Even if the top 10% of risks are only score 3.0, do NOT mark them Critical.
                    #    "Critical" implies a score of at least 7.0 (adjustable to your preference).
                    tau_crit = max(p90, 7.0) 
                    tau_high = max(p70, 4.0)
                print(all_vulns)
                # Assign Priorities based on Distribution
                for vuln in all_vulns:
                    # 3. Explicitly handle healthy items first
                    if (vuln.hdfm_score * 10) <= 0.0:
                        vuln.priority = Priority.LOW
                    elif (vuln.hdfm_score * 10) >= tau_crit:
                        vuln.priority = Priority.CRITICAL
                    elif (vuln.hdfm_score * 10) >= tau_high:
                        vuln.priority = Priority.HIGH
                    else:
                        # Anything positive but below High threshold is Medium
                        vuln.priority = Priority.MEDIUM
            # Step 5: Create and persist result
            result = AnalysisResult(
                sbom_id=sbom_id,
                timestamp=datetime.now(),
                total_components=len(components),
                total_vulnerabilities=len(all_vulns),
                critical_findings=len([v for v in all_vulns if v.priority == Priority.CRITICAL]),
                hub_components=len([s for s in tcs_scores.values() if s > 0.7]),
                max_depth=self.graph_analyzer.calculate_max_depth(dependencies),
                vulnerabilities=all_vulns,
                entropy_weights=weights
            )
            
            self.repository.save_analysis(sbom_id, result)
            
            return result
        except Exception as e:
            print(e)