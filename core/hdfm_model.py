from typing import Dict, List
import numpy as np
import pandas as pd

from core.entities import Priority, Vulnerability


class HDFMModel:
    """Hybrid Decision-Fusion Model v4.0"""
    
    @staticmethod
    def calculate_vei(cvss_vector: str) -> float:
        """Calculate Vector-based Exposure Index"""
        if not cvss_vector:
            return 0.5
        
        vector_map = {
        'AV:N': 0.85,  # Reduced from 1.0 to give other metrics breathing room
        'AV:A': 0.6,   # Reduced
        'AV:L': 0.3,
        'AV:P': 0.1,
        }
        
        for key, value in vector_map.items():
            if key in cvss_vector:
                return value
        
        return 0.5
    
    @staticmethod
    def calculate_exploitability_fusion(epss: float, kev: bool) -> float:
        """Exploitability Fusion: E = 1 - (1 - P_EPSS)(1 - P_KEV)"""
        p_kev = 1.0 if kev else 0.0
        return 1 - (1 - epss) * (1 - p_kev)
    
    @staticmethod
    def calculate_entropy_weights(metrics_df: pd.DataFrame) -> Dict[str, float]:
        """Shannon Entropy-based Dynamic Weighting"""
        m = len(metrics_df)
        
        if m <= 1:
            return {'severity': 0.25, 'tcs': 0.25, 'vei': 0.25, 'exploitability': 0.25}
        
        k = 1.0 / np.log(m)
        weights = {}
        
        for col in ['severity', 'tcs', 'vei', 'exploitability']:
            col_sum = metrics_df[col].sum()
            
            if col_sum == 0:
                weights[col] = 0
                continue
            
            p_ij = metrics_df[col] / col_sum
            p_ij_clean = p_ij[p_ij > 0]
            entropy = -k * np.sum(p_ij_clean * np.log(p_ij_clean))
            weights[col] = 1 - entropy
        
        total = sum(weights.values())
        
        if total == 0:
            return {'severity': 0.25, 'tcs': 0.25, 'vei': 0.25, 'exploitability': 0.25}
        
        return {k: v / total for k, v in weights.items()}
    
    @staticmethod
    def calculate_epss_median(vulnerabilities: List[Vulnerability]) -> float:
        """Phase 2: Calculate Dynamic Baseline (eta)"""
        epss_scores = [v.epss for v in vulnerabilities]
        if not epss_scores:
            return 0.0
        return float(np.median(epss_scores))

    @staticmethod
    def calculate_hdfm_score(vuln: Vulnerability, weights: Dict[str, float], eta: float) -> float:
        """
        Phase 3: Contextual Branching & Scoring
        Implements mutually exclusive decision tree from Algorithm 1
        """
        # 1. Base Weighted Score (Dot Product)
        base_score = (
            vuln.exploitability * weights.get('exploitability', 0.3) +
            vuln.severity * weights.get('severity', 0.3) +  # Represents Impact (I)
            vuln.vei * weights.get('vei', 0.1) +            # Represents Exposure (X)
            vuln.tcs * weights.get('tcs', 0.3)              # Represents Criticality (C)
        )

        # 2. Contextual Branching (Mutually Exclusive)
        # Branch A: Active Threat or Structural Criticality
        print(vuln.component_name, base_score)
        if (vuln.cvss_score >= 9.8 and (vuln.tcs >= 0.7 and vuln.exploitability >= 0.5)):
            final_score = base_score * 1.5
        # Branch A+: CVSS Critical & High Network Exposure
        # FIX: Changed (vei == 1.0) to (vei >= 0.85) to catch 'Network' vectors that aren't perfectly 1.0
        elif (vuln.cvss_score >= 9.0) and (vuln.vei >= 0.85) and vuln.tcs >= 0.5:
            final_score = base_score * 1.2

        # Branch B: Significant Exposure
        # FIX: Lowered threshold slightly to be inclusive of standard network vectors
        elif vuln.vei >= 0.8 and vuln.tcs >= 0.4:
            final_score = base_score * 1.0

        # Branch C: Latent / Local Risk
        else:
            final_score = base_score * 0.5
        return final_score

    @staticmethod
    def assign_priority(hdfm_score: float) -> Priority:
        if hdfm_score > 0.8:
            return Priority.CRITICAL
        elif hdfm_score > 0.5:
            return Priority.HIGH
        elif hdfm_score > 0.3:
            return Priority.MEDIUM
        else:
            return Priority.LOW
