# TODO

class HDFMException(Exception):
    def __init__(self, message: str, error_code: str = "HDFM-GENERIC"):
        self.message = message
        self.error_code = error_code
        super().__init__(self.message)

    def __str__(self):
        return f"[{self.error_code}] {self.message}"


class InvalidSBOMException(HDFMException):
    def __init__(self, missing_field: str = None, reason: str = "Format not recognized"):
        self.missing_field = missing_field
        if missing_field:
            msg = f"SBOM validation failed: Missing required field '{missing_field}'"
        else:
            msg = f"SBOM validation failed: {reason}"
        
        super().__init__(msg, error_code="HDFM-SBOM-001")



class AnalysisException(HDFMException):
    def __init__(self, phase: str, details: str, cve_id: str = None):
        self.phase = phase
        self.cve_id = cve_id
        msg = f"Failure during {phase}: {details}"
        if cve_id:
            msg += f" (Impacted CVE: {cve_id})"
            
        super().__init__(msg, error_code="HDFM-MATH-ERR")
