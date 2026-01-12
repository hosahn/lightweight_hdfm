class HDFMException(Exception):
    """Base exception for HDFM domain"""
    pass


class InvalidSBOMException(HDFMException):
    """Raised when SBOM data is invalid"""
    pass


class AnalysisException(HDFMException):
    """Raised when analysis fails"""
    pass
