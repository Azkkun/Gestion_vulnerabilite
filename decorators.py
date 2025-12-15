"""
decorators.py
=============
Implémentation du pattern Decorator pour enrichir les vulnérabilités
"""

from typing import Dict
from models import Vulnerability, SeverityLevel, VulnerabilityType


class VulnerabilityDecorator(Vulnerability):
    """Décorateur de base pour enrichir les vulnérabilités"""
    
    def __init__(self, vulnerability: Vulnerability):
        self._vulnerability = vulnerability
    
    def get_id(self) -> str:
        return self._vulnerability.get_id()
    
    def get_description(self) -> str:
        return self._vulnerability.get_description()
    
    def get_severity(self) -> SeverityLevel:
        return self._vulnerability.get_severity()
    
    def get_score(self) -> float:
        return self._vulnerability.get_score()
    
    def get_type(self) -> VulnerabilityType:
        return self._vulnerability.get_type()
    
    def get_metadata(self) -> Dict:
        return self._vulnerability.get_metadata()


class RemediationDecorator(VulnerabilityDecorator):
    """Ajoute des informations de remédiation (contre-mesures)"""
    
    def __init__(self, vulnerability: Vulnerability, remediation: str, 
                 estimated_time: str, priority: str):
        super().__init__(vulnerability)
        self._remediation = remediation
        self._estimated_time = estimated_time
        self._priority = priority
    
    def get_metadata(self) -> Dict:
        metadata = super().get_metadata()
        metadata.update({
            "remediation": self._remediation,
            "estimated_remediation_time": self._estimated_time,
            "remediation_priority": self._priority
        })
        return metadata


class ExploitabilityDecorator(VulnerabilityDecorator):
    """Ajoute des informations d'exploitabilité et recalcule le score"""
    
    def __init__(self, vulnerability: Vulnerability, exploit_available: bool,
                 exploit_complexity: str, public_exploit: bool = False):
        super().__init__(vulnerability)
        self._exploit_available = exploit_available
        self._exploit_complexity = exploit_complexity
        self._public_exploit = public_exploit
    
    def get_score(self) -> float:
        """Recalcule automatiquement le score selon l'exploitabilité"""
        base_score = super().get_score()
        
        if self._exploit_available:
            base_score *= 1.2
        
        if self._public_exploit:
            base_score *= 1.3
        
        if self._exploit_complexity == "Low":
            base_score *= 1.1
        
        return min(10.0, base_score)
    
    def get_metadata(self) -> Dict:
        metadata = super().get_metadata()
        metadata.update({
            "exploit_available": self._exploit_available,
            "exploit_complexity": self._exploit_complexity,
            "public_exploit": self._public_exploit,
            "base_score": super().get_score(),
            "adjusted_score": self.get_score()
        })
        return metadata


class ImpactDecorator(VulnerabilityDecorator):
    """Ajoute des informations d'impact métier"""
    
    def __init__(self, vulnerability: Vulnerability, business_impact: str,
                 affected_assets: list[str], data_exposure: bool = False):
        super().__init__(vulnerability)
        self._business_impact = business_impact
        self._affected_assets = affected_assets
        self._data_exposure = data_exposure
    
    def get_metadata(self) -> Dict:
        metadata = super().get_metadata()
        metadata.update({
            "business_impact": self._business_impact,
            "affected_assets": self._affected_assets,
            "asset_count": len(self._affected_assets),
            "data_exposure_risk": self._data_exposure
        })
        return metadata


class SourceDecorator(VulnerabilityDecorator):
    """Ajoute des informations sur la source de détection"""
    
    def __init__(self, vulnerability: Vulnerability, source: str,
                 detection_method: str, confidence: float):
        super().__init__(vulnerability)
        self._source = source
        self._detection_method = detection_method
        self._confidence = confidence
    
    def get_metadata(self) -> Dict:
        metadata = super().get_metadata()
        metadata.update({
            "detection_source": self._source,
            "detection_method": self._detection_method,
            "confidence_level": f"{self._confidence * 100}%"
        })
        return metadata