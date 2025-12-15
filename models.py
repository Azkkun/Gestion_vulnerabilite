"""
models.py
=========
Définition des modèles de données, enums et dataclasses
"""

from abc import ABC, abstractmethod
from datetime import datetime
from enum import Enum
from typing import Dict
from dataclasses import dataclass
import uuid


class SeverityLevel(Enum):
    """Niveaux de sévérité des vulnérabilités"""
    CRITICAL = 10
    HIGH = 8
    MEDIUM = 5
    LOW = 3
    INFO = 1


class VulnerabilityType(Enum):
    """Types de vulnérabilités"""
    NETWORK = "network"
    DEPENDENCY = "dependency"
    FILE_SYSTEM = "file_system"
    CONFIGURATION = "configuration"
    CODE = "code"


@dataclass
class CVEData:
    """Données CVE simplifiées"""
    cve_id: str
    description: str
    severity: SeverityLevel
    cvss_score: float
    affected_systems: list[str]
    published_date: datetime
    last_modified: datetime


class Vulnerability(ABC):
    """Interface de base pour les vulnérabilités"""
    
    @abstractmethod
    def get_id(self) -> str:
        """Retourne l'identifiant unique"""
        pass
    
    @abstractmethod
    def get_description(self) -> str:
        """Retourne la description"""
        pass
    
    @abstractmethod
    def get_severity(self) -> SeverityLevel:
        """Retourne le niveau de sévérité"""
        pass
    
    @abstractmethod
    def get_score(self) -> float:
        """Retourne le score CVSS"""
        pass
    
    @abstractmethod
    def get_metadata(self) -> Dict:
        """Retourne toutes les métadonnées"""
        pass
    
    @abstractmethod
    def get_type(self) -> VulnerabilityType:
        """Retourne le type de vulnérabilité"""
        pass


class BaseVulnerability(Vulnerability):
    """Implémentation de base d'une vulnérabilité"""
    
    def __init__(self, cve_data: CVEData, vuln_type: VulnerabilityType):
        self._id = str(uuid.uuid4())
        self._cve_data = cve_data
        self._type = vuln_type
        self._discovered_at = datetime.now()
        self._metadata: Dict = {}
    
    def get_id(self) -> str:
        return self._id
    
    def get_description(self) -> str:
        return self._cve_data.description
    
    def get_severity(self) -> SeverityLevel:
        return self._cve_data.severity
    
    def get_score(self) -> float:
        return self._cve_data.cvss_score
    
    def get_type(self) -> VulnerabilityType:
        return self._type
    
    def get_metadata(self) -> Dict:
        return {
            "id": self._id,
            "cve_id": self._cve_data.cve_id,
            "type": self._type.value,
            "severity": self._cve_data.severity.name,
            "score": self._cve_data.cvss_score,
            "discovered_at": self._discovered_at.isoformat(),
            "description": self._cve_data.description,
            **self._metadata
        }