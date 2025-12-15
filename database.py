"""
database.py
===========
Implémentation du pattern Singleton pour la base de données
"""

from typing import Optional, Dict
from datetime import datetime
from models import Vulnerability, SeverityLevel, VulnerabilityType, CVEData


class VulnerabilityDatabase:
    """
    Singleton pour la base de données de vulnérabilités
    Garantit une instance unique partagée dans toute l'application
    """
    
    _instance: Optional['VulnerabilityDatabase'] = None
    _initialized: bool = False
    
    def __new__(cls):
        """Contrôle la création d'instance (une seule instance possible)"""
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance
    
    def __init__(self):
        """Initialise la base une seule fois"""
        if not VulnerabilityDatabase._initialized:
            self._vulnerabilities: Dict[str, Vulnerability] = {}
            self._cve_database: Dict[str, CVEData] = {}
            self._initialize_cve_database()
            VulnerabilityDatabase._initialized = True
            print("✅ Base de données initialisée (Singleton)")
    
    def _initialize_cve_database(self):
        """Initialise la base CVE avec des données d'exemple"""
        sample_cves = [
            CVEData(
                cve_id="CVE-2024-0001",
                description="SQL Injection in authentication module",
                severity=SeverityLevel.CRITICAL,
                cvss_score=9.8,
                affected_systems=["Web Application", "Database"],
                published_date=datetime(2024, 1, 15),
                last_modified=datetime(2024, 1, 20)
            ),
            CVEData(
                cve_id="CVE-2024-0002",
                description="Outdated dependency with known vulnerabilities (Log4j)",
                severity=SeverityLevel.HIGH,
                cvss_score=7.5,
                affected_systems=["Java Applications", "Apache Log4j"],
                published_date=datetime(2024, 2, 10),
                last_modified=datetime(2024, 2, 15)
            ),
            CVEData(
                cve_id="CVE-2024-0003",
                description="Insecure file permissions allowing unauthorized access",
                severity=SeverityLevel.MEDIUM,
                cvss_score=5.3,
                affected_systems=["Linux", "File System"],
                published_date=datetime(2024, 3, 5),
                last_modified=datetime(2024, 3, 10)
            ),
            CVEData(
                cve_id="CVE-2024-0004",
                description="Cross-Site Scripting (XSS) in user input fields",
                severity=SeverityLevel.HIGH,
                cvss_score=7.2,
                affected_systems=["Web Application", "Frontend"],
                published_date=datetime(2024, 4, 1),
                last_modified=datetime(2024, 4, 5)
            ),
            CVEData(
                cve_id="CVE-2024-0005",
                description="Weak cryptographic algorithm in password storage",
                severity=SeverityLevel.CRITICAL,
                cvss_score=9.1,
                affected_systems=["Authentication System", "Database"],
                published_date=datetime(2024, 5, 12),
                last_modified=datetime(2024, 5, 15)
            )
        ]
        
        for cve in sample_cves:
            self._cve_database[cve.cve_id] = cve
    
    def add_vulnerability(self, vulnerability: Vulnerability) -> None:
        """Ajoute une vulnérabilité à la base"""
        self._vulnerabilities[vulnerability.get_id()] = vulnerability
        print(f"  Vulnérabilité ajoutée à la BDD: {vulnerability.get_id()}")
    
    def get_vulnerability(self, vuln_id: str) -> Optional[Vulnerability]:
        """Récupère une vulnérabilité par son ID"""
        return self._vulnerabilities.get(vuln_id)
    
    def get_all_vulnerabilities(self) -> list[Vulnerability]:
        """Récupère toutes les vulnérabilités"""
        return list(self._vulnerabilities.values())
    
    def get_vulnerabilities_by_severity(self, 
                                       severity: SeverityLevel) -> list[Vulnerability]:
        """Récupère les vulnérabilités par niveau de sévérité"""
        return [v for v in self._vulnerabilities.values() 
                if v.get_severity() == severity]
    
    def get_vulnerabilities_by_type(self, 
                                   vuln_type: VulnerabilityType) -> list[Vulnerability]:
        """Récupère les vulnérabilités par type"""
        return [v for v in self._vulnerabilities.values() 
                if v.get_type() == vuln_type]
    
    def get_cve_data(self, cve_id: str) -> Optional[CVEData]:
        """Récupère les données CVE"""
        return self._cve_database.get(cve_id)
    
    def get_statistics(self) -> Dict:
        """Calcule les statistiques de la base"""
        total = len(self._vulnerabilities)
        by_severity = {}
        by_type = {}
        
        for severity in SeverityLevel:
            count = len(self.get_vulnerabilities_by_severity(severity))
            by_severity[severity.name] = count
        
        for vuln_type in VulnerabilityType:
            count = len(self.get_vulnerabilities_by_type(vuln_type))
            by_type[vuln_type.value] = count
        
        avg_score = sum(v.get_score() for v in self._vulnerabilities.values()) / total if total > 0 else 0
        
        return {
            "total_vulnerabilities": total,
            "by_severity": by_severity,
            "by_type": by_type,
            "average_score": round(avg_score, 2)
        }
    
    def clear(self) -> None:
        """Vide la base de vulnérabilités (garde les CVE)"""
        self._vulnerabilities.clear()
