"""
analyzers.py
============
Implémentation du pattern Strategy pour les différents types d'analyse
"""

from abc import ABC, abstractmethod
from models import Vulnerability, VulnerabilityType, BaseVulnerability
from decorators import (
    SourceDecorator, ExploitabilityDecorator, 
    ImpactDecorator, RemediationDecorator
)
from database import VulnerabilityDatabase


class AnalysisStrategy(ABC):
    """Interface pour les stratégies d'analyse"""
    
    @abstractmethod
    def analyze(self, target: str) -> list[Vulnerability]:
        """Effectue l'analyse et retourne les vulnérabilités trouvées"""
        pass
    
    @abstractmethod
    def get_analysis_type(self) -> VulnerabilityType:
        """Retourne le type d'analyse"""
        pass
    
    @abstractmethod
    def get_name(self) -> str:
        """Retourne le nom de l'analyseur"""
        pass


class NetworkAnalyzer(AnalysisStrategy):
    """
    Analyseur de vulnérabilités réseau
    Simule un scan de ports, détection d'injections SQL, XSS, etc.
    """
    
    def __init__(self):
        self._db = VulnerabilityDatabase()
    
    def analyze(self, target: str) -> list[Vulnerability]:
        """Simule une analyse réseau"""
        print(f"   Scan des ports et services...")
        print(f"   Test d'injection SQL...")
        print(f"   Test XSS...")
        
        vulnerabilities = []
        
        # SQL Injection
        cve_data = self._db.get_cve_data("CVE-2024-0001")
        if cve_data:
            vuln = BaseVulnerability(cve_data, VulnerabilityType.NETWORK)
            
            vuln = SourceDecorator(
                vuln,
                source="Network Scanner",
                detection_method="SQL Injection Test",
                confidence=0.95
            )
            
            vuln = ExploitabilityDecorator(
                vuln,
                exploit_available=True,
                exploit_complexity="Low",
                public_exploit=True
            )
            
            vuln = ImpactDecorator(
                vuln,
                business_impact="CRITIQUE - Accès complet à la base de données",
                affected_assets=[target, "Database Server", "User Data"],
                data_exposure=True
            )
            
            vuln = RemediationDecorator(
                vuln,
                remediation="Implémenter des requêtes paramétrées (Prepared Statements)",
                estimated_time="2-4 heures",
                priority="URGENT"
            )
            
            vulnerabilities.append(vuln)
        
        # XSS
        cve_data = self._db.get_cve_data("CVE-2024-0004")
        if cve_data:
            vuln = BaseVulnerability(cve_data, VulnerabilityType.NETWORK)
            
            vuln = SourceDecorator(
                vuln,
                source="Network Scanner",
                detection_method="XSS Payload Injection",
                confidence=0.88
            )
            
            vuln = ExploitabilityDecorator(
                vuln,
                exploit_available=True,
                exploit_complexity="Medium",
                public_exploit=False
            )
            
            vuln = ImpactDecorator(
                vuln,
                business_impact="ÉLEVÉ - Vol de sessions utilisateurs",
                affected_assets=[target, "User Sessions"],
                data_exposure=True
            )
            
            vuln = RemediationDecorator(
                vuln,
                remediation="Sanitiser les entrées utilisateur et encoder les sorties",
                estimated_time="1-2 heures",
                priority="HAUTE"
            )
            
            vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    def get_analysis_type(self) -> VulnerabilityType:
        return VulnerabilityType.NETWORK
    
    def get_name(self) -> str:
        return "Network Security Analyzer"


class DependencyAnalyzer(AnalysisStrategy):
    """
    Analyseur de dépendances
    Simule un scan de packages npm, pip, maven, etc.
    """
    
    def __init__(self):
        self._db = VulnerabilityDatabase()
    
    def analyze(self, target: str) -> list[Vulnerability]:
        """Simule une analyse de dépendances"""
        print(f"   Analyse du fichier package.json...")
        print(f"   Vérification des versions...")
        print(f"   Consultation de la base CVE...")
        
        vulnerabilities = []
        
        cve_data = self._db.get_cve_data("CVE-2024-0002")
        if cve_data:
            vuln = BaseVulnerability(cve_data, VulnerabilityType.DEPENDENCY)
            
            vuln = SourceDecorator(
                vuln,
                source="Dependency Scanner",
                detection_method="Version Matching",
                confidence=1.0
            )
            
            vuln = ExploitabilityDecorator(
                vuln,
                exploit_available=True,
                exploit_complexity="Medium",
                public_exploit=True
            )
            
            vuln = ImpactDecorator(
                vuln,
                business_impact="ÉLEVÉ - Exécution de code à distance possible",
                affected_assets=[target, "Application Server", "Log System"],
                data_exposure=False
            )
            
            vuln = RemediationDecorator(
                vuln,
                remediation="Mettre à jour Log4j vers la version 2.17.1 ou supérieure",
                estimated_time="30 minutes",
                priority="HAUTE"
            )
            
            vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    def get_analysis_type(self) -> VulnerabilityType:
        return VulnerabilityType.DEPENDENCY
    
    def get_name(self) -> str:
        return "Dependency Vulnerability Scanner"


class FileSystemAnalyzer(AnalysisStrategy):
    """
    Analyseur du système de fichiers
    Simule un scan de permissions, fichiers sensibles, etc.
    """
    
    def __init__(self):
        self._db = VulnerabilityDatabase()
    
    def analyze(self, target: str) -> list[Vulnerability]:
        """Simule une analyse du système de fichiers"""
        print(f"   Scan des permissions de fichiers...")
        print(f"   Recherche de fichiers sensibles...")
        print(f"   Vérification des configurations...")
        
        vulnerabilities = []
        
        # Permissions
        cve_data = self._db.get_cve_data("CVE-2024-0003")
        if cve_data:
            vuln = BaseVulnerability(cve_data, VulnerabilityType.FILE_SYSTEM)
            
            vuln = SourceDecorator(
                vuln,
                source="File System Scanner",
                detection_method="Permission Analysis",
                confidence=1.0
            )
            
            vuln = ExploitabilityDecorator(
                vuln,
                exploit_available=False,
                exploit_complexity="High",
                public_exploit=False
            )
            
            vuln = ImpactDecorator(
                vuln,
                business_impact="MOYEN - Accès non autorisé aux fichiers de configuration",
                affected_assets=[target, "/etc/config", "/var/secrets"],
                data_exposure=True
            )
            
            vuln = RemediationDecorator(
                vuln,
                remediation="Appliquer les permissions correctes (chmod 600 pour les fichiers sensibles)",
                estimated_time="15 minutes",
                priority="MOYENNE"
            )
            
            vulnerabilities.append(vuln)
        
        # Cryptographie faible
        cve_data = self._db.get_cve_data("CVE-2024-0005")
        if cve_data:
            vuln = BaseVulnerability(cve_data, VulnerabilityType.FILE_SYSTEM)
            
            vuln = SourceDecorator(
                vuln,
                source="File System Scanner",
                detection_method="Configuration File Analysis",
                confidence=0.92
            )
            
            vuln = ExploitabilityDecorator(
                vuln,
                exploit_available=True,
                exploit_complexity="Low",
                public_exploit=False
            )
            
            vuln = ImpactDecorator(
                vuln,
                business_impact="CRITIQUE - Mots de passe facilement déchiffrables",
                affected_assets=[target, "User Database", "Authentication System"],
                data_exposure=True
            )
            
            vuln = RemediationDecorator(
                vuln,
                remediation="Migrer vers bcrypt ou Argon2 pour le hachage des mots de passe",
                estimated_time="4-6 heures",
                priority="URGENT"
            )
            
            vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    def get_analysis_type(self) -> VulnerabilityType:
        return VulnerabilityType.FILE_SYSTEM
    
    def get_name(self) -> str:
        return "File System Security Analyzer"
