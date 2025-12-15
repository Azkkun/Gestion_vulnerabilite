"""
Système de Gestion de Vulnérabilités (mini SIEM)
================================================
Architecture basée sur les design patterns:
- Strategy: Différents types d'analyseurs
- Singleton: Base de données centralisée
- Decorator: Enrichissement des vulnérabilités
"""

from abc import ABC, abstractmethod
from datetime import datetime
from enum import Enum
from typing import List, Dict, Optional
from dataclasses import dataclass
import uuid


# ============================================================================
# ENUMS ET DATACLASSES
# ============================================================================

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
    affected_systems: List[str]
    published_date: datetime
    last_modified: datetime


# ============================================================================
# PATTERN DECORATOR - Enrichissement des vulnérabilités
# ============================================================================

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
        
        # Augmente le score si un exploit est disponible
        if self._exploit_available:
            base_score *= 1.2
        
        # Augmente encore plus si l'exploit est public
        if self._public_exploit:
            base_score *= 1.3
        
        # Ajuste selon la complexité
        if self._exploit_complexity == "Low":
            base_score *= 1.1
        
        return min(10.0, base_score)  # Score max = 10
    
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
                 affected_assets: List[str], data_exposure: bool = False):
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


# ============================================================================
# PATTERN SINGLETON - Base de données
# ============================================================================

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
        print(f"  💾 Vulnérabilité ajoutée à la BDD: {vulnerability.get_id()}")
    
    def get_vulnerability(self, vuln_id: str) -> Optional[Vulnerability]:
        """Récupère une vulnérabilité par son ID"""
        return self._vulnerabilities.get(vuln_id)
    
    def get_all_vulnerabilities(self) -> List[Vulnerability]:
        """Récupère toutes les vulnérabilités"""
        return list(self._vulnerabilities.values())
    
    def get_vulnerabilities_by_severity(self, 
                                       severity: SeverityLevel) -> List[Vulnerability]:
        """Récupère les vulnérabilités par niveau de sévérité"""
        return [v for v in self._vulnerabilities.values() 
                if v.get_severity() == severity]
    
    def get_vulnerabilities_by_type(self, 
                                   vuln_type: VulnerabilityType) -> List[Vulnerability]:
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


# ============================================================================
# PATTERN STRATEGY - Analyseurs
# ============================================================================

class AnalysisStrategy(ABC):
    """Interface pour les stratégies d'analyse"""
    
    @abstractmethod
    def analyze(self, target: str) -> List[Vulnerability]:
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
    
    def analyze(self, target: str) -> List[Vulnerability]:
        """Simule une analyse réseau"""
        print(f"  🔍 Scan des ports et services...")
        print(f"  🔍 Test d'injection SQL...")
        print(f"  🔍 Test XSS...")
        
        vulnerabilities = []
        
        # Simulation: trouve une vulnérabilité SQL Injection
        cve_data = self._db.get_cve_data("CVE-2024-0001")
        if cve_data:
            # Crée la vulnérabilité de base
            vuln = BaseVulnerability(cve_data, VulnerabilityType.NETWORK)
            
            # Enrichit avec des décorateurs
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
        
        # Trouve aussi une XSS
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
    
    def analyze(self, target: str) -> List[Vulnerability]:
        """Simule une analyse de dépendances"""
        print(f"  📦 Analyse du fichier package.json...")
        print(f"  📦 Vérification des versions...")
        print(f"  📦 Consultation de la base CVE...")
        
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
    
    def analyze(self, target: str) -> List[Vulnerability]:
        """Simule une analyse du système de fichiers"""
        print(f"  📁 Scan des permissions de fichiers...")
        print(f"  📁 Recherche de fichiers sensibles...")
        print(f"  📁 Vérification des configurations...")
        
        vulnerabilities = []
        
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
        
        # Trouve aussi un problème de crypto
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


class VulnerabilityScanner:
    """
    Scanner utilisant différentes stratégies d'analyse (Pattern Strategy)
    Permet de changer dynamiquement le type d'analyse
    """
    
    def __init__(self):
        self._strategy: Optional[AnalysisStrategy] = None
        self._db = VulnerabilityDatabase()
    
    def set_strategy(self, strategy: AnalysisStrategy) -> None:
        """Définit la stratégie d'analyse (changement dynamique)"""
        self._strategy = strategy
        print(f"\n🔧 Stratégie d'analyse: {strategy.get_name()}")
    
    def scan(self, target: str) -> List[Vulnerability]:
        """Effectue un scan avec la stratégie actuelle"""
        if not self._strategy:
            raise ValueError("❌ Aucune stratégie d'analyse définie")
        
        print(f"🎯 Cible: {target}")
        vulnerabilities = self._strategy.analyze(target)
        
        # Ajoute les vulnérabilités à la base de données (Singleton)
        for vuln in vulnerabilities:
            self._db.add_vulnerability(vuln)
        
        print(f"✅ {len(vulnerabilities)} vulnérabilité(s) détectée(s)\n")
        return vulnerabilities
    
    def scan_all(self, target: str) -> List[Vulnerability]:
        """Effectue un scan complet avec toutes les stratégies"""
        all_vulnerabilities = []
        strategies = [
            NetworkAnalyzer(),
            DependencyAnalyzer(),
            FileSystemAnalyzer()
        ]
        
        for strategy in strategies:
            self.set_strategy(strategy)
            vulnerabilities = self.scan(target)
            all_vulnerabilities.extend(vulnerabilities)
        
        return all_vulnerabilities


# ============================================================================
# SYSTÈME DE RAPPORTS
# ============================================================================

class ReportGenerator:
    """Générateur de rapports de sécurité"""
    
    def __init__(self):
        self._db = VulnerabilityDatabase()
    
    def generate_summary_report(self) -> str:
        """Génère un rapport résumé"""
        stats = self._db.get_statistics()
        
        report = []
        report.append("\n" + "="*80)
        report.append("📊 RAPPORT DE SÉCURITÉ - RÉSUMÉ")
        report.append("="*80)
        report.append(f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        report.append(f"Total de vulnérabilités: {stats['total_vulnerabilities']}")
        report.append(f"Score moyen: {stats['average_score']}")
        report.append("")
        
        report.append("RÉPARTITION PAR SÉVÉRITÉ:")
        report.append("-" * 40)
        for severity, count in sorted(stats['by_severity'].items(), 
                                     key=lambda x: SeverityLevel[x[0]].value, 
                                     reverse=True):
            if count > 0:
                report.append(f"  {severity}: {count}")
        
        report.append("")
        report.append("RÉPARTITION PAR TYPE:")
        report.append("-" * 40)
        for vuln_type, count in stats['by_type'].items():
            if count > 0:
                report.append(f"  {vuln_type}: {count}")
        
        report.append("="*80)
        
        return "\n".join(report)
    
    def generate_detailed_report(self) -> str:
        """Génère un rapport détaillé"""
        vulnerabilities = self._db.get_all_vulnerabilities()
        
        report = []
        report.append("\n" + "="*80)
        report.append("📋 RAPPORT DE SÉCURITÉ - DÉTAILS DES VULNÉRABILITÉS")
        report.append("="*80)
        report.append(f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        report.append(f"Nombre total: {len(vulnerabilities)}")
        report.append("")
        
        # Trie par score décroissant
        sorted_vulns = sorted(vulnerabilities, 
                            key=lambda v: v.get_score(), 
                            reverse=True)
        
        for i, vuln in enumerate(sorted_vulns, 1):
            metadata = vuln.get_metadata()
            
            report.append(f"\n{'─'*80}")
            report.append(f"#{i} - {metadata.get('cve_id', 'N/A')}")
            report.append(f"{'─'*80}")
            report.append(f"ID: {vuln.get_id()}")
            report.append(f"Type: {metadata.get('type', 'N/A').upper()}")
            report.append(f"Sévérité: {vuln.get_severity().name} ⚠️")
            report.append(f"Score CVSS: {vuln.get_score():.2f}/10.0")
            
            if "base_score" in metadata:
                report.append(f"  (Score de base: {metadata['base_score']:.2f}, ajusté: {metadata['adjusted_score']:.2f})")
            
            report.append(f"\nDescription:")
            report.append(f"  {vuln.get_description()}")
            
            if "detection_source" in metadata:
                report.append(f"\nDétection:")
                report.append(f"  Source: {metadata['detection_source']}")
                report.append(f"  Méthode: {metadata['detection_method']}")
                report.append(f"  Confiance: {metadata['confidence_level']}")
            
            if "exploit_available" in metadata:
                report.append(f"\nExploitabilité:")
                report.append(f"  Exploit disponible: {'✓ OUI' if metadata['exploit_available'] else '✗ Non'}")
                report.append(f"  Complexité: {metadata['exploit_complexity']}")
                if metadata.get('public_exploit'):
                    report.append(f"  ⚠️  Exploit PUBLIC disponible!")
            
            if "business_impact" in metadata:
                report.append(f"\nImpact:")
                report.append(f"  {metadata['business_impact']}")
                report.append(f"  Assets affectés ({metadata['asset_count']}): {', '.join(metadata['affected_assets'])}")
                if metadata.get('data_exposure_risk'):
                    report.append(f"  ⚠️  Risque d'exposition de données!")
            
            if "remediation" in metadata:
                report.append(f"\nContre-mesures:")
                report.append(f"  {metadata['remediation']}")
                report.append(f"  Temps estimé: {metadata['estimated_remediation_time']}")
                report.append(f"  Priorité: {metadata['remediation_priority']}")
        
        report.append(f"\n{'='*80}\n")
        
        return "\n".join(report)
    
    def save_report(self, filename: str, detailed: bool = True) -> None:
        """Sauvegarde le rapport dans un fichier"""
        content = self.generate_detailed_report() if detailed else self.generate_summary_report()
        
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(content)
        
        print(f"💾 Rapport sauvegardé: {filename}")


# ============================================================================
# SYSTÈME PRINCIPAL
# ============================================================================

class VulnerabilityManagementSystem:
    """Système principal de gestion des vulnérabilités"""
    
    def __init__(self):
        self._db = VulnerabilityDatabase()
        self._scanner = VulnerabilityScanner()
        self._report_generator = ReportGenerator()
    
    def scan_target(self, target: str, analysis_type: Optional[str] = None) -> None:
        """Scanne une cible avec un type d'analyse spécifique ou complet"""
        print(f"\n{'='*80}")
        print(f"🚀 DÉMARRAGE DU SCAN: {target}")
        print(f"{'='*80}")
        
        if analysis_type == "network":
            self._scanner.set_strategy(NetworkAnalyzer())
            self._scanner.scan(target)
        elif analysis_type == "dependency":
            self._scanner.set_strategy(DependencyAnalyzer())
            self._scanner.scan(target)
        elif analysis_type == "filesystem":
            self._scanner.set_strategy(FileSystemAnalyzer())
            self._scanner.scan(target)
        else:
            # Scan complet avec toutes les stratégies
            print("📋 Mode: Scan complet (toutes les stratégies)")
            self._scanner.scan_all(target)
    
    def generate_report(self, filename: str = "security_report.txt", 
                       detailed: bool = True) -> None:
        """Génère et affiche le rapport"""
        if detailed:
            print(self._report_generator.generate_detailed_report())
        else:
            print(self._report_generator.generate_summary_report())
        
        self._report_generator.save_report(filename, detailed)
    
    def get_statistics(self) -> Dict:
        """Retourne les statistiques"""
        return self._db.get_statistics()
    
    def get_critical_vulnerabilities(self) -> List[Vulnerability]:
        """Retourne les vulnérabilités critiques"""
        return self._db.get_vulnerabilities_by_severity(SeverityLevel.CRITICAL)


# ============================================================================
# DÉMONSTRATION
# ============================================================================

def main():
    
    # Initialisation du système
    system = VulnerabilityManagementSystem()
    
    system.scan_target("webapp.example.com", "network")
    
    system.scan_target("api.example.com", "dependency")
    
    system.scan_target("/var/www/production", "filesystem")
    
    system.scan_target("production-server.example.com")
    
    # Affichage du rapport résumé
    print(system._report_generator.generate_summary_report())
    
    # Génération du rapport détaillé
    print("\n" + "="*80)
    print("📄 GÉNÉRATION DU RAPPORT DÉTAILLÉ")
    print("="*80)
    system.generate_report("vulnerability_report.txt", detailed=True)
    
    # Affichage des vulnérabilités critiques
    critical = system.get_critical_vulnerabilities()
    if critical:
        print(f"\n⚠️  ALERTE: {len(critical)} vulnérabilité(s) CRITIQUE(S) détectée(s)!")
        for vuln in critical:
            print(f"   • {vuln.get_id()} - Score: {vuln.get_score():.2f}")

if __name__ == "__main__":
    main()