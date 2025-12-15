"""
system.py
=========
Système principal de gestion des vulnérabilités
"""

from typing import Optional, Dict
from models import Vulnerability, SeverityLevel
from database import VulnerabilityDatabase
from scanner import VulnerabilityScanner
from analyzers import NetworkAnalyzer, DependencyAnalyzer, FileSystemAnalyzer
from reports import ReportGenerator


class VulnerabilityManagementSystem:
    """Système principal de gestion des vulnérabilités"""
    
    def __init__(self):
        self._db = VulnerabilityDatabase()
        self._scanner = VulnerabilityScanner()
        self._report_generator = ReportGenerator()
    
    def scan_target(self, target: str, analysis_type: Optional[str] = None) -> None:
        """Scanne une cible avec un type d'analyse spécifique ou complet"""
        print(f"\n{'='*80}")
        print(f" DÉMARRAGE DU SCAN: {target}")
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
            print(" Mode: Scan complet (toutes les stratégies)")
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
    
    def get_critical_vulnerabilities(self) -> list[Vulnerability]:
        """Retourne les vulnérabilités critiques"""
        return self._db.get_vulnerabilities_by_severity(SeverityLevel.CRITICAL)
