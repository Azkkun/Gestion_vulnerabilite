"""
scanner.py
==========
Scanner de vulnérabilités 
"""

from typing import Optional
from models import Vulnerability
from analyzers import AnalysisStrategy, NetworkAnalyzer, DependencyAnalyzer, FileSystemAnalyzer
from database import VulnerabilityDatabase


class VulnerabilityScanner:
    
    def __init__(self):
        self._strategy: Optional[AnalysisStrategy] = None
        self._db = VulnerabilityDatabase()
    
    def set_strategy(self, strategy: AnalysisStrategy) -> None:
        """Définit la stratégie d'analyse (changement dynamique)"""
        self._strategy = strategy
        print(f"\n Stratégie d'analyse: {strategy.get_name()}")
    
    def scan(self, target: str) -> list[Vulnerability]:
        """Effectue un scan avec la stratégie actuelle"""
        if not self._strategy:
            raise ValueError(" Aucune stratégie d'analyse définie")
        
        print(f" Cible: {target}")
        vulnerabilities = self._strategy.analyze(target)
        
        # Ajoute les vulnérabilités à la base de données (Singleton)
        for vuln in vulnerabilities:
            self._db.add_vulnerability(vuln)
        
        print(f" {len(vulnerabilities)} vulnérabilité(s) détectée(s)\n")
        return vulnerabilities
    
    def scan_all(self, target: str) -> list[Vulnerability]:
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
