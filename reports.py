"""
reports.py
==========
Générateur de rapports de sécurité
"""

from datetime import datetime
from models import SeverityLevel
from database import VulnerabilityDatabase


class ReportGenerator:
    """Générateur de rapports de sécurité"""
    
    def __init__(self):
        self._db = VulnerabilityDatabase()
    
    def generate_summary_report(self) -> str:
        """Génère un rapport résumé"""
        stats = self._db.get_statistics()
        
        report = []
        report.append("\n" + "="*80)
        report.append(" RAPPORT DE SÉCURITÉ - RÉSUMÉ")
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
        report.append(" RAPPORT DE SÉCURITÉ - DÉTAILS DES VULNÉRABILITÉS")
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
            report.append(f"Sévérité: {vuln.get_severity().name} ")
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
                    report.append(f"    Exploit PUBLIC disponible!")
            
            if "business_impact" in metadata:
                report.append(f"\nImpact:")
                report.append(f"  {metadata['business_impact']}")
                report.append(f"  Assets affectés ({metadata['asset_count']}): {', '.join(metadata['affected_assets'])}")
                if metadata.get('data_exposure_risk'):
                    report.append(f"    Risque d'exposition de données!")
            
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
        
        print(f" Rapport sauvegardé: {filename}")
