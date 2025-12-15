"""
main.py
=======
Point d'entrée de l'application - Démonstration du système
"""

from system import VulnerabilityManagementSystem


def main():
    """Fonction principale de démonstration"""
    
    # Initialisation du système
    system = VulnerabilityManagementSystem()
    
    # Scan réseau
    system.scan_target("webapp.example.com", "network")
    
    # Scan des dépendances
    system.scan_target("api.example.com", "dependency")
    
    # Scan du système de fichiers
    system.scan_target("/var/www/production", "filesystem")
    
    # Scan complet
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