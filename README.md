# 🛡️ SIEM - POO - 2025

[![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Design Patterns](https://img.shields.io/badge/Design%20Patterns-3-orange.svg)](https://refactoring.guru/design-patterns)

## 📋 Table des matières

- [Vue d'ensemble](#-vue-densemble)
- [Design Patterns](#-design-patterns)
- [Installation](#-installation)
- [Utilisation](#-utilisation)
- [Fonctionnalités](#-fonctionnalités)



## 🎯 Vue d'ensemble

Ce projet implémente un **système de gestion de vulnérabilités** (mini SIEM) permettant de :
- 🔍 Scanner différents types de cibles (réseau, dépendances, système de fichiers)
- 💾 Stocker les vulnérabilités dans une base de données centralisée
- 📊 Enrichir les vulnérabilités avec des métadonnées (remédiation, exploitabilité, impact)
- 📈 Recalculer automatiquement les scores de sévérité
- 📄 Générer des rapports de sécurité détaillés

### Objectifs pédagogiques

✅ Appliquer les **design patterns** classiques  
✅ Respecter les principes **SOLID**  
✅ Utiliser les bonnes pratiques Python (type hints, ABC, dataclasses)  
✅ Créer une architecture **modulaire et extensible**

## 🎨 Design Patterns

Le projet implémente **3 design patterns** majeurs :

### 1. 🔄 Strategy Pattern (Analyseurs)

**Problème résolu** : Permettre de changer dynamiquement l'algorithme d'analyse sans modifier le code client.

```python
# Interface commune
class AnalysisStrategy(ABC):
    @abstractmethod
    def analyze(self, target: str) -> List[Vulnerability]:
        pass

# Stratégies concrètes
class NetworkAnalyzer(AnalysisStrategy):
    def analyze(self, target: str):
        # Scan réseau (SQL injection, XSS, etc.)
        ...

class DependencyAnalyzer(AnalysisStrategy):
    def analyze(self, target: str):
        # Scan de dépendances (npm, pip, maven)
        ...

class FileSystemAnalyzer(AnalysisStrategy):
    def analyze(self, target: str):
        # Scan du système de fichiers
        ...

# Utilisation
scanner = VulnerabilityScanner()
scanner.set_strategy(NetworkAnalyzer())  # Changement dynamique
scanner.scan("webapp.example.com")
```

**Avantages** :
- ✅ Ajout facile de nouveaux types d'analyseurs
- ✅ Séparation des responsabilités
- ✅ Testabilité accrue

### 2. 🔒 Singleton Pattern (Base de données)

**Problème résolu** : Garantir une seule instance de la base de données partagée dans toute l'application.

```python
class VulnerabilityDatabase:
    _instance = None
    _initialized = False
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance
    
    def __init__(self):
        if not VulnerabilityDatabase._initialized:
            self._vulnerabilities = {}
            self._cve_database = {}
            VulnerabilityDatabase._initialized = True

# Utilisation
db1 = VulnerabilityDatabase()
db2 = VulnerabilityDatabase()
assert db1 is db2  # Même instance !
```

**Avantages** :
- ✅ Cohérence des données
- ✅ Point d'accès global
- ✅ Économie de ressources

### 3. 🎁 Decorator Pattern (Enrichissement)

**Problème résolu** : Ajouter dynamiquement des fonctionnalités aux vulnérabilités sans modifier leur classe de base.

```python
# Vulnérabilité de base
vuln = BaseVulnerability(cve_data, VulnerabilityType.NETWORK)

# Enrichissement progressif avec des décorateurs
vuln = SourceDecorator(vuln, source="Network Scanner", ...)
vuln = ExploitabilityDecorator(vuln, exploit_available=True, ...)
vuln = ImpactDecorator(vuln, business_impact="CRITIQUE", ...)
vuln = RemediationDecorator(vuln, remediation="Fix SQL injection", ...)

# Le score est recalculé automatiquement !
print(vuln.get_score())  # Score ajusté selon l'exploitabilité
```

**Avantages** :
- ✅ Composition flexible
- ✅ Respect du principe Open/Closed
- ✅ Recalcul automatique des scores


## 🚀 Installation

### Prérequis

- Python 3.8 ou supérieur
- Aucune dépendance externe (utilise uniquement la bibliothèque standard)

### Installation

```bash
# Cloner le projet
git clone https://github.com/votre-equipe/vulnerability-management-system.git
cd vulnerability-management-system](https://github.com/Azkkun/Gestion_vulnerabilite

# Aucune installation nécessaire, le projet utilise uniquement la stdlib Python
```

## 💻 Utilisation

### Lancement de la démo

```bash
python analyse.py
```

### Utilisation programmatique

```python
from vulnerability_management_system import VulnerabilityManagementSystem

# Initialiser le système
system = VulnerabilityManagementSystem()

# Scanner une cible (scan réseau uniquement)
system.scan_target("webapp.example.com", "network")

# Scanner avec toutes les stratégies
system.scan_target("production-server.com")

# Générer un rapport
system.generate_report("security_report.txt", detailed=True)

# Obtenir les statistiques
stats = system.get_statistics()
print(f"Total: {stats['total_vulnerabilities']}")
print(f"Score moyen: {stats['average_score']}")

# Récupérer les vulnérabilités critiques
critical = system.get_critical_vulnerabilities()
for vuln in critical:
    print(f"⚠️ {vuln.get_id()} - Score: {vuln.get_score()}")
```

### Créer un analyseur personnalisé

```python
from analyzers import AnalysisStrategy
from models import VulnerabilityType

class CustomAnalyzer(AnalysisStrategy):
    def analyze(self, target: str) -> List[Vulnerability]:
        # Votre logique d'analyse
        vulnerabilities = []
        # ...
        return vulnerabilities
    
    def get_analysis_type(self) -> VulnerabilityType:
        return VulnerabilityType.CODE
    
    def get_name(self) -> str:
        return "Custom Code Analyzer"

# Utilisation
scanner = VulnerabilityScanner()
scanner.set_strategy(CustomAnalyzer())
scanner.scan("my-app")
```

## ✨ Fonctionnalités

### Base de données CVE

- ✅ 5 CVE d'exemple (SQL Injection, XSS, Log4j, etc.)
- ✅ Stockage centralisé (Singleton)
- ✅ Recherche par ID, sévérité, type
- ✅ Statistiques en temps réel

### Analyseurs (Strategy)

| Analyseur | Type | Détecte |
|-----------|------|---------|
| **NetworkAnalyzer** | Réseau | SQL Injection, XSS, ports ouverts |
| **DependencyAnalyzer** | Dépendances | Packages obsolètes (npm, pip, maven) |
| **FileSystemAnalyzer** | Fichiers | Permissions incorrectes, crypto faible |

### Enrichissement (Decorator)

| Décorateur | Fonction | Exemple |
|------------|----------|---------|
| **SourceDecorator** | Source de détection | Scanner réseau, confiance 95% |
| **ExploitabilityDecorator** | Exploitabilité + **recalcul du score** | Exploit public → score × 1.3 |
| **ImpactDecorator** | Impact métier | Assets affectés, exposition de données |
| **RemediationDecorator** | Contre-mesures | Solution, temps estimé, priorité |

### Rapports

- 📊 **Rapport résumé** : statistiques globales
- 📋 **Rapport détaillé** : toutes les vulnérabilités avec métadonnées
- 💾 Export en fichier texte
- 🎯 Tri par score décroissant
