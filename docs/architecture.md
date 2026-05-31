# Architecture détaillée — PFE SOC AI

## 1. Vue d'ensemble

Ce projet met en place un **SOC virtuel** complet, où la détection de menaces est automatisée par un LLM (Claude API), et où chaque règle de détection est gérée comme du code (*Detection as Code*).

L'objectif est de démontrer qu'un LLM peut :
1. **Analyser** dynamiquement les alertes de sécurité d'un SIEM (Wazuh) ;
2. **Identifier** le type d'attaque (catégorie MITRE ATT&CK, sévérité, IP source) ;
3. **Générer** automatiquement une règle XML compatible Wazuh ;
4. **Déployer** cette règle via un pipeline CI/CD (GitHub Actions).

## 2. Topologie du laboratoire

```
┌─────────────────────────┐         ┌─────────────────────────────────┐
│   Kali Linux            │         │   Wazuh Manager Ubuntu          │
│   (192.168.1.x)         │ ──────▶ │   (192.168.1.132)               │
│                         │ attaque │                                 │
│   - hydra (SSH brute)   │         │   - wazuh-manager v4.7.5        │
│   - nmap (scan)         │         │   - wazuh-indexer (OpenSearch)  │
│   - nikto / sqlmap      │         │   - wazuh-dashboard             │
│   - hping3 (DoS)        │         │   - filebeat                    │
│                         │         │   - wazuh-agent (auto-monitor)  │
│   wazuh-agent installé  │         │   - Apache (cible web)          │
└─────────────────────────┘         │   - OpenSSH (cible SSH)         │
                                    │                                 │
                                    │   Services PFE :                │
                                    │   - pfe-llm-analyst.service     │
                                    │   - pfe-nmap-watcher.service    │
                                    │   - pfe-soc-dashboard.service   │
                                    │   - flask_api.py (port 8080)    │
                                    └────────────┬────────────────────┘
                                                 │
                                                 ▼
                                    ┌─────────────────────────────────┐
                                    │   GitHub                        │
                                    │   hamadycisse7540-hash/         │
                                    │     pfe-soc-ai                  │
                                    │                                 │
                                    │   - rules/custom/*.xml          │
                                    │   - .github/workflows/          │
                                    │     (validation CI/CD)          │
                                    │   - self-hosted runner          │
                                    │     sur le manager              │
                                    └─────────────────────────────────┘
```

## 3. Pipeline de détection (Detection as Code)

### Étapes complètes, du paquet réseau à la règle déployée

```
1.  [Kali]      Attaquant lance une attaque
                ex : hydra -l root -P rockyou.txt ssh://192.168.1.132

2.  [Manager]   OpenSSH journalise les tentatives d'auth
                /var/log/auth.log : "Failed password for root from x.x.x.x"

3.  [Wazuh Agent → Manager]
                Lecture en temps réel par filebeat → wazuh-manager
                Décodeur SSH applique les règles built-in

4.  [Wazuh]     Génère une alerte JSON dans /var/ossec/logs/alerts/alerts.json
                {
                  "rule": {"level": 10, "id": 5712, ...},
                  "data": {"srcip": "...", "srcuser": "root"},
                  "agent": {...}
                }

5.  [pfe-llm-analyst.service]
                Service systemd qui tail -f alerts.json
                → filtre les alertes de niveau ≥ 8
                → envoie le contexte de l'alerte à Claude API

6.  [Claude API]
                Reçoit le prompt :
                "Tu es un analyste SOC. Analyse cette alerte Wazuh,
                identifie le type d'attaque (catégorie MITRE),
                la sévérité (low/medium/high/critical),
                l'IP source, et génère une règle XML Wazuh
                qui détecterait ce pattern à l'avenir."
                → retourne une règle XML

7.  [pfe-llm-analyst]
                Sauvegarde la règle dans :
                /var/ossec/etc/rules/llm_<categorie>_<id>.xml
                ET
                ~/pfe_soc/github/rules/custom/llm_<categorie>_<id>.xml

8.  [Git push]  Auto-commit + push vers le dépôt GitHub

9.  [GitHub Actions]
                Workflow déclenché → validate XML syntax
                → lint Wazuh rules
                → si OK : merge auto possible

10. [Wazuh]     Restart manager → la nouvelle règle est active
                → la prochaine occurrence du pattern est détectée
                   directement par Wazuh, sans appel LLM
```

### Boucle d'apprentissage

Le système devient **plus performant avec le temps** :
- Les premières alertes d'un type donné déclenchent un appel LLM (coûteux).
- Une fois la règle générée et déployée, les occurrences suivantes sont détectées par Wazuh directement (gratuit, latence ms).
- Le LLM n'est sollicité que pour des **patterns nouveaux ou inconnus**.

## 4. Composants

### 4.1 Wazuh

- **wazuh-manager v4.7.5** : SIEM central, applique les décodeurs et les règles.
- **wazuh-indexer** : OpenSearch backend (stockage des alertes).
- **wazuh-dashboard** : UI web sur `https://192.168.1.132`.
- **filebeat** : transport des alertes vers l'indexer.
- **wazuh-agent** sur Kali et sur le manager lui-même.

### 4.2 Services PFE (systemd)

| Service | Fichier | Rôle |
|---------|---------|------|
| `pfe-llm-analyst.service` | `llm_analyst_v3.py` | Lit `alerts.json`, appelle Claude, génère/déploie règles |
| `pfe-nmap-watcher.service` | `nmap_watcher.py` | Lit iptables LOG, détecte les patterns Nmap (SYN scan, etc.) |
| `pfe-soc-dashboard.service` | `soc_dashboard.py` | Dashboard local des détections (port à confirmer) |

### 4.3 API Flask (`flask_api.py`)

REST API sur port `8080` exposant :
- `GET /api/stats` — statistiques de détection
- `GET /` — health check
- (autres endpoints à documenter dans le code)

### 4.4 Détection ML (`ai_detector_v3.py` + `train_model_v2.py`)

Modèle **Random Forest** entraîné sur **CICIDS2017** :
- Features : statistiques de flux réseau (durée, taille paquets, flags TCP, etc.)
- Classes : Benign, DoS, DDoS, PortScan, BruteForce, WebAttack, Infiltration
- Artéfacts : `models/model_v2.pkl`, `models/features_v2.json`

Ce composant est complémentaire au LLM : il permet une détection **précoce** sur le trafic brut, avant même que Wazuh ne génère une alerte.

## 5. Dépôt "Detection as Code" (`github/`)

```
github/
├── README.md
├── rules/
│   ├── custom/           # règles générées par LLM + curées
│   ├── local_rules.xml   # règles locales Wazuh
│   └── tests/            # tests des règles (wazuh-logtest)
├── scripts/              # copies déployables des scripts root
├── models/               # features.json (référence)
└── docs/
```

Ce dossier est un **vrai dépôt Git** distinct, poussé sur GitHub. Sa CI/CD valide chaque règle.

## 6. Sécurité et bonnes pratiques

- **Clé API Anthropic** : actuellement en clair dans `start_demo.sh` et dans le service systemd. À sortir vers un `.env` ou `Environment=file:/etc/pfe/secrets.env` pour le rendu final.
- **iptables** : le script `start_demo.sh` flush les règles iptables. À reconsidérer en prod.
- **Self-hosted runner** : tourne sur le manager. Risque : un PR malveillant peut exécuter du code sur le manager. Acceptable en démo PFE, pas en prod.

## 7. Limites et perspectives

### Limites actuelles
- Les règles générées par LLM ne sont pas systématiquement testées avec `wazuh-logtest` avant déploiement.
- Le LLM peut générer des règles redondantes ou conflictuelles.
- Coût des appels API si volume d'alertes important.

### Pistes d'amélioration
- Cache de prompts (Anthropic prompt caching) → réduit le coût.
- Déduplication des règles par signature.
- Pipeline de validation : `wazuh-logtest` avant commit.
- Modèle ML local en première ligne, LLM uniquement sur les cas incertains.
- Feedback loop : annoter les faux positifs pour affiner les prompts.
