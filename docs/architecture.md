# Architecture détaillée — PFE SOC AI

## 1. Vue d'ensemble

Ce projet met en place un SOC virtuel complet où la détection de menaces est automatisée par un LLM (Claude API), et où chaque règle de détection est gérée comme du code (Detection as Code).

L'objectif est de démontrer qu'un LLM peut :

- Analyser dynamiquement les alertes de sécurité d'un SIEM (Wazuh) ;
- Identifier le type d'attaque (catégorie MITRE ATT&CK, sévérité, IP source) ;
- Déclencher une réponse graduée automatique (blocage temporaire, email SOC) ;
- Générer automatiquement une règle XML compatible Wazuh ;
- Déployer cette règle via un pipeline CI/CD (GitHub Actions).

## 2. Topologie du laboratoire
┌─────────────────────────┐         ┌─────────────────────────────────────┐

│   Kali Linux            │         │   Ubuntu Manager (192.168.1.132)    │

│   (192.168.1.158 DHCP)  │ ──────▶ │                                     │

│                         │ attaque │   Wazuh Manager v4.7.5              │

│   - hydra (SSH brute)   │         │   Wazuh Indexer (OpenSearch)        │

│   - nmap (SYN scan)     │         │   Wazuh Dashboard (https://:443)    │

│   - nikto (web scan)    │         │   Filebeat                          │

│   - hping3 / inject     │         │   Apache HTTP Server                │

│                         │         │   OpenSSH Server                    │

│   wazuh-agent ID 001    │         │                                     │

│   Active                │         │   Services PFE :                    │

└─────────────────────────┘         │   pfe-llm-analyst.service           │

│   pfe-nmap-watcher.service          │

│   pfe-flask-api.service (port 8080) │

└────────────┬────────────────────────┘

│

▼

┌─────────────────────────────────────┐

│   GitHub                            │

│   [username]/pfe-soc-ai             │

│                                     │

│   rules/custom/*.xml                │

│   .github/workflows/deploy.yml      │

│   self-hosted runner (sur manager)  │

└─────────────────────────────────────┘
## 3. Pipeline de détection (Detection as Code)

### Flux complet — de l'attaque à la règle déployée
[Kali]              Attaquant lance une attaque

ex : hydra -l root -P rockyou.txt ssh://192.168.1.132
[OpenSSH]           Journalise les tentatives

"Failed password for root from 192.168.1.158 port 35304 ssh2"
[Wazuh]             Décodeur SSH + règles built-in

Règle 100010 (échec SSH) → 8x en 120s → Règle 100003 (level 14)
[alerts.json]       Alerte JSON générée :

{

"rule": {"level": 14, "id": "100003",

"description": "BRUTE FORCE SSH"},

"data": {"srcip": "192.168.1.158", "dstuser": "root"},

"agent": {"id": "001", "name": "kali"}

}
[pfe-llm-analyst]   Service systemd surveille alerts.json (tail seek)

Filtre niveau >= 8, catégorise via ATTACK_CATEGORIES
[Claude API]        claude-sonnet-4-6, max_tokens=400

→ JSON : type, severite, action, niveau_regle,

parent_sid, description_regle
[Réponse graduée]   Human-in-the-Loop SOAR :

CRITIQUE → iptables DROP 60min (Popen bash)

+ Email SOC + Règle XML

HAUTE    → iptables DROP 15min (Popen bash)

+ Email SOC + Règle XML

MOYENNE  → Email SOC + Règle XML
[Génération XML]    Template par catégorie → ID unique auto-incrémenté

Validation : wazuh-analysisd -t

Déploiement : /var/ossec/etc/rules/llm_*.xml

restart wazuh-manager
[GitHub]            Commit automatique :

"LLM auto-rule: brute_force_ssh [20260618_003430]"
[GitHub Actions]    deploy.yml déclenché sur push rules/**

Job validate : xmllint + test_rules.py (IDs uniques)

Job deploy   : self-hosted runner → cp + restart Wazuh
[Email SOC]         Rapport HTML enrichi :

- Sévérité + bannière avertissement SOC

- IP source + lien ipinfo.io

- Action effectuée automatiquement

- Recommandation IA (Claude API)

- Boutons : Débloquer IP / Infos IP / IPs bloquées
### Boucle d'apprentissage Detection as Code
1ère occurrence d'une catégorie d'attaque

↓

Appel LLM (~4s) → règle XML générée et déployée

↓

2ème occurrence et suivantes

↓

Détection directe par Wazuh (latence ms, 0 coût API)
## 4. Composants

### 4.1 Wazuh

| Composant | Rôle |
|-----------|------|
| wazuh-manager v4.7.5 | SIEM central — décodeurs + règles |
| wazuh-indexer | OpenSearch backend (stockage alertes) |
| wazuh-dashboard | UI web — https://192.168.1.132 |
| filebeat | Transport alertes vers indexer |
| wazuh-agent (Kali, ID 001) | Supervision machine attaquante |

### 4.2 Services PFE (systemd)

| Service | Fichier | Rôle |
|---------|---------|------|
| pfe-llm-analyst.service | llm_analyst_v3.py | Analyse LLM + Human-in-the-Loop SOAR |
| pfe-nmap-watcher.service | nmap_watcher.py | Détection Nmap via kern.log + iptables |
| pfe-flask-api.service | flask_api.py | API REST + Dashboard SOC IP Management |

### 4.3 API Flask (port 8080)

| Méthode | Endpoint | Description |
|---------|----------|-------------|
| GET | /dashboard | Dashboard SOC IP Management |
| GET | /api/stats | Statistiques de détection |
| GET | /api/blocked | IPs bloquées (iptables) |
| GET | /api/top-ips | Top 10 IPs attaquantes |
| GET | /api/rules-count | Règles LLM déployées sur Wazuh |
| POST | /api/block/\<ip\> | Blocage manuel analyste SOC |
| POST | /api/unblock/\<ip\> | Déblocage analyste SOC |

### 4.4 Human-in-the-Loop SOAR
CRITIQUE    iptables DROP 60min + Email      Requise via email

HAUTE       iptables DROP 15min + Email      Non requise

MOYENNE     Email uniquement                 Non requise

FAIBLE      Email uniquement                 Non requise
Déblocage analyste : `POST http://192.168.1.132:8080/api/unblock/<ip>`

## 5. Règles statiques (8 fichiers, 16 IDs, MITRE ATT&CK)

| Fichier | IDs | Attaque | Match | MITRE |
|---------|-----|---------|-------|-------|
| rule_100001 | 100009 | SSH Invalid user | Invalid user | T1110.003 |
| rule_100002 | 100002 | Nmap scan | IPTABLES-DROP freq=18/45s | T1046 |
| rule_100003 | 100010+100003 | Brute Force SSH | Failed password × 8/120s | T1110 |
| rule_100004 | 100004 | SQL Injection | sqlmap/UNION SELECT | T1190 |
| rule_100005 | 100005 | Web Scanner | nikto/sqlmap/nmap | T1595.003 |
| rule_100006 | 100006 | Sudo root | USER=root (!ubuntu) | T1548.003 |
| rule_100007 | 100007 | Auth failure PAM | authentication failure | T1110 |
| rule_100008 | 100008 | New user created | useradd/adduser | T1136.001 |

## 6. Résultats expérimentaux (session 18 juin 2026)

| Scénario | Détection | Déploiement | Délai | Sévérité | MITRE |
|----------|-----------|-------------|-------|---------|-------|
| Nmap scan | 00:27:39 | 00:28:01 | 22s | HAUTE | T1046 |
| SSH Brute Force | 00:34:27 | 00:34:47 | 20s | CRITIQUE | T1110 |
| Web scan CGI | 00:40:40 | 00:41:03 | 23s | HAUTE | T1190 |
| Shellshock | 00:41:07 | 00:41:46 | 39s | CRITIQUE | T1059 |
| DoS SYN Flood | 00:49:30 | 00:49:55 | 25s | CRITIQUE | T1498 |
| Privilege Escalation | 00:50:15 | 00:50:40 | 25s | CRITIQUE | T1548 |

**Temps moyen : 26 secondes** (alerte détectée → règle déployée + email + GitHub)

## 7. Anti-doublon

- Clé de déduplication : `(category,)` → 1 seule règle LLM par catégorie par session
- Cache persistant : `.seen_categories.json`
- Vérification fichiers `llm_{category}_*.xml` existants dans `/var/ossec/etc/rules/`
- Reset avant démo : `rm -f .seen_categories.json`

## 8. Sécurité et bonnes pratiques

- Clé API Anthropic : stockée dans `.env` (EnvironmentFile systemd), jamais en dur
- `.seen_categories.json` et `*.db-journal` exclus du repo via `.gitignore`
- Self-hosted runner : tourne sur le manager (acceptable en démo PFE)
- Active Response Wazuh configuré pour les règles 100002, 100003, 100005, 100006
- Déblocage automatique via `Popen bash` détaché (CRITIQUE=3600s, HAUTE=900s)

## 9. Limites et perspectives

### Limites actuelles
- Catégorie `default` fourre-tout (Shellshock + autres non catégorisés)
- Déblocage via `Popen sleep + iptables` (non persistant au redémarrage du service)
- Email simple (pas de ticket ITSM)
- Active Response graphique limitée (alertes sur agent 000 = manager local)

### Améliorations futures (production)
- `firewall-cmd --timeout` ou `nftables sets` avec expiration native
- SOAR professionnel (Cortex XSOAR, Shuffle, Splunk SOAR)
- Tickets ITSM (ServiceNow, Jira) au lieu d'email
- Wazuh Active Response natif pour agents distants
- Interface dashboard avec historique et audit trail complet
