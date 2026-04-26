 PFE SOC - AI Empowered Detection as Code

## Sujet
AI Empowered Detection as a Code for an advanced, time efficient
and last trending threat detection in a SOC environment

## Architecture
Kali Linux (Attaquant)
↓ SSH Brute Force / Nmap
Wazuh Agent v4.7.5
↓ logs temps réel
Wazuh Manager + OpenSearch
↓ alerts.json
Python AI Detector (Random Forest)
↓ classification ML
Dashboard Wazuh + API Flask
## Résultats ML
- Dataset : CIC-IDS2017 (2.7M+ flux réseau)
- Algorithme : Random Forest (100 arbres)
- Accuracy : 100%
- Taux faux positifs : 0.0%
- Détection temps réel : < 1 seconde

## Structure
- `rules/` — Règles Wazuh personnalisées
- `scripts/` — Scripts Python de détection IA
- `models/` — Features du modèle ML
- `docs/` — Documentation

## Lancement
```bash
# Activer l'environnement
source ~/ml_env/bin/activate

# Lancer le détecteur IA
python scripts/ai_detector_v3.py &

# Lancer l'API Flask
python scripts/flask_api.py &
```

## API Endpoints
- GET /api/stats — Statistiques globales
- GET /api/detections — Historique des détections
- GET /api/top-ips — Top IPs attaquantes
- GET /api/block/<ip> — Bloquer une IP
- GET /api/blocked — Liste des IPs bloquées
