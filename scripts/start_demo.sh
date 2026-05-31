#!/bin/bash
echo "========================================"
echo "  PFE SOC - PRÉPARATION DÉMO COMPLÈTE"
echo "========================================"

# 1. Services
echo ""
echo "1. Vérification services..."
sudo systemctl start wazuh-indexer 2>/dev/null; sleep 5
sudo systemctl start wazuh-manager 2>/dev/null; sleep 8
sudo systemctl start filebeat 2>/dev/null; sleep 3
sudo systemctl start wazuh-dashboard 2>/dev/null; sleep 10
sudo systemctl start pfe-llm-analyst 2>/dev/null; sleep 3
sudo systemctl start pfe-nmap-watcher 2>/dev/null; sleep 2

echo "Services actifs:"
sudo systemctl is-active wazuh-manager wazuh-dashboard wazuh-indexer \
  filebeat pfe-llm-analyst pfe-nmap-watcher \
  actions.runner.hamadycisse7540-hash-pfe-soc-ai.ubuntu-wazuh-runner | \
  paste - - - - - - - | \
  awk '{print "  manager:"$1" dashboard:"$2" indexer:"$3" filebeat:"$4" llm:"$5" nmap:"$6" runner:"$7}'

# 2. Nettoyage synchronisé
echo ""
echo "2. Nettoyage pour démo propre..."
sudo systemctl stop pfe-llm-analyst
sudo rm -f /var/ossec/etc/rules/llm_*.xml
rm -f ~/pfe_soc/rules/custom/llm_*.xml
cd ~/pfe_soc
git add rules/custom/ 2>/dev/null
git diff --cached --quiet || git commit -m "Demo reset: nettoyage regles LLM"
git push 2>/dev/null || true
echo "100050" > ~/pfe_soc/.rule_id_counter
sudo systemctl restart wazuh-manager
sleep 8
sudo systemctl start pfe-llm-analyst
sleep 5

# 3. iptables pour Nmap
echo ""
echo "3. Configuration iptables Nmap..."
sudo iptables -F 2>/dev/null
sudo iptables -I INPUT -i eth0 -j LOG --log-prefix "IPTABLES-DROP: " --log-level 4
echo "  iptables LOG actif sur eth0"

# 4. Flask API
echo ""
echo "4. API Flask..."
pkill -f flask_api 2>/dev/null
source ~/ml_env/bin/activate
# Charge la clé API depuis ~/pfe_soc/.env (non versionné)
set -a; source ~/pfe_soc/.env; set +a
python3 ~/pfe_soc/flask_api.py > /tmp/flask.log 2>&1 &
sleep 3
curl -s http://localhost:8080/ > /dev/null && echo "  API Flask: OK" || echo "  API Flask: ERREUR"

# 5. Agent Kali
echo ""
echo "5. Agent Kali:"
sudo /var/ossec/bin/agent_control -l 2>/dev/null | grep -E "ID|kali"

# 6. Repo GitHub
echo ""
echo "6. Repo GitHub:"
ls ~/pfe_soc/rules/custom/
echo "IDs statiques:"
grep 'rule id=' ~/pfe_soc/rules/custom/*.xml 2>/dev/null | grep -v llm_

echo ""
echo "========================================"
echo "  SYSTÈME PRÊT POUR LA DÉMO !"
echo "========================================"
echo ""
echo "Dashboard   : https://192.168.1.132"
echo "API Flask   : http://192.168.1.132:8080/api/stats"
echo "GitHub      : https://github.com/hamadycisse7540-hash/pfe-soc-ai"
echo "Actions     : https://github.com/hamadycisse7540-hash/pfe-soc-ai/actions"
echo ""
echo "Catégories détectées :"
echo "  1. SSH Brute Force    → hydra depuis Kali (réel)"
echo "  2. Nmap Scan          → nmap depuis Kali (réel)"
echo "  3. Web Attack         → nikto depuis Kali (réel)"
echo "  4. Shellshock         → nikto déclenche automatiquement"
echo "  5. DoS Attack         → injection"
echo "  6. Privilege Escal.   → injection"
echo ""
echo "Commandes démo :"
echo "  Terminal 1: sudo journalctl -u pfe-llm-analyst -f"
echo "  Terminal 2: watch -n 3 'sudo ls /var/ossec/etc/rules/llm_*.xml 2>/dev/null'"
echo "  Kali SSH  : hydra -l root -P /usr/share/wordlists/rockyou.txt ssh://192.168.1.132 -t 4 -I"
echo "  Kali Nmap : nmap -sS -p 22,80,443,8080 192.168.1.132"
echo "  Kali Web  : nikto -h http://192.168.1.132"
echo "  Injection : python3 ~/pfe_soc/inject_alerts.py
  Inject+Nmap: python3 ~/pfe_soc/inject_alerts.py --with-nmap"
