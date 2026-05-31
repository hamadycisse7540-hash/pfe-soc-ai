#!/bin/bash
"""
Script de déploiement des règles Wazuh
Exécuté automatiquement par GitHub Actions après validation
"""
set -e

WAZUH_RULES_DIR="/var/ossec/etc/rules"
LOCAL_RULES_DIR="rules/custom"

echo "=== Déploiement des règles Wazuh ==="

# Copie toutes les règles validées
for rule_file in $LOCAL_RULES_DIR/*.xml; do
    filename=$(basename "$rule_file")
    echo "  Déploiement : $filename"
    sudo cp "$rule_file" "$WAZUH_RULES_DIR/$filename"
done

# Valide la configuration Wazuh
echo "  Validation de la configuration..."
sudo /var/ossec/bin/wazuh-analysisd -t 2>/dev/null && echo "  OK configuration valide"

# Redémarre le manager
echo "  Redémarrage du manager..."
sudo systemctl restart wazuh-manager
sleep 5

# Vérifie que le service tourne
sudo systemctl is-active wazuh-manager && echo "  OK manager redémarré"
echo "=== Déploiement terminé ==="
