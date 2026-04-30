#!/usr/bin/env python3
"""
Tests de validation des règles Wazuh avant déploiement
"""
import xml.etree.ElementTree as ET
import subprocess
import os
import sys

RULES_DIR = "rules/custom"

def test_xml_syntax(filepath):
    """Vérifie la syntaxe XML de chaque règle"""
    try:
        ET.parse(filepath)
        print(f"  OK syntaxe XML : {filepath}")
        return True
    except ET.ParseError as e:
        print(f"  ERREUR XML : {filepath} — {e}")
        return False

def test_rule_ids_unique(rules_dir):
    """Vérifie que les IDs de règles ne sont pas en doublon"""
    ids = []
    for f in os.listdir(rules_dir):
        if not f.endswith('.xml'):
            continue
        tree = ET.parse(os.path.join(rules_dir, f))
        for rule in tree.findall('.//rule'):
            rid = rule.get('id')
            if rid in ids:
                print(f"  ERREUR doublon ID : {rid} dans {f}")
                return False
            ids.append(rid)
    print(f"  OK IDs uniques : {len(ids)} règles vérifiées")
    return True

def test_rule_levels(rules_dir):
    """Vérifie que les niveaux sont entre 0 et 15"""
    for f in os.listdir(rules_dir):
        if not f.endswith('.xml'):
            continue
        tree = ET.parse(os.path.join(rules_dir, f))
        for rule in tree.findall('.//rule'):
            level = int(rule.get('level', 0))
            if level < 0 or level > 15:
                print(f"  ERREUR niveau invalide : {level} dans {f}")
                return False
    print(f"  OK niveaux valides dans toutes les règles")
    return True

def test_descriptions_present(rules_dir):
    """Vérifie que chaque règle a une description"""
    for f in os.listdir(rules_dir):
        if not f.endswith('.xml'):
            continue
        tree = ET.parse(os.path.join(rules_dir, f))
        for rule in tree.findall('.//rule'):
            desc = rule.find('description')
            if desc is None or not desc.text:
                rid = rule.get('id')
                print(f"  ERREUR description manquante : règle {rid} dans {f}")
                return False
    print(f"  OK descriptions présentes dans toutes les règles")
    return True

if __name__ == "__main__":
    print("=== Validation des règles Wazuh ===\n")
    results = []

    # Test syntaxe XML
    print("1. Syntaxe XML :")
    for f in os.listdir(RULES_DIR):
        if f.endswith('.xml'):
            results.append(test_xml_syntax(os.path.join(RULES_DIR, f)))

    print("\n2. IDs uniques :")
    results.append(test_rule_ids_unique(RULES_DIR))

    print("\n3. Niveaux valides :")
    results.append(test_rule_levels(RULES_DIR))

    print("\n4. Descriptions :")
    results.append(test_descriptions_present(RULES_DIR))

    print(f"\n{'OK TOUS LES TESTS PASSENT' if all(results) else 'ECHEC — corriger avant déploiement'}")
    sys.exit(0 if all(results) else 1)
