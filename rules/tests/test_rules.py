#!/usr/bin/env python3
"""Validation des règles XML générées par le LLM"""
import os, sys
import xml.etree.ElementTree as ET

rules_dir = "rules/custom"
errors = []
ids_seen = set()

if not os.path.exists(rules_dir):
    print("Dossier rules/custom vide - OK")
    sys.exit(0)

# Parcours récursif : on doit voir TOUTES les regles, y compris dans
# d'eventuels sous-dossiers, sinon un SID duplique passe inapercu.
xml_files = []
for dirpath, _, filenames in os.walk(rules_dir):
    for fname in filenames:
        if fname.endswith('.xml'):
            xml_files.append(os.path.join(dirpath, fname))

for fpath in sorted(xml_files):
    rel = os.path.relpath(fpath, rules_dir)
    try:
        tree = ET.parse(fpath)
        root = tree.getroot()
        for rule in root.findall('.//rule'):
            rid = rule.get('id')
            lvl = rule.get('level')
            desc = rule.find('description')
            if not rid:
                errors.append(f"{rel}: règle sans id")
            if not lvl:
                errors.append(f"{rel}: règle sans level")
            if desc is None or not desc.text:
                errors.append(f"{rel}: règle sans description")
            # Une regle de detection Wazuh doit avoir au moins une condition
            # de matching, sinon elle est "vide" et inexploitable par le moteur.
            conditions = ['if_sid', 'if_matched_sid', 'match', 'regex',
                          'srcip', 'decoded_as', 'field', 'program_name']
            if not any(rule.find(c) is not None for c in conditions):
                errors.append(f"{rel}: règle {rid} sans logique de détection (vide)")
            if rid in ids_seen:
                errors.append(f"{rel}: ID {rid} dupliqué")
            ids_seen.add(rid)
        print(f"OK {rel}")
    except ET.ParseError as e:
        errors.append(f"{rel}: XML invalide - {e}")

if errors:
    print("\nERREURS:")
    for e in errors: print(f"  - {e}")
    sys.exit(1)
else:
    print(f"\nToutes les règles valides ({len(ids_seen)} IDs uniques)")
    sys.exit(0)
