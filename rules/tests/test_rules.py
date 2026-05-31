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

for fname in sorted(os.listdir(rules_dir)):
    if not fname.endswith('.xml'):
        continue
    fpath = os.path.join(rules_dir, fname)
    try:
        tree = ET.parse(fpath)
        root = tree.getroot()
        for rule in root.findall('.//rule'):
            rid = rule.get('id')
            lvl = rule.get('level')
            desc = rule.find('description')
            if not rid:
                errors.append(f"{fname}: règle sans id")
            if not lvl:
                errors.append(f"{fname}: règle sans level")
            if desc is None or not desc.text:
                errors.append(f"{fname}: règle sans description")
            if rid in ids_seen:
                errors.append(f"{fname}: ID {rid} dupliqué")
            ids_seen.add(rid)
        print(f"OK {fname}")
    except ET.ParseError as e:
        errors.append(f"{fname}: XML invalide - {e}")

if errors:
    print("\nERREURS:")
    for e in errors: print(f"  - {e}")
    sys.exit(1)
else:
    print(f"\nToutes les règles valides ({len(ids_seen)} IDs uniques)")
    sys.exit(0)
