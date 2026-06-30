"""Descarga el dataset STIX de MITRE ATT&CK (Enterprise) y lo guarda local."""
import json
import urllib.request

URL = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
OUT_PATH = "data/raw/enterprise-attack.json"

import os
os.makedirs("data/raw", exist_ok=True)
print("Descargando MITRE ATT&CK STIX...")
urllib.request.urlretrieve(URL, OUT_PATH)
with open(OUT_PATH, encoding="utf-8") as f:
    data = json.load(f)
print(f"Descargado: {len(data['objects'])} objetos STIX.")