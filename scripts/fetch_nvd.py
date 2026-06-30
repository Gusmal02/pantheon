"""Descarga un lote reciente de CVEs desde la API pública de NVD (sin autenticación, limitado)."""
import json
import time
import urllib.request

BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
OUT_PATH = "data/raw/nvd_sample.json"

import os
os.makedirs("data/raw", exist_ok=True)
print("Descargando muestra de CVEs recientes de NVD...")
with urllib.request.urlopen(f"{BASE_URL}?resultsPerPage=200") as resp:
    data = json.load(resp)
with open(OUT_PATH, "w", encoding="utf-8") as f:
    json.dump(data, f)
print(f"Descargado: {data.get('totalResults', '?')} CVEs totales disponibles, 200 guardados.")