from pantheon.ornith.ner_extractor import extract_iocs

texto = (
    "Se detectó tráfico desde 192.168.1.105 hacia el dominio evil-c2.xyz, "
    "explotando CVE-2024-3400, con un payload de hash "
    "5d41402abc4b2a76b9719d911017c592 (MD5) descargado durante el ataque."
)

resultado = extract_iocs(texto)
print("IOCs encontrados:")
for ioc in resultado:
    print(f"  - {ioc}")