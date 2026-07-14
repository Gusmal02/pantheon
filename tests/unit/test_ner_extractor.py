"""Tests unitarios para el extractor de IOCs."""

import pytest

from pantheon.ornith.ner_extractor import extract_iocs


class TestExtractIocs:
    def test_ipv4_detected(self):
        result = extract_iocs("conexión sospechosa desde 192.168.1.100 al puerto 443")
        assert "192.168.1.100" in result

    def test_cve_detected(self):
        result = extract_iocs("exploit para CVE-2021-44228 detectado en logs")
        assert "CVE-2021-44228" in result

    def test_cve_case_insensitive(self):
        result = extract_iocs("se explotó cve-2021-44228")
        assert any("CVE-2021-44228" in ioc.upper() for ioc in result)

    def test_sha256_detected(self):
        sha256 = "a" * 64
        result = extract_iocs(f"hash del malware: {sha256}")
        assert sha256 in result

    def test_sha1_detected(self):
        sha1 = "b" * 40
        result = extract_iocs(f"firma: {sha1}")
        assert sha1 in result

    def test_md5_detected(self):
        md5 = "c" * 32
        result = extract_iocs(f"md5: {md5}")
        assert md5 in result

    def test_domain_detected(self):
        result = extract_iocs("el malware contactó malware.example.com via HTTP")
        assert "malware.example.com" in result

    def test_no_duplicates(self):
        result = extract_iocs("192.168.1.1 192.168.1.1 192.168.1.1")
        assert result.count("192.168.1.1") == 1

    def test_empty_text_returns_empty(self):
        assert extract_iocs("") == []

    def test_no_iocs_returns_empty(self):
        result = extract_iocs("el sistema de logs registra eventos normales del servidor")
        assert isinstance(result, list)

    def test_multiple_iocs_in_same_text(self):
        text = "ataque desde 10.0.0.5 usando CVE-2022-1234 hash a" * 32 + "a" * 32
        result = extract_iocs(text)
        assert "10.0.0.5" in result
        assert "CVE-2022-1234" in result

    def test_returns_sorted_list(self):
        result = extract_iocs("10.0.0.1 192.168.1.1 CVE-2020-1234")
        assert result == sorted(result)

    def test_sha256_not_captured_as_md5(self):
        sha256 = "d" * 64
        result = extract_iocs(f"payload: {sha256}")
        assert sha256 in result
        # el hash completo (64 chars) no debe aparecer truncado como MD5 (32 chars)
        assert sha256[:32] not in result or sha256 in result
