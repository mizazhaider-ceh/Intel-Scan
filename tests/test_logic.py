import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from intel_scan_core.logic import (
    _create_md_content,
    _create_txt_content,
    parse_raw_whois_to_dataframe,
    sanitize_domain,
    save_report,
)


def test_sanitize_plain_domain():
    assert sanitize_domain("tesla.com") == "tesla.com"


def test_sanitize_strips_www_and_scheme_and_path():
    assert sanitize_domain("https://www.tesla.com/path") == "tesla.com"


def test_sanitize_strips_userinfo_and_port():
    assert sanitize_domain("https://user:pw@example.com:8080/x") == "example.com"


def test_sanitize_empty():
    assert sanitize_domain("") == ""


def test_sanitize_lowercases_and_trims():
    assert sanitize_domain("  Example.COM. ") == "example.com"


def test_parse_whois_to_dataframe():
    raw = "Domain Name: EXAMPLE.COM\nRegistrar: Example Registrar\n>>> last update note\n"
    df = parse_raw_whois_to_dataframe(raw)
    assert list(df.columns) == ["Attribute", "Value"]
    assert len(df) == 2
    assert df.iloc[0]["Attribute"] == "Domain Name"


def test_parse_whois_empty():
    df = parse_raw_whois_to_dataframe("")
    assert list(df.columns) == ["Attribute", "Value"]
    assert len(df) == 0


def test_txt_report_content():
    results = {
        "dns": {"A": ["93.184.216.34"]},
        "subdomains": {"www.example.com": "93.184.216.34"},
    }
    content = _create_txt_content("example.com", results, "2026-01-01_00-00-00")
    assert "example.com" in content
    assert "93.184.216.34" in content
    assert "www.example.com" in content


def test_md_report_content():
    results = {"dns": {"A": ["93.184.216.34"]}}
    content = _create_md_content("example.com", results, "2026-01-01_00-00-00")
    assert "# IntelScan Report: `example.com`" in content
    assert "`93.184.216.34`" in content


def test_save_report_json_roundtrip(tmp_path):
    results = {"domain": "example.com", "dns": {"A": ["93.184.216.34"]}}
    path = save_report(str(tmp_path), "example.com", results, "JSON")
    assert os.path.exists(path)
    with open(path, encoding="utf-8") as f:
        loaded = json.load(f)
    assert loaded["dns"] == {"A": ["93.184.216.34"]}


def test_save_report_txt_and_markdown(tmp_path):
    results = {"domain": "example.com"}
    for fmt, ext in (("TXT", "txt"), ("Markdown", "markdown")):
        path = save_report(str(tmp_path), "example.com", results, fmt)
        assert path.endswith("." + ext)
        assert os.path.exists(path)
