"""Per-finding signal extraction (Fase 1 of the prioritization layer)."""
import pytest

from mulitaminer.prioritization.signals import (
    exploitation,
    exposure,
    extract_cve_ids,
    host_of,
    max_epss,
    severity_band,
)


@pytest.mark.parametrize(
    "record, expected",
    [
        ({"host": "10.0.0.1"}, "10.0.0.1"),                       # OpenVAS direct field
        ({"ip_address": "8.8.8.8"}, "8.8.8.8"),                   # alternate scalar name
        ({"target": "srv01"}, "srv01"),                          # another common name
        # Tenable WAS: host nested in instances[].instance as a URL
        ({"host": None, "instances": [{"instance": "https://app.x/api"}]}, "https://app.x/api"),
        # instance sub-key under a different name (url)
        ({"instances": [{"url": "https://app.y/login"}]}, "https://app.y/login"),
        ({"host": "", "instances": []}, None),                    # nothing usable
        ({}, None),
    ],
)
def test_host_of(record, expected):
    assert host_of(record) == expected


@pytest.mark.parametrize(
    "record, expected",
    [
        # OpenVAS shape: references is a list of "cve: ..." / "url: ..." strings.
        ({"references": ["cve: CVE-2020-1938", "url: http://x"]}, ["CVE-2020-1938"]),
        # Dedup + order preserved + case-normalized.
        (
            {"references": ["CVE-2021-44228", "cve-2021-44228", "CVE-2019-0001"]},
            ["CVE-2021-44228", "CVE-2019-0001"],
        ),
        # CVE hiding in plugin_details (a dict) rather than references.
        ({"references": [], "plugin_details": {"id": "CVE-2017-5638"}}, ["CVE-2017-5638"]),
        # No CVE anywhere (typical Tenable WAS finding).
        ({"references": [], "plugin_details": {}}, []),
        ({}, []),
    ],
)
def test_extract_cve_ids(record, expected):
    assert extract_cve_ids(record) == expected


@pytest.mark.parametrize(
    "host, expected",
    [
        ("127.0.0.1", "internal"),       # loopback
        ("10.1.2.3", "internal"),        # RFC1918
        ("172.31.1.54", "internal"),     # RFC1918
        ("192.168.0.9", "internal"),     # RFC1918
        ("8.8.8.8", "exposed"),          # public IP
        ("juice-shop-x.us-west1.run.app", "exposed"),  # public FQDN (WAS) → cautious
        ("https://app.example.com/login", "exposed"),  # URL is stripped to host
        ("", "exposed"),                 # unknown → cautious
        (None, "exposed"),               # missing → cautious
        ("srv01", "internal"),           # single-label name → not a public FQDN
        ("printer.local", "internal"),   # mDNS special-use suffix
        ("api.internal", "internal"),    # ICANN private-use suffix
        ("dc1.corp", "internal"),        # conventional internal suffix
        ("[::1]", "internal"),           # IPv6 loopback
    ],
)
def test_exposure(host, expected):
    assert exposure({"host": host}) == expected


@pytest.mark.parametrize(
    "record, expected",
    [
        # Tenable WAS: exposure derived from the instance URL's hostname.
        ({"instances": [{"instance": "https://public.example.com/api"}]}, "exposed"),
        ({"instances": [{"instance": "https://intranet.corp/app"}]}, "internal"),
        ({"instances": [{"instance": "http://10.0.0.5/x"}]}, "internal"),
    ],
)
def test_exposure_from_instances(record, expected):
    assert exposure(record) == expected


@pytest.mark.parametrize(
    "record, expected",
    [
        ({"cvss": 9.0}, "high"),
        ({"cvss": 7.0}, "high"),
        ({"cvss": 6.9}, "medium"),
        ({"cvss": 4.0}, "medium"),
        ({"cvss": 3.9}, "low"),
        ({"cvss": "8.6"}, "high"),                       # string CVSS coerces
        # No/zero CVSS → fall back to the scanner's severity label.
        ({"cvss": 0.0, "severity": "High"}, "high"),
        ({"cvss": None, "severity": "Medium"}, "medium"),
        ({"severity": "Log"}, "low"),
        ({"severity": "Critical"}, "high"),
        ({}, "low"),                                     # nothing → low
    ],
)
def test_severity_band(record, expected):
    assert severity_band(record) == expected


KEV = {"CVE-2021-44228"}
EPSS = {"CVE-2021-44228": 0.99, "CVE-2015-9251": 0.30, "CVE-2000-0001": 0.01}


@pytest.mark.parametrize(
    "cve_ids, expected",
    [
        (["CVE-2021-44228"], "active"),          # in KEV
        (["CVE-2015-9251"], "likely"),           # EPSS 0.30 ≥ 0.10
        (["CVE-2000-0001"], "none"),             # has CVE, EPSS 0.01 < 0.10 → checked
        (["CVE-9999-9999"], "none"),             # has CVE, unknown to feeds → none
        ([], "unknown"),                         # no CVE (e.g. WAS finding) → can't assess
        (["CVE-2000-0001", "CVE-2021-44228"], "active"),  # any KEV hit wins
    ],
)
def test_exploitation(cve_ids, expected):
    assert exploitation(cve_ids, KEV, EPSS) == expected


def test_max_epss_picks_highest():
    assert max_epss(["CVE-2000-0001", "CVE-2015-9251"], EPSS) == 0.30
    assert max_epss([], EPSS) == 0.0
    assert max_epss(["CVE-9999-9999"], EPSS) == 0.0
