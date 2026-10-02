"""CISA Known Exploited Vulnerabilities catalog: parsing, matching and caching."""

from __future__ import annotations

import json
import os
import time

import pytest
from conftest import load_fixture

from config import CISAKEVConfig
from kev_client import KEVClient


@pytest.fixture
def kev_config(tmp_path) -> CISAKEVConfig:
    return CISAKEVConfig(cache_path=str(tmp_path / "kev.json"), cache_ttl_hours=24)


def test_catalog_entries_are_parsed_with_ransomware_flag():
    catalog = KEVClient._parse_catalog(load_fixture("kev_catalog_subset.json"))

    assert set(catalog) == {"CVE-2021-22681", "CVE-2018-7841", "CVE-2016-8562",
                            "CVE-2017-0144", "CVE-2021-44228"}
    rockwell = catalog["CVE-2021-22681"]
    assert rockwell.vendor == "Rockwell"
    assert rockwell.date_added == "2026-03-05"
    assert rockwell.due_date and rockwell.required_action
    assert catalog["CVE-2017-0144"].known_ransomware_use == "Known"
    assert rockwell.known_ransomware_use == "Unknown"


def test_entries_without_cve_id_are_ignored():
    raw = {"vulnerabilities": [{"vendorProject": "x"}, {"cveID": "CVE-2020-0001"}]}
    catalog = KEVClient._parse_catalog(raw)

    assert list(catalog) == ["CVE-2020-0001"]


async def test_remote_catalog_is_fetched_matched_and_cached(fake_api, kev_config):
    client = KEVClient(kev_config)

    await client.load_catalog()

    assert client.is_loaded and client.catalog_size == 5
    assert client.lookup("CVE-2021-22681").product == "Multiple Products"
    assert client.lookup("CVE-2022-1161") is None  # real ControlLogix CVE that is not in KEV
    assert set(client.batch_lookup(["CVE-2021-22681", "CVE-2022-1161", "CVE-2018-7841"])) == {
        "CVE-2021-22681", "CVE-2018-7841"}
    with open(kev_config.cache_path, encoding="utf-8") as f:
        cached = json.load(f)
    assert cached["count"] == 5


async def test_fresh_cache_avoids_network(fake_api, kev_config):
    with open(kev_config.cache_path, "w", encoding="utf-8") as f:
        json.dump(load_fixture("kev_catalog_subset.json"), f)

    client = KEVClient(kev_config)
    await client.load_catalog()

    assert client.catalog_size == 5
    assert fake_api.kev_calls() == []


async def test_expired_cache_is_refreshed(fake_api, kev_config):
    with open(kev_config.cache_path, "w", encoding="utf-8") as f:
        json.dump({"vulnerabilities": [{"cveID": "CVE-1999-0001"}]}, f)
    two_days_ago = time.time() - 48 * 3600
    os.utime(kev_config.cache_path, (two_days_ago, two_days_ago))

    client = KEVClient(kev_config)
    await client.load_catalog()

    assert len(fake_api.kev_calls()) == 1
    assert client.lookup("CVE-1999-0001") is None
    assert client.lookup("CVE-2021-22681") is not None


async def test_stale_cache_is_used_when_cisa_is_unreachable(fake_api, kev_config):
    with open(kev_config.cache_path, "w", encoding="utf-8") as f:
        json.dump(load_fixture("kev_catalog_subset.json"), f)
    old = time.time() - 72 * 3600
    os.utime(kev_config.cache_path, (old, old))
    fake_api.kev_status = 503

    client = KEVClient(kev_config)
    await client.load_catalog()

    assert len(fake_api.kev_calls()) == 1
    assert client.is_loaded
    assert client.lookup("CVE-2021-22681") is not None


async def test_unreachable_cisa_and_no_cache_leaves_catalog_unloaded(fake_api, kev_config):
    fake_api.kev_status = 500

    client = KEVClient(kev_config)
    await client.load_catalog()

    assert not client.is_loaded
    assert client.lookup("CVE-2021-22681") is None


async def test_corrupt_cache_triggers_refetch(fake_api, kev_config):
    with open(kev_config.cache_path, "w", encoding="utf-8") as f:
        f.write("{not json")

    client = KEVClient(kev_config)
    await client.load_catalog()

    assert client.catalog_size == 5
    assert len(fake_api.kev_calls()) == 1
