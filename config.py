"""Configuration for ICS Supply Chain Vulnerability Scanner."""

import os
from dataclasses import dataclass, field

from dotenv import load_dotenv

load_dotenv()


@dataclass
class AzureOpenAIConfig:
    endpoint: str = os.getenv("AZURE_OPENAI_ENDPOINT", "")
    api_key: str = os.getenv("AZURE_OPENAI_API_KEY", "")
    deployment: str = os.getenv("AZURE_OPENAI_DEPLOYMENT", "gpt-4o")
    api_version: str = os.getenv("AZURE_OPENAI_API_VERSION", "2024-06-01")
    temperature: float = float(os.getenv("LLM_TEMPERATURE", "0.2"))
    max_tokens: int = int(os.getenv("LLM_MAX_TOKENS", "2048"))


@dataclass
class NVDConfig:
    base_url: str = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    api_key: str = os.getenv("NVD_API_KEY", "")
    rate_limit_delay: float = float(os.getenv("NVD_RATE_LIMIT_DELAY", "0.6"))
    # Without API key, NVD allows ~5 req/30s. With key, ~50 req/30s.
    rate_limit_delay_no_key: float = 6.0
    timeout: int = 30
    max_retries: int = 3


@dataclass
class CISAKEVConfig:
    catalog_url: str = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    cache_ttl_hours: int = int(os.getenv("KEV_CACHE_TTL_HOURS", "24"))
    cache_path: str = os.getenv("KEV_CACHE_PATH", ".cache/kev_catalog.json")


@dataclass
class OTRiskWeights:
    """OT-specific risk scoring multipliers."""
    # Purdue level weights: lower levels = higher impact on physical process
    purdue_weights: dict = field(default_factory=lambda: {
        0: 1.5,   # Physical process (sensors, actuators)
        1: 1.5,   # Basic control (PLCs, RTUs)
        2: 1.2,   # Area supervisory (HMI, SCADA servers)
        3: 1.0,   # Site operations (historian, OPC servers)
        3.5: 0.9, # DMZ
        4: 0.8,   # Enterprise IT
        5: 0.8,   # Enterprise network
    })

    # Network exposure multipliers
    exposure_weights: dict = field(default_factory=lambda: {
        "internet": 1.4,
        "corporate": 1.1,
        "dmz": 1.0,
        "isolated": 0.7,
        "air-gapped": 0.6,
    })

    # Patch feasibility
    patch_weights: dict = field(default_factory=lambda: {
        "available": 0.9,
        "scheduled": 1.0,
        "unavailable": 1.3,
        "eol": 1.4,  # End of life - no patches coming
    })

    # CISA KEV presence
    kev_multiplier: float = 1.5
    no_kev_multiplier: float = 1.0

    # Score cap
    max_score: float = 10.0


@dataclass
class ScannerConfig:
    nvd: NVDConfig = field(default_factory=NVDConfig)
    kev: CISAKEVConfig = field(default_factory=CISAKEVConfig)
    llm: AzureOpenAIConfig = field(default_factory=AzureOpenAIConfig)
    risk: OTRiskWeights = field(default_factory=OTRiskWeights)
    output_dir: str = os.getenv("OUTPUT_DIR", "output")
    log_level: str = os.getenv("LOG_LEVEL", "INFO")
    max_concurrent_queries: int = int(os.getenv("MAX_CONCURRENT_QUERIES", "5"))
