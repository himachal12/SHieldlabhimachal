"""
ShieldLabs Configuration
Centralized config with scan mode management.
"""

import os
from enum import Enum
from importlib.util import find_spec

if find_spec("dotenv"):
    from dotenv import load_dotenv

    load_dotenv()


class ScanMode(str, Enum):
    PASSIVE = "passive"
    ACTIVE = "active"


class Config:
    # App
    APP_NAME: str = os.getenv("APP_NAME", "ShieldLabs")
    APP_VERSION: str = os.getenv("APP_VERSION", "1.0.0")
    DEBUG: bool = os.getenv("DEBUG", "True") == "True"

    # Database
    DATABASE_URL: str = os.getenv("DATABASE_URL", "sqlite:///./shieldlabs.db")

    # LLMs
    GROQ_API_KEY: str = os.getenv("GROQ_API_KEY", "")
    OLLAMA_BASE_URL: str = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")
    OLLAMA_MODEL: str = os.getenv("OLLAMA_MODEL", "qwen2.5-coder:7b")

    # Tools
    NUCLEI_PATH: str = (
        os.getenv("NUCLEI_PATH")
        or __import__("shutil").which("nuclei")
        or ""
    )
    SQLMAP_PATH: str = os.getenv("SQLMAP_PATH", "")
    SQLMAP_PYTHON: str = os.getenv("SQLMAP_PYTHON", "")

    # Scan modes
    DEFAULT_SCAN_MODE: ScanMode = ScanMode(
        os.getenv("DEFAULT_SCAN_MODE", "passive").lower()
    )
    SQLMAP_MAX_REQUESTS: int = int(os.getenv("SQLMAP_MAX_REQUESTS", "50"))
    ACTIVE_SCAN_CONSENT_MESSAGE: str = os.getenv(
        "ACTIVE_SCAN_CONSENT_MESSAGE",
        "Active scanning uses real attack payloads. Only scan systems you own "
        "or have explicit written permission to test."
    )

    # Scanning limits
    SCAN_TIMEOUT: int = int(os.getenv("SCAN_TIMEOUT", "600"))
    NMAP_TIMEOUT: int = int(os.getenv("NMAP_TIMEOUT", "60"))


settings = Config()