"""
LLM utility wrapper
Provides unified interface for Ollama (local) and Groq (cloud) calls
"""

import os
import time
import requests
from groq import Groq
from app.utils.logger import get_logger

logger = get_logger("llm")

# ==================
# CONFIG
# ==================

OLLAMA_BASE_URL = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "qwen2.5-coder:7b")
GROQ_API_KEY = os.getenv("GROQ_API_KEY")
GROQ_MODEL = "llama-3.3-70b-versatile"  # Current Groq free-tier flagship model

# Initialize Groq client once (reused across calls)
groq_client = Groq(api_key=GROQ_API_KEY) if GROQ_API_KEY else None


# ==================
# OLLAMA (LOCAL)
# ==================

def ollama_call(
    prompt: str,
    model: str = None,
    timeout: int = 120,
    system_prompt: str | None = None,
) -> str:
    """
    Call local Ollama instance (runs on your 4050 GPU)
    Use this for: code parsing, semantic analysis, fix generation
    (anything where you don't want to burn Groq's daily quota)

    Args:
        prompt: The text prompt to send
        model: Override default model (optional)
        timeout: Max seconds to wait for response

    Returns:
        The model's text response, or empty string on failure
    """
    model = model or OLLAMA_MODEL
    start = time.time()

    try:
        payload = {
            "model": model,
            "prompt": prompt,
            "stream": False,  # Get full response at once, not token-by-token
        }
        if system_prompt:
            payload["system"] = system_prompt

        response = requests.post(
            f"{OLLAMA_BASE_URL}/api/generate",
            json=payload,
            timeout=timeout
        )
        response.raise_for_status()
        data = response.json()

        elapsed = round(time.time() - start, 2)
        logger.info(f"Ollama call completed in {elapsed}s (model={model})")

        return data.get("response", "").strip()

    except requests.exceptions.Timeout:
        logger.error(f"Ollama call timed out after {timeout}s")
        return ""
    except requests.exceptions.ConnectionError:
        logger.error("Cannot connect to Ollama. Is it running? (ollama serve)")
        return ""
    except Exception as e:
        logger.error(f"Ollama call failed: {str(e)}")
        return ""


# ==================
# GROQ (CLOUD)
# ==================

def groq_call(
    prompt: str,
    model: str = None,
    max_tokens: int = 1024,
    system_prompt: str | None = None,
) -> str:
    """
    Call Groq API (cloud, fast, but rate-limited to 150 req/day on free tier)
    Use this for: severity reasoning, attack chain analysis
    (high-value reasoning tasks where you want a stronger model)

    Args:
        prompt: The text prompt to send
        model: Override default model (optional)
        max_tokens: Max tokens in response

    Returns:
        The model's text response, or empty string on failure
    """
    if not groq_client:
        logger.error("Groq API key not configured in .env")
        return ""

    model = model or GROQ_MODEL
    start = time.time()

    try:
        messages = [{"role": "user", "content": prompt}]
        if system_prompt:
            messages.insert(0, {"role": "system", "content": system_prompt})

        response = groq_client.chat.completions.create(
            model=model,
            messages=messages,
            max_tokens=max_tokens,
            temperature=0.2  # Low temperature = more deterministic, less creative
        )

        elapsed = round(time.time() - start, 2)
        logger.info(f"Groq call completed in {elapsed}s (model={model})")

        return response.choices[0].message.content.strip()

    except Exception as e:
        logger.error(f"Groq call failed: {str(e)}")
        return ""


# ==================
# SMART ROUTER (OPTIONAL HELPER)
# ==================

def llm_call(prompt: str, prefer: str = "ollama", **kwargs) -> str:
    """
    Smart wrapper that tries preferred provider first, falls back to the other.

    Args:
        prompt: The text prompt
        prefer: "ollama" or "groq"
        **kwargs: Passed through to the underlying call

    Returns:
        Response text, or empty string if both fail
    """
    if prefer == "groq":
        result = groq_call(prompt, **kwargs)
        if result:
            return result
        logger.warning("Groq failed, falling back to Ollama")
        return ollama_call(prompt, **kwargs)
    else:
        result = ollama_call(prompt, **kwargs)
        if result:
            return result
        logger.warning("Ollama failed, falling back to Groq")
        return groq_call(prompt, **kwargs)
