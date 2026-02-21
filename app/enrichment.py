"""Ollama AI enrichment client for attack session classification."""

import hashlib
import json
import logging
import os
import aiohttp
from typing import Optional

logger = logging.getLogger(__name__)

OLLAMA_URL = os.environ.get("OLLAMA_URL", "http://192.168.10.97:11434")
OLLAMA_MODEL = os.environ.get("OLLAMA_MODEL", "mistral-small3.2:24b")
TIMEOUT = 30  # seconds
CLASSIFIER_VERSION = "1.5.0"

SYSTEM_PROMPT = """You are a cybersecurity threat analyst. Analyze the SSH honeypot session data and classify the attack.

Respond with ONLY valid JSON (no markdown, no explanation):
{
  "attack_type": "brute_force|credential_stuffing|recon|malware_deployment|cryptominer|botnet_recruitment|lateral_movement|data_exfil|unknown",
  "mitre_techniques": ["T1110.001"],
  "threat_level": "low|medium|high|critical",
  "summary": "One-line human-readable summary"
}

Classification rules:
- brute_force: Multiple failed logins, few/no commands after success
- credential_stuffing: Varied username/password combos tried systematically
- recon: Successful login followed by system enumeration (uname, /proc, lscpu, etc.)
- malware_deployment: wget/curl downloads, file execution, persistence mechanisms
- cryptominer: Downloads + CPU-intensive processes, mining pool connections
- botnet_recruitment: Downloads + outbound connections, IRC, C2 patterns
- lateral_movement: Network scanning, SSH to other hosts
- data_exfil: Reading sensitive files, encoding/exfiltrating data
- recon: Also use for bare connections with no login attempts (port scans, banner grabs, SSH version probes)
- unknown: ONLY if data is corrupted or truly uninterpretable. Bare connections and scans are recon, not unknown.

Threat levels:
- low: Failed brute force only, no successful login
- medium: Successful login + basic recon
- high: Malware download or persistent access
- critical: Active exploitation, cryptominer, or botnet with C2"""


async def enrich_session(session: dict) -> dict:
    """
    Enrich a session with AI classification via Ollama.

    Args:
        session: Assembled session dict with credentials_attempted, commands, downloads.

    Returns:
        Dict with attack_type, mitre_techniques, threat_level, summary.
        Returns defaults on failure.
    """
    # Build a concise session summary for the LLM
    session_summary = _build_session_summary(session)

    try:
        payload = {
            "model": OLLAMA_MODEL,
            "messages": [
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": f"Analyze this SSH honeypot session:\n\n{session_summary}"},
            ],
            "stream": False,
            "format": "json",
            "options": {
                "temperature": 0.1,
                "num_predict": 512,
            },
        }

        timeout = aiohttp.ClientTimeout(total=TIMEOUT)
        async with aiohttp.ClientSession(timeout=timeout) as http:
            async with http.post(f"{OLLAMA_URL}/api/chat", json=payload) as resp:
                if resp.status != 200:
                    logger.error(f"Ollama returned {resp.status}: {await resp.text()}")
                    return _default_enrichment(session)

                data = await resp.json()
                content = data.get("message", {}).get("content", "")

                try:
                    result = json.loads(content)
                    return _validate_enrichment(result, session)
                except json.JSONDecodeError:
                    logger.error(f"Failed to parse Ollama response as JSON: {content[:200]}")
                    return _default_enrichment(session)

    except aiohttp.ClientError as e:
        logger.error(f"Ollama connection error: {e}")
        return _default_enrichment(session)
    except Exception as e:
        logger.error(f"Enrichment failed: {e}")
        return _default_enrichment(session)


def _build_session_summary(session: dict) -> str:
    """Build a concise text summary of the session for the LLM."""
    parts = [
        f"Source IP: {session.get('src_ip', 'unknown')}",
        f"Duration: {session.get('duration_seconds', 0)}s",
        f"SSH Client: {session.get('ssh_client', 'unknown')}",
    ]

    creds = session.get("credentials_attempted", [])
    if creds:
        failed = sum(1 for c in creds if not c.get("success"))
        success = sum(1 for c in creds if c.get("success"))
        parts.append(f"Login attempts: {len(creds)} ({failed} failed, {success} success)")
        # Show unique credentials
        unique = list({f"{c['username']}:{c['password']}" for c in creds})[:10]
        parts.append(f"Credentials tried: {', '.join(unique)}")

    commands = session.get("commands", [])
    if commands:
        parts.append(f"Commands executed ({len(commands)}):")
        for cmd in commands[:15]:
            # Truncate very long commands
            display = cmd[:200] + "..." if len(cmd) > 200 else cmd
            parts.append(f"  $ {display}")

    downloads = session.get("downloads", [])
    if downloads:
        parts.append(f"Files downloaded ({len(downloads)}):")
        for dl in downloads:
            parts.append(f"  URL: {dl.get('url', 'N/A')}, SHA256: {dl.get('sha256', 'N/A')[:16]}...")

    if session.get("hassh"):
        parts.append(f"HASSH: {session['hassh']}")

    return "\n".join(parts)


CLOUD_PROVIDER_ASNS = {
    "AS14061": "DigitalOcean", "AS16276": "OVH", "AS63949": "Linode/Akamai",
    "AS16509": "Amazon AWS", "AS15169": "Google Cloud", "AS8075": "Microsoft Azure",
    "AS13335": "Cloudflare", "AS20473": "Vultr", "AS24940": "Hetzner",
    "AS46606": "DigitalOcean", "AS201011": "Scaleway", "AS9009": "M247",
    "AS62567": "DigitalOcean", "AS132203": "Tencent Cloud", "AS45102": "Alibaba Cloud",
    "AS37963": "Alibaba Cloud", "AS396982": "Google Cloud",
}


async def enrich_ip_geo(ip: str) -> dict:
    """
    Enrich an IP with ASN, org, country, and cloud provider via ipwho.is.
    Returns dict with asn, org, country, cloud_provider (all optional).
    """
    try:
        timeout = aiohttp.ClientTimeout(total=5)
        async with aiohttp.ClientSession(timeout=timeout) as http:
            async with http.get(f"https://ipwho.is/{ip}") as resp:
                if resp.status != 200:
                    return {}
                data = await resp.json()
                if not data.get("success", True):
                    return {}
                asn_num = str(data.get("connection", {}).get("asn", ""))
                org = data.get("connection", {}).get("org", "")
                country = data.get("country_code", "")
                cloud = CLOUD_PROVIDER_ASNS.get(asn_num, "")
                return {
                    "asn": asn_num,
                    "org": org,
                    "country": country,
                    "cloud_provider": cloud,
                }
    except Exception as e:
        logger.warning(f"IP geo enrichment failed for {ip}: {e}")
        return {}


VALID_ATTACK_TYPES = {
    "brute_force", "credential_stuffing", "recon", "malware_deployment",
    "cryptominer", "botnet_recruitment", "lateral_movement", "data_exfil", "unknown",
}
VALID_THREAT_LEVELS = {"low", "medium", "high", "critical"}


def _validate_enrichment(result: dict, session: dict) -> dict:
    """Validate and sanitize the AI enrichment result."""
    attack_type = result.get("attack_type", "unknown")
    if attack_type not in VALID_ATTACK_TYPES:
        attack_type = "unknown"

    # Reclassify "unknown" to "recon" for bare connections (port scans, banner grabs)
    if attack_type == "unknown":
        creds = session.get("credentials_attempted", [])
        commands = session.get("commands", [])
        downloads = session.get("downloads", [])
        if not creds and not commands and not downloads:
            attack_type = "recon"

    threat_level = result.get("threat_level", "medium")
    if threat_level not in VALID_THREAT_LEVELS:
        threat_level = "medium"

    mitre = result.get("mitre_techniques", [])
    if not isinstance(mitre, list):
        mitre = []
    # Validate technique IDs look reasonable
    mitre = [t for t in mitre if isinstance(t, str) and t.startswith("T") and len(t) <= 12]

    summary = result.get("summary", "")
    if not isinstance(summary, str) or len(summary) > 500:
        summary = f"{attack_type} from {session.get('src_ip', 'unknown')}"

    features = extract_observed_features(session)
    features["classification_method"] = "ai"
    features["classifier_version"] = CLASSIFIER_VERSION
    features["model"] = OLLAMA_MODEL
    features["prompt_hash"] = hashlib.sha256(SYSTEM_PROMPT.encode()).hexdigest()[:16]
    return {
        "attack_type": attack_type,
        "mitre_techniques": mitre,
        "threat_level": threat_level,
        "summary": summary,
        "observed_features": features,
    }


def extract_observed_features(session: dict) -> dict:
    """Extract observable features from a session for explainability."""
    creds = session.get("credentials_attempted", [])
    commands = session.get("commands", [])
    downloads = session.get("downloads", [])
    cmd_text = " ".join(commands).lower() if commands else ""

    return {
        "login_attempts": len(creds),
        "successful_logins": sum(1 for c in creds if c.get("success")),
        "commands_executed": len(commands),
        "files_downloaded": len(downloads),
        "download_command_seen": any(kw in cmd_text for kw in ["wget", "curl", "tftp", "/dev/tcp"]),
        "persistence_attempt": any(kw in cmd_text for kw in ["crontab", "systemctl", "authorized_keys", ".bashrc", "/etc/rc.local"]),
        "system_recon": any(kw in cmd_text for kw in ["uname", "lscpu", "/proc/cpuinfo", "nproc", "cat /etc/issue", "whoami", "id "]),
        "mining_indicators": any(kw in cmd_text for kw in ["xmrig", "minerd", "stratum", "pool.", "cryptonight"]),
        "network_scan": any(kw in cmd_text for kw in ["nmap", "masscan", "zmap", "ssh ", "sshpass"]),
        "data_access": any(kw in cmd_text for kw in ["/etc/passwd", "/etc/shadow", ".ssh/id_rsa", "cat /etc"]),
        "classification_method": "ai",  # overridden to "rule_based" in fallback
        "classifier_version": CLASSIFIER_VERSION,
        "prompt_hash": hashlib.sha256(SYSTEM_PROMPT.encode()).hexdigest()[:16],
    }


def _default_enrichment(session: dict) -> dict:
    """Return a rule-based fallback classification when AI is unavailable."""
    creds = session.get("credentials_attempted", [])
    commands = session.get("commands", [])
    downloads = session.get("downloads", [])
    src_ip = session.get("src_ip", "unknown")

    techniques = []
    attack_type = "recon"  # Default: bare connections are reconnaissance
    threat_level = "low"

    # Bare connections with no activity are port scans / banner grabs
    if not creds and not commands and not downloads:
        techniques.append("T1595.002")  # Active Scanning: Vulnerability Scanning
        return {
            "attack_type": "recon",
            "mitre_techniques": techniques,
            "threat_level": "low",
            "summary": f"Port scan or SSH banner grab from {src_ip}",
            "observed_features": {
                **extract_observed_features(session),
                "classification_method": "rule_based",
                "classifier_version": CLASSIFIER_VERSION,
                "model": None,
                "prompt_hash": None,
            },
        }

    if creds:
        failed = sum(1 for c in creds if not c.get("success"))
        success = sum(1 for c in creds if c.get("success"))

        if failed > 0:
            techniques.append("T1110.001")
            attack_type = "brute_force"
            threat_level = "low"

        if success > 0:
            techniques.append("T1078")
            threat_level = "medium"

    if commands:
        techniques.append("T1059.004")
        attack_type = "recon" if not downloads else attack_type
        threat_level = "medium"

        # Check for common patterns
        cmd_text = " ".join(commands).lower()
        if any(kw in cmd_text for kw in ["wget", "curl", "tftp", "/dev/tcp"]):
            techniques.append("T1105")
            attack_type = "malware_deployment"
            threat_level = "high"
        if any(kw in cmd_text for kw in ["uname", "/proc/cpuinfo", "lscpu", "nproc"]):
            techniques.append("T1082")
        if any(kw in cmd_text for kw in ["xmrig", "minerd", "stratum", "pool"]):
            techniques.append("T1496")
            attack_type = "cryptominer"
            threat_level = "critical"

    if downloads:
        if "T1105" not in techniques:
            techniques.append("T1105")
        attack_type = "malware_deployment"
        threat_level = "high"

    summary = f"{attack_type.replace('_', ' ').title()} from {src_ip}"
    if len(creds) > 0:
        summary += f" ({len(creds)} credential attempts)"
    if commands:
        summary += f", {len(commands)} commands"
    if downloads:
        summary += f", {len(downloads)} downloads"

    features = extract_observed_features(session)
    features["classification_method"] = "rule_based"
    features["classifier_version"] = CLASSIFIER_VERSION
    features["model"] = None
    features["prompt_hash"] = None
    return {
        "attack_type": attack_type,
        "mitre_techniques": techniques,
        "threat_level": threat_level,
        "summary": summary,
        "observed_features": features,
    }
