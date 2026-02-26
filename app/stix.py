"""STIX 2.1 bundle generator for threat intel feed."""

import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

# MITRE ATT&CK technique ID → name mapping (common honeypot techniques)
MITRE_TECHNIQUES = {
    "T1110": "Brute Force",
    "T1110.001": "Brute Force: Password Guessing",
    "T1110.003": "Brute Force: Password Spraying",
    "T1110.004": "Brute Force: Credential Stuffing",
    "T1078": "Valid Accounts",
    "T1059.004": "Command and Scripting Interpreter: Unix Shell",
    "T1105": "Ingress Tool Transfer",
    "T1496": "Resource Hijacking",
    "T1082": "System Information Discovery",
    "T1033": "System Owner/User Discovery",
    "T1087": "Account Discovery",
    "T1547": "Boot or Logon Autostart Execution",
    "T1053": "Scheduled Task/Job",
    "T1070": "Indicator Removal",
    "T1021.004": "Remote Services: SSH",
    "T1133": "External Remote Services",
    "T1190": "Exploit Public-Facing Application",
    "T1595": "Active Scanning",
    "T1595.002": "Active Scanning: Vulnerability Scanning",
    "T1592": "Gather Victim Host Information",
}

# Technique → kill chain phase
TECHNIQUE_PHASES = {
    "T1110": "credential-access",
    "T1110.001": "credential-access",
    "T1110.003": "credential-access",
    "T1110.004": "credential-access",
    "T1078": "initial-access",
    "T1059.004": "execution",
    "T1105": "command-and-control",
    "T1496": "impact",
    "T1082": "discovery",
    "T1033": "discovery",
    "T1087": "discovery",
    "T1547": "persistence",
    "T1053": "persistence",
    "T1070": "defense-evasion",
    "T1021.004": "lateral-movement",
    "T1133": "initial-access",
    "T1190": "initial-access",
    "T1595": "reconnaissance",
    "T1595.002": "reconnaissance",
    "T1592": "reconnaissance",
}


def _deterministic_uuid(namespace: str, *parts: Any) -> str:
    """Generate a deterministic UUID5 from namespace + parts."""
    ns_uuid = uuid.uuid5(uuid.NAMESPACE_URL, f"https://threat-intel.101904.xyz/{namespace}")
    combined = ":".join(str(p) for p in parts)
    return str(uuid.uuid5(ns_uuid, combined))


def _stix_id(stix_type: str, *parts: Any) -> str:
    """Generate a STIX-compliant deterministic ID."""
    return f"{stix_type}--{_deterministic_uuid(stix_type, *parts)}"


def _now_iso() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S.000Z")


def _valid_until(from_ts: str, days: float = 7) -> str:
    """Calculate valid_until timestamp."""
    try:
        dt = datetime.fromisoformat(from_ts.replace("Z", "+00:00"))
        return (dt + timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    except (ValueError, AttributeError):
        dt = datetime.now(UTC) + timedelta(days=days)
        return dt.strftime("%Y-%m-%dT%H:%M:%S.000Z")


# Shared STIX objects — reused across all bundles
PRODUCER_IDENTITY = {
    "type": "identity",
    "spec_version": "2.1",
    "id": _stix_id("identity", "honeypot-svr04"),
    "created": "2026-01-01T00:00:00.000Z",
    "modified": "2026-01-01T00:00:00.000Z",
    "name": "Honeypot SVR04 Threat Intel Feed",
    "identity_class": "system",
    "description": "AI-enriched SSH honeypot threat intelligence feed. "
                   "Data is derived from a Cowrie SSH honeypot and classified "
                   "using Mistral Small 3.2 with rule-based fallback.",
    "contact_information": "https://github.com/Tristan1019-user/honeypot-threat-intel",
}

TLP_CLEAR_MARKING = {
    "type": "marking-definition",
    "spec_version": "2.1",
    "id": "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9",
    "created": "2017-01-20T00:00:00.000Z",
    "definition_type": "tlp",
    "name": "TLP:CLEAR",
    "definition": {"tlp": "clear"},
}


def _threat_level_to_confidence(threat_level: str | None) -> int:
    """Map threat level to STIX confidence score."""
    level = threat_level or ""
    return {"critical": 95, "high": 85, "medium": 65, "low": 40}.get(level, 50)


def session_to_stix_bundle(session: dict[str, Any]) -> dict[str, Any]:
    """
    Convert an enriched session dict to a STIX 2.1 bundle.

    Expected session keys:
        session_id, src_ip, timestamp_start, timestamp_end, ssh_client, hassh,
        attack_type, threat_level, mitre_techniques, mitre_names, summary,
        credentials_attempted, commands, downloads
    """
    objects: list[dict[str, Any]] = []
    session_id = session.get("session_id", "unknown")
    src_ip = session.get("src_ip", "0.0.0.0")
    ts_start = session.get("timestamp_start", _now_iso())
    ts_end = session.get("timestamp_end", ts_start)
    threat_level = session.get("threat_level", "medium")
    attack_type = session.get("attack_type", "unknown")
    summary = session.get("summary", f"SSH attack from {src_ip}")
    mitre_techniques = session.get("mitre_techniques", [])
    confidence = _threat_level_to_confidence(threat_level)

    identity_id = PRODUCER_IDENTITY["id"]

    # 1. Identity + TLP marking
    objects.append(PRODUCER_IDENTITY)
    objects.append(TLP_CLEAR_MARKING)

    # 2. IPv4 address observable
    ipv4_id = _stix_id("ipv4-addr", src_ip)
    objects.append({
        "type": "ipv4-addr",
        "spec_version": "2.1",
        "id": ipv4_id,
        "value": src_ip,
    })

    # 3. Network traffic observable
    traffic_id = _stix_id("network-traffic", session_id, src_ip)
    objects.append({
        "type": "network-traffic",
        "spec_version": "2.1",
        "id": traffic_id,
        "src_ref": ipv4_id,
        "dst_port": 22,
        "protocols": ["tcp", "ssh"],
    })

    # 4. Main indicator
    indicator_id = _stix_id("indicator", session_id, src_ip)
    kill_chain_phases: list[dict[str, str]] = []
    for t in mitre_techniques:
        phase = TECHNIQUE_PHASES.get(t)
        if phase:
            kill_chain_phases.append({
                "kill_chain_name": "mitre-attack",
                "phase_name": phase,
            })

    indicator_obj: dict[str, Any] = {
        "type": "indicator",
        "spec_version": "2.1",
        "id": indicator_id,
        "created": ts_start,
        "modified": ts_start,
        "name": f"Malicious SSH source: {src_ip}",
        "description": summary,
        "pattern": f"[ipv4-addr:value = '{src_ip}']",
        "pattern_type": "stix",
        "valid_from": ts_start,
        "valid_until": _valid_until(ts_start),
        "labels": ["malicious-activity", attack_type],
        "confidence": confidence,
        "created_by_ref": identity_id,
        "object_marking_refs": [TLP_CLEAR_MARKING["id"]],
    }
    if kill_chain_phases:
        indicator_obj["kill_chain_phases"] = kill_chain_phases
    objects.append(indicator_obj)

    # 5. Observed data
    observed_id = _stix_id("observed-data", session_id)
    objects.append({
        "type": "observed-data",
        "spec_version": "2.1",
        "id": observed_id,
        "first_observed": ts_start,
        "last_observed": ts_end,
        "number_observed": 1,
        "object_refs": [ipv4_id, traffic_id],
        "created_by_ref": identity_id,
        "object_marking_refs": [TLP_CLEAR_MARKING["id"]],
    })

    # 6. Attack patterns (MITRE ATT&CK)
    attack_pattern_ids: list[str] = []
    for technique_id in mitre_techniques:
        technique_name = MITRE_TECHNIQUES.get(technique_id, technique_id)
        ap_id = _stix_id("attack-pattern", technique_id)
        attack_pattern_ids.append(ap_id)
        objects.append({
            "type": "attack-pattern",
            "spec_version": "2.1",
            "id": ap_id,
            "name": technique_name,
            "external_references": [
                {
                    "source_name": "mitre-attack",
                    "external_id": technique_id,
                    "url": f"https://attack.mitre.org/techniques/{technique_id.replace('.', '/')}/",
                }
            ],
        })

    # 7. Malware objects for downloads
    downloads = session.get("downloads", [])
    for dl in downloads:
        sha256 = dl.get("sha256")
        if sha256:
            malware_id = _stix_id("malware", sha256)
            objects.append({
                "type": "malware",
                "spec_version": "2.1",
                "id": malware_id,
                "is_family": False,
                "name": f"Downloaded binary {sha256[:12]}...",
                "description": f"Binary downloaded from {dl.get('url', 'unknown')}",
                "malware_types": ["unknown"],
                "hashes": {"SHA-256": sha256},
            })
            # Relationship: indicator → delivers malware
            objects.append({
                "type": "relationship",
                "spec_version": "2.1",
                "id": _stix_id("relationship", indicator_id, "delivers", malware_id),
                "relationship_type": "delivers",
                "source_ref": indicator_id,
                "target_ref": malware_id,
                "created": ts_start,
                "modified": ts_start,
            })

    # 8. Relationships: indicator → indicates → attack-pattern
    for ap_id in attack_pattern_ids:
        objects.append({
            "type": "relationship",
            "spec_version": "2.1",
            "id": _stix_id("relationship", indicator_id, "indicates", ap_id),
            "relationship_type": "indicates",
            "source_ref": indicator_id,
            "target_ref": ap_id,
            "created": ts_start,
            "modified": ts_start,
        })

    # Relationship: indicator → based-on → observed-data
    objects.append({
        "type": "relationship",
        "spec_version": "2.1",
        "id": _stix_id("relationship", indicator_id, "based-on", observed_id),
        "relationship_type": "based-on",
        "source_ref": indicator_id,
        "target_ref": observed_id,
        "created": ts_start,
        "modified": ts_start,
    })

    # Clean None values from objects
    cleaned: list[dict[str, Any]] = []
    for obj in objects:
        cleaned.append({k: v for k, v in obj.items() if v is not None})

    bundle_id = f"bundle--{_deterministic_uuid('bundle', session_id)}"
    return {
        "type": "bundle",
        "id": bundle_id,
        "objects": cleaned,
    }


def merge_stix_bundles(bundles: list[dict[str, Any]]) -> dict[str, Any]:
    """Merge multiple STIX bundles into one, deduplicating by object ID."""
    seen_ids: set[str] = set()
    all_objects: list[dict[str, Any]] = []
    for bundle in bundles:
        for obj in bundle.get("objects", []):
            obj_id = obj.get("id")
            if obj_id and obj_id not in seen_ids:
                seen_ids.add(obj_id)
                all_objects.append(obj)

    return {
        "type": "bundle",
        "id": f"bundle--{uuid.uuid4()}",
        "objects": all_objects,
    }
