"""Pydantic response models for the Threat Intel Feed API.

These models serve as OpenAPI component schemas for client generation,
validation, and typed integration (Go/TS/Java/Python)."""

from pydantic import BaseModel, Field
from typing import Optional, Literal
from enum import Enum


# --- Enums ---

class ThreatLevel(str, Enum):
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


class AttackType(str, Enum):
    brute_force = "brute_force"
    credential_stuffing = "credential_stuffing"
    recon = "recon"
    discovery = "discovery"
    malware_deployment = "malware_deployment"
    cryptominer = "cryptominer"
    botnet_recruitment = "botnet_recruitment"
    lateral_movement = "lateral_movement"
    data_exfil = "data_exfil"
    unknown = "unknown"


class IndicatorType(str, Enum):
    ipv4_addr = "ipv4-addr"
    url = "url"
    file_hash = "file-hash"
    credential = "credential"


class RevocationReason(str, Enum):
    false_positive = "false_positive"
    benign_scanner = "benign_scanner"
    tor_exit = "tor_exit"
    researcher = "researcher"
    shared_infrastructure = "shared_infrastructure"
    other = "other"


# --- Shared sub-models ---

class CollectionWindow(BaseModel):
    first_observed: Optional[str] = Field(None, description="ISO 8601 timestamp of first observation")
    last_observed: Optional[str] = Field(None, description="ISO 8601 timestamp of most recent observation")


class ObservedFeatures(BaseModel):
    """Observable features driving classification. Enables explainability without relying on opaque model labels."""
    login_attempts: int = Field(0, description="Total credential attempts in session")
    successful_logins: int = Field(0, description="Successful authentications")
    commands_executed: int = Field(0, description="Shell commands run post-auth")
    files_downloaded: int = Field(0, description="Files fetched via wget/curl/tftp")
    download_command_seen: bool = Field(False, description="wget/curl/tftp observed")
    persistence_attempt: bool = Field(False, description="crontab/systemd/authorized_keys modification")
    system_recon: bool = Field(False, description="uname/lscpu/proc enumeration")
    mining_indicators: bool = Field(False, description="xmrig/stratum/pool references")
    network_scan: bool = Field(False, description="nmap/masscan/ssh to other hosts")
    data_access: bool = Field(False, description="Reading /etc/passwd, /etc/shadow, or similar")
    classification_method: str = Field("ai", description="'ai' (Ollama/Mistral) or 'rule_based' (fallback)")
    classifier_version: Optional[str] = Field(None, description="Classifier code version (semver)")
    model: Optional[str] = Field(None, description="LLM model used (null for rule_based)")
    prompt_hash: Optional[str] = Field(None, description="First 16 chars of SHA-256 of system prompt (null for rule_based)")


class PaginationOffset(BaseModel):
    limit: int = Field(..., description="Requested page size")
    offset: int = Field(..., description="Current offset")
    returned: int = Field(..., description="Records in this response")
    total: int = Field(..., description="Total matching records")
    has_more: bool = Field(..., description="More records available")


class PaginationCursor(BaseModel):
    limit: int = Field(..., description="Requested page size")
    cursor: Optional[str] = Field(None, description="Opaque cursor from the previous response; null on the first request")
    next_cursor: Optional[str] = Field(None, description="Cursor for next page. Null if no more records.")
    has_more: bool = Field(..., description="More records available")


# --- Error ---

class ErrorResponse(BaseModel):
    """Standard error response."""
    detail: str = Field(..., description="Human-readable error message")

    model_config = {"json_schema_extra": {"examples": [{"detail": "Indicator not found"}]}}


class RateLimitError(BaseModel):
    """429 Too Many Requests response."""
    error: str = Field("rate_limit_exceeded")
    detail: str = Field("Too many requests. See Retry-After header.")
    retry_after_seconds: int = Field(60, description="Seconds to wait before retrying")
    guidance: str = Field("Back off exponentially. Default rate: 100 req/min, STIX bundle: 30 req/min.")


# --- Health ---

class HealthResponse(BaseModel):
    status: str = Field("ok", description="API status")
    version: str = Field(..., description="API version (semver)")
    model_version: str = Field(..., description="AI model used for classification")
    feed_id: str = Field("honeypot-svr04", description="Unique feed/sensor identifier")
    last_update: Optional[str] = Field(None, description="ISO 8601 timestamp of last pipeline run")
    total_sessions: int = Field(0, description="Total attack sessions in database")
    total_indicators: int = Field(0, description="Total IOC indicators in database")


# --- Indicators ---

class IndicatorRecord(BaseModel):
    """A single IOC indicator with provenance, confidence, and collection metadata."""
    type: str = Field(..., description="Indicator type: ipv4-addr, url, file-hash")
    value: str = Field(..., description="Indicator value (IP, URL, or SHA-256 hash)")
    first_seen: Optional[str] = Field(None, description="ISO 8601 first observation")
    last_seen: Optional[str] = Field(None, description="ISO 8601 most recent observation")
    times_seen: int = Field(1, description="Number of sessions this indicator appeared in")
    threat_level: Optional[str] = Field(None, description="low/medium/high/critical")
    confidence: int = Field(50, ge=0, le=100, description="Confidence score (0-100). Maps: low=40, medium=65, high=85, critical=95")
    revoked: bool = Field(False, description="True if marked as false positive/researcher/Tor exit")
    revoked_reason: Optional[str] = Field(None, description="Revocation reason if revoked")
    sensor_id: str = Field("honeypot-svr04", description="Sensor that observed this indicator")
    feed_id: str = Field("honeypot-svr04", description="Feed identifier")
    collection_window: CollectionWindow | None = Field(None, description="Observation time window")
    stix_object: Optional[dict] = Field(None, description="Inline STIX indicator object (only when include=stix)")

    model_config = {"json_schema_extra": {"examples": [{
        "type": "ipv4-addr", "value": "176.120.22.52",
        "first_seen": "2026-01-15T03:22:10Z", "last_seen": "2026-02-19T14:08:33Z",
        "times_seen": 14, "threat_level": "high", "confidence": 85,
        "revoked": False, "sensor_id": "honeypot-svr04", "feed_id": "honeypot-svr04",
        "collection_window": {"first_observed": "2026-01-15T03:22:10Z", "last_observed": "2026-02-19T14:08:33Z"},
    }]}}


class FeedResponseOffset(BaseModel):
    """IOC feed response with offset-based pagination."""
    feed_id: str = Field("honeypot-svr04")
    sensor_id: str = Field("honeypot-svr04")
    generated_at: str = Field(..., description="ISO 8601 generation timestamp")
    model_version: str = Field(..., description="AI model version")
    indicator_count: int = Field(..., description="Number of indicators in this response")
    pagination: PaginationOffset
    indicators: list[IndicatorRecord]


class FeedResponseCursor(BaseModel):
    """IOC feed response with cursor-based pagination (for SIEM ingestion)."""
    feed_id: str = Field("honeypot-svr04")
    sensor_id: str = Field("honeypot-svr04")
    generated_at: str = Field(..., description="ISO 8601 generation timestamp")
    model_version: str = Field(..., description="AI model version")
    indicator_count: int = Field(..., description="Number of indicators in this response")
    pagination: PaginationCursor
    indicators: list[IndicatorRecord]


class IndicatorListResponse(BaseModel):
    """Paginated indicator list."""
    indicators: list[IndicatorRecord]
    pagination: PaginationOffset


# --- Sessions ---

class SessionSummary(BaseModel):
    """Attack session summary (list view, no STIX bundle)."""
    session_id: str = Field(..., description="Unique session identifier from Cowrie")
    src_ip: str = Field(..., description="Attacker source IP")
    timestamp_start: Optional[str] = None
    timestamp_end: Optional[str] = None
    duration_seconds: Optional[float] = None
    ssh_client: Optional[str] = Field(None, description="SSH client version string")
    hassh: Optional[str] = Field(None, description="HASSH fingerprint of SSH client")
    attack_type: Optional[str] = Field(None, description="Classified attack type (see AttackType enum)")
    threat_level: Optional[str] = Field(None, description="low/medium/high/critical")
    confidence: int = Field(50, ge=0, le=100)
    model_version: str = Field(..., description="Model used for this classification")
    mitre_techniques: list[str] = Field(default_factory=list, description="MITRE ATT&CK technique IDs")
    summary: Optional[str] = Field(None, description="Human-readable attack summary")
    country: Optional[str] = Field(None, description="2-letter country code (best-effort)")
    asn: Optional[str] = Field(None, description="Autonomous System Number")
    org: Optional[str] = Field(None, description="ISP/hosting provider")
    cloud_provider: Optional[str] = Field(None, description="Detected cloud provider (AWS, DO, Hetzner, etc.)")
    observed_features: Optional[ObservedFeatures] = Field(None, description="Observable features driving classification")


class CredentialAttempt(BaseModel):
    username: str
    password: str = Field("***", description="Always redacted in API responses")
    success: bool


class DownloadRecord(BaseModel):
    url: str = Field(..., description="URL the attacker fetched")
    sha256: str = Field(..., description="SHA-256 hash of downloaded file")


class SessionDetail(SessionSummary):
    """Full session detail including commands, credentials, downloads, and STIX bundle."""
    commands: list[str] = Field(default_factory=list, description="Shell commands executed")
    credentials_attempted: list[CredentialAttempt] = Field(default_factory=list, description="Login attempts (passwords redacted)")
    downloads: list[DownloadRecord] = Field(default_factory=list, description="Files downloaded by attacker")
    stix_bundle: Optional[dict] = Field(None, description="Complete STIX 2.1 bundle for this session")


class SessionListResponse(BaseModel):
    sessions: list[SessionSummary]
    pagination: PaginationOffset


# --- Stats ---

class ASNEntry(BaseModel):
    asn: str
    org: Optional[str] = None
    count: int


class RecentSession(BaseModel):
    id: str
    src_ip: str
    attack_type: Optional[str] = None
    threat_level: Optional[str] = None
    mitre_techniques: Optional[str] = None
    summary: Optional[str] = None
    timestamp_start: Optional[str] = None
    country: Optional[str] = None
    asn: Optional[str] = None
    org: Optional[str] = None


class RecentIndicator(BaseModel):
    type: str
    value: str
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None
    times_seen: int = 1
    threat_level: Optional[str] = None


class StatsResponse(BaseModel):
    total_sessions: int = 0
    total_indicators: int = 0
    total_malware_samples: int = 0
    attack_types: dict[str, int] = Field(default_factory=dict, description="Attack type distribution")
    threat_levels: dict[str, int] = Field(default_factory=dict, description="Threat level distribution")
    top_source_ips: list[dict] = Field(default_factory=list, description="Top attacker IPs by session count")
    top_credentials: list[dict] = Field(default_factory=list, description="Top credentials (passwords redacted)")
    mitre_technique_frequency: dict[str, int] = Field(default_factory=dict, description="MITRE ATT&CK technique hit counts")
    top_countries: dict[str, int] = Field(default_factory=dict, description="Country code distribution")
    top_asns: list[ASNEntry] = Field(default_factory=list, description="Top ASNs by session count")
    recent_sessions: list[RecentSession] = Field(default_factory=list, description="3 most recent sessions")
    recent_indicators: list[RecentIndicator] = Field(default_factory=list, description="5 most recent indicators")
    last_update: Optional[str] = None
    model_version: Optional[str] = None
    api_version: Optional[str] = None


# --- IP Sightings ---

class IPSightingResponse(BaseModel):
    ip: str
    sighting_count: int = Field(..., description="Number of sessions from this IP")
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None
    asn: Optional[str] = None
    org: Optional[str] = None
    country: Optional[str] = None
    cloud_provider: Optional[str] = None


# --- Integrity ---

class IntegrityResponse(BaseModel):
    dataset_fingerprint: str = Field(..., description="SHA-256 fingerprint over indicator dataset")
    coverage: str = Field(..., description="Description of what the fingerprint covers")
    total_sessions: int = 0
    total_indicators: int = 0
    total_malware_samples: int = 0
    last_update: Optional[str] = None
    generated_at: str = Field(..., description="ISO 8601 timestamp this hash was computed")
    verify: str = Field(..., description="Verification instructions")


# --- Revocation ---

class RevocationResponse(BaseModel):
    status: str = Field(..., description="'revoked' or 'active'")
    value: str = Field(..., description="Indicator value")
    reason: Optional[str] = Field(None, description="Revocation reason (if revoked)")


# --- TAXII ---

class TAXIIDiscovery(BaseModel):
    title: str
    description: str
    default: str
    api_roots: list[str]


class TAXIICollection(BaseModel):
    id: str
    title: str
    description: str
    can_read: bool = True
    can_write: bool = False
    media_types: list[str] = Field(default_factory=lambda: ["application/stix+json;version=2.1"])


class TAXIICollections(BaseModel):
    collections: list[TAXIICollection]


# --- About (JSON) ---

class ScoringLevel(BaseModel):
    confidence: int
    description: str


class ScoringInfo(BaseModel):
    method: str
    threat_level: dict[str, ScoringLevel]
    indicator_ttl_days: int = 7
    notes: str


class AboutResponse(BaseModel):
    feed_id: str
    producer: str
    api_version: str
    model_version: str
    stix_version: str = "2.1"
    tlp_marking: str = "TLP:CLEAR"
    docs: dict[str, str]
    scoring: ScoringInfo
    attack_types: list[str]
    data_handling: dict
    source: str
    rate_limits: dict[str, str]
