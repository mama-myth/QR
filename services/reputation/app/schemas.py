import re
from typing import Optional
from pydantic import BaseModel, Field, field_validator

class ReputationLookupRequest(BaseModel):
    lookup_token: str = Field(
        ...,
        min_length=8,
        max_length=64,
        description="Truncated hash prefix or SHA-256 token of the target identifier. Never submit raw URLs, paths, queries, or PII.",
    )
    protocol_version: str = Field(default="1.0.0", max_length=16)

    @field_validator("lookup_token")
    @classmethod
    def validate_no_pii_or_raw_url(cls, v: str) -> str:
        # Check against raw URL schemes
        if re.search(r"^(https?|ftp|tel|upi|wifi):", v, re.IGNORECASE):
            raise ValueError("Raw URI schemes are prohibited. Provide an anonymized hash token only.")

        # Check for query strings, slashes, or path characters
        if any(c in v for c in ["/", "?", "&", "=", "@", ":", ";"]):
            raise ValueError("Token must not contain URL path, query delimiters, credentials, or PII.")

        # Must be valid hex characters
        if not re.match(r"^[a-fA-F0-9]+$", v):
            raise ValueError("Lookup token must be a hexadecimal hash prefix or digest.")

        return v.lower()

class ReputationLookupResponse(BaseModel):
    status: str  # 'VERIFIED_MALICIOUS', 'CLEAN', 'UNAVAILABLE', 'UNKNOWN'
    token_prefix: str
    reputation_score: Optional[float] = None
    cached: bool = False
    source: str = "curated_threat_feed"
    message: str
