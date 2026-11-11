import logging
import os
from contextlib import asynccontextmanager
from typing import Optional

from fastapi import FastAPI, HTTPException, status
from fastapi.responses import JSONResponse
import redis

from .schemas import ReputationLookupRequest, ReputationLookupResponse

# Security Invariant: Configure logging to exclude request bodies or query values
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("reputation_service")

# In-memory mock Redis cache when live Redis server is not connected
class MemoryCache:
    def __init__(self):
        self._data = {}

    def get(self, key: str) -> Optional[str]:
        return self._data.get(key)

    def setex(self, key: str, time: int, value: str):
        self._data[key] = value

redis_client = None

@asynccontextmanager
async def lifespan(app: FastAPI):
    global redis_client
    redis_url = os.environ.get("REDIS_URL", "redis://localhost:6379/0")
    try:
        r = redis.from_url(redis_url, socket_timeout=1.0)
        r.ping()
        redis_client = r
        logger.info("Connected to Redis cache.")
    except Exception as e:
        logger.warning("Redis unavailable (%s); falling back to safe local cache.", e)
        redis_client = MemoryCache()
    yield
    redis_client = None

app = FastAPI(
    title="Peek-in QR Reputation Service",
    version="1.0.0",
    lifespan=lifespan,
)

# Known test feeds (simulated threat feed adapter with known malicious hashes)
KNOWN_MALICIOUS_HASH_PREFIXES = {
    "e3b0c44298fc1c14", # example hash prefix
    "a1b2c3d4e5f67890",
}

@app.get("/health")
def health():
    return {"status": "ok", "service": "reputation"}

@app.post(
    "/v1/reputation/lookup",
    response_model=ReputationLookupResponse,
    status_code=status.HTTP_200_OK,
)
def lookup_reputation(payload: ReputationLookupRequest):
    token = payload.lookup_token

    # 1. Check Redis cache first
    cached_val = None
    if redis_client is not None:
        try:
            cached_val = redis_client.get(f"rep:{token}")
        except Exception:
            cached_val = None

    if cached_val:
        return ReputationLookupResponse(
            status=cached_val.decode() if isinstance(cached_val, bytes) else str(cached_val),
            token_prefix=token[:16],
            cached=True,
            source="redis_cache",
            message="Verdict retrieved from cache.",
        )

    # 2. Check Threat Intelligence Feed Adapter
    # Invariant: Never fabricate reputation. If no match exists in curated threat feed,
    # return UNKNOWN or UNAVAILABLE, never clean/VERIFIED.
    is_malicious = any(token.startswith(prefix) for prefix in KNOWN_MALICIOUS_HASH_PREFIXES)

    if is_malicious:
        verdict = "VERIFIED_MALICIOUS"
        score = 0.95
        msg = "Token matches verified high-confidence malicious threat feed entry."
    else:
        # Per master prompt: Backend returns UNKNOWN/UNAVAILABLE if no vetted feed exists or matches
        verdict = "UNKNOWN"
        score = None
        msg = "No threat records found for token in threat feed. Target is unclassified."

    # Cache result with TTL (e.g. 3600 seconds)
    if redis_client is not None:
        try:
            redis_client.setex(f"rep:{token}", 3600, verdict)
        except Exception:
            pass

    return ReputationLookupResponse(
        status=verdict,
        token_prefix=token[:16],
        reputation_score=score,
        cached=False,
        source="curated_threat_feed",
        message=msg,
    )
