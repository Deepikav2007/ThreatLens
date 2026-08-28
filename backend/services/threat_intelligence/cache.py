"""
MailTrace AI - Threat Intelligence In-Memory TTL Cache
Feature 5: Threat Intelligence
"""

import time
import threading
from typing import Any, Optional, Dict, Tuple


class ThreatIntelCache:
    """
    Thread-safe in-memory cache for threat intelligence lookups.
    Stores cached provider results with customizable TTLs to prevent redundant API queries.
    """
    def __init__(self, default_ttl_seconds: int = 3600):
        self.default_ttl = default_ttl_seconds
        self._cache: Dict[str, Tuple[Any, float]] = {}  # key -> (data, expires_at)
        self._lock = threading.Lock()
        self.hits = 0
        self.misses = 0

    def _make_key(self, provider: str, indicator_type: str, indicator: str) -> str:
        return f"{provider.lower()}:{indicator_type.lower()}:{indicator.strip().lower()}"

    def get(self, provider: str, indicator_type: str, indicator: str) -> Optional[Any]:
        """Retrieves a cached value if present and not expired."""
        key = self._make_key(provider, indicator_type, indicator)
        now = time.time()

        with self._lock:
            if key in self._cache:
                data, expires_at = self._cache[key]
                if now < expires_at:
                    self.hits += 1
                    return data
                else:
                    # Evict expired entry
                    del self._cache[key]
            self.misses += 1
            return None

    def set(self, provider: str, indicator_type: str, indicator: str, data: Any, ttl_seconds: Optional[int] = None) -> None:
        """Stores a result in the cache with expiration timestamp."""
        key = self._make_key(provider, indicator_type, indicator)
        ttl = ttl_seconds if ttl_seconds is not None else self.default_ttl
        expires_at = time.time() + ttl

        with self._lock:
            self._cache[key] = (data, expires_at)

    def clear(self) -> None:
        """Clears all cached entries."""
        with self._lock:
            self._cache.clear()
            self.hits = 0
            self.misses = 0


# Global default cache instance
default_intel_cache = ThreatIntelCache()
