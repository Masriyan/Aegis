import asyncio
import aiohttp
import time
import structlog
from typing import Optional, Dict, Any, Callable, Awaitable

logger = structlog.get_logger(__name__)

class CircuitBreakerOpen(Exception):
    pass

class CircuitBreaker:
    """Simple Circuit Breaker pattern implementation."""
    def __init__(self, failure_threshold: int = 5, recovery_timeout: int = 60):
        self.failure_threshold = failure_threshold
        self.recovery_timeout = recovery_timeout
        
        self.failures = 0
        self.last_failure_time = 0
        self.state = "CLOSED" # CLOSED, OPEN, HALF-OPEN
        
    def record_failure(self):
        self.failures += 1
        self.last_failure_time = time.time()
        if self.failures >= self.failure_threshold:
            self.state = "OPEN"
            logger.warning(f"Circuit Breaker OPEN after {self.failures} failures.")

    def record_success(self):
        self.failures = 0
        self.state = "CLOSED"

    def can_execute(self) -> bool:
        if self.state == "CLOSED":
            return True
        if self.state == "OPEN":
            if time.time() - self.last_failure_time >= self.recovery_timeout:
                self.state = "HALF-OPEN"
                return True
            return False
        # HALF-OPEN
        return True


# Global circuit breakers for hosts
host_circuit_breakers = {}

def get_circuit_breaker(host: str) -> CircuitBreaker:
    if host not in host_circuit_breakers:
        host_circuit_breakers[host] = CircuitBreaker()
    return host_circuit_breakers[host]


async def fetch_with_retry(
    session: aiohttp.ClientSession,
    url: str,
    method: str = "GET",
    max_retries: int = 3,
    base_delay: float = 1.0,
    max_delay: float = 10.0,
    **kwargs
) -> Optional[aiohttp.ClientResponse]:
    """
    HTTP fetch with exponential backoff and circuit breaker.
    Uses caller's aiohttp.ClientSession. Does NOT close the response automatically
    unless it fails all retries. The caller MUST manage the response context.
    
    Returns standard aiohttp response object or None if failed/circuit-open.
    """
    from urllib.parse import urlparse
    parsed = urlparse(url)
    host = parsed.netloc
    
    cb = get_circuit_breaker(host)
    if not cb.can_execute():
        logger.error(f"Circuit breaker is OPEN for {host}. Aborting request.")
        return None

    retries = 0
    delay = base_delay
    
    while retries <= max_retries:
        try:
            if method == "GET":
                response = await session.get(url, **kwargs)
            elif method == "POST":
                response = await session.post(url, **kwargs)
            else:
                response = await session.request(method, url, **kwargs)
                
            if response.status in [429, 500, 502, 503, 504]:
                # Temporary failures, we should retry
                response.close()
                raise aiohttp.ClientResponseError(
                    request_info=response.request_info,
                    history=response.history,
                    status=response.status,
                    message=f"Server returned {response.status}"
                )
                
            cb.record_success()
            return response
            
        except (aiohttp.ClientError, asyncio.TimeoutError) as e:
            retries += 1
            if retries > max_retries:
                cb.record_failure()
                logger.error(f"Max retries reached for {url}: {str(e)}")
                return None
                
            logger.warning(f"Request failed to {url} ({str(e)}). Retrying {retries}/{max_retries} in {delay}s...")
            await asyncio.sleep(delay)
            # Exponential backoff with jitter could be added here
            delay = min(delay * 2, max_delay)
            
    return None
