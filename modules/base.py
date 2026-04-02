import abc
import time
from typing import Any, Dict, List, Optional
import aiohttp
from pydantic import BaseModel, Field

class ModuleResult(BaseModel):
    """Standardized output for all modules."""
    module_name: str
    status: str = "success"  # success, error, skipped
    data: Dict[str, Any] = Field(default_factory=dict)
    error: Optional[str] = None
    execution_time: float = 0.0

class BaseModule(abc.ABC):
    """
    Abstract Base Class for all Aegis Recon/Hunting Modules.
    Forces async execution and standardizes module configuration.
    """
    
    # Define these in subclasses
    name: str = "base_module"
    description: str = "Base description"
    category: str = "uncategorized"
    
    # List of module names that must complete successfully before this one runs
    # e.g., ["dns", "whois"]
    dependencies: List[str] = []
    
    # Optional API key requirement. Used for graceful degradation.
    # Set to the env variable name, e.g. "VT_API_KEY". If None, no key required.
    required_api_key_env: Optional[str] = None
    
    # Rate limit configurations (requests per minute)
    # The runner will throttle execution if needed
    rate_limit_rpm: Optional[int] = None
    
    async def execute(self, target: str, session: aiohttp.ClientSession, shared_state: Dict[str, Any]) -> ModuleResult:
        """
        Wrapper to handle execution time tracking and standard exception handling.
        Do not override this unless necessary.
        """
        start_time = time.time()
        result = ModuleResult(module_name=self.name)
        
        try:
            data = await self.run(target, session, shared_state)
            if data is None:
                # E.g. skip for some reason
                result.status = "skipped"
            else:
                result.data = data
        except Exception as e:
            result.status = "error"
            result.error = str(e)
            
        result.execution_time = round(time.time() - start_time, 3)
        return result

    async def async_fetch(self, url: str, session: aiohttp.ClientSession, **kwargs) -> Optional[aiohttp.ClientResponse]:
        """
        Helper method to fetch data using the circuit breaker and exponential backoff retry logic.
        """
        from core.utils import fetch_with_retry
        return await fetch_with_retry(session, url, **kwargs)

    @abc.abstractmethod
    async def run(self, target: str, session: aiohttp.ClientSession, shared_state: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Core logic of the module. Must be implemented by subclasses.
        
        Args:
            target: The primary target URL or Domain string.
            session: The shared aiohttp.ClientSession for making async requests.
            shared_state: Dictionary containing the results of previously run modules (from dependencies).
                          Example: shared_state['dns'] gives raw data from DNS module.
            
        Returns:
            Dict containing the resulting data. If returning None, it will be marked as skipped.
        """
        pass
