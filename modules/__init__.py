import pkgutil
import importlib
import inspect
from .base import BaseModule

import logging
logger = logging.getLogger(__name__)

def load_modules() -> dict[str, BaseModule]:
    """Dynamically load and instantiate all modules in this package."""
    loaded_modules = {}
    package_name = __name__

    try:
        import modules  # Ensure the package is available in sys.modules
        for _, module_name, _ in pkgutil.iter_modules(modules.__path__):
            if module_name == "base":
                continue
            
            full_module_name = f"{package_name}.{module_name}"
            try:
                mod = importlib.import_module(full_module_name)
                for name, obj in inspect.getmembers(mod, inspect.isclass):
                    # Check if it's a subclass of BaseModule and not BaseModule itself
                    if issubclass(obj, BaseModule) and obj is not BaseModule:
                        if getattr(obj, "__abstractmethods__", None):
                            continue # Skip abstract intermediate classes
                        instance = obj()
                        loaded_modules[instance.name] = instance
                        logger.debug(f"Loaded module: {instance.name} ({instance.category})")
            except Exception as e:
                logger.error(f"Failed to load module {full_module_name}: {e}")
                
    except Exception as e:
        logger.error(f"Error loading modules from {package_name}: {e}")
        
    return loaded_modules
