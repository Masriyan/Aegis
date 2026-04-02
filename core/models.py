from pydantic import BaseModel, Field
from typing import Dict, Any, List

class ScanTask(BaseModel):
    task_id: str
    target_url: str
    selected_modules: List[str]
    mode: str
    extra_subdomains: List[str] = Field(default_factory=list)
    extra_exposures: List[str] = Field(default_factory=list)
    workflow_steps: List[Dict[str, Any]] = Field(default_factory=list)
    status: str = "pending" # pending, running, completed, error
