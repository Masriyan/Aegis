import asyncio
import aiohttp
import json
import logging
from typing import Dict, Any, List
from core.celery_app import celery_app
import os

# Initialize modules here
from modules import load_modules
AVAILABLE_MODULES = load_modules()

logger = logging.getLogger(__name__)

async def run_scan_async(target_url: str, selected_modules: List[str], scan_options: Dict[str, Any], task_context: Any) -> Dict[str, Any]:
    """
    Run the asynchronous scanning loop.
    This resolves dependencies and handles rate limits.
    """
    results = {}
    shared_state = {}
    
    # Filter modules to run
    modules_to_run = {name: mod for name, mod in AVAILABLE_MODULES.items() if name in selected_modules}
    
    # Group by dependencies to run in phases safely
    # Phase 1: No dependencies
    # Phase 2: Dependencies are in Phase 1
    # For a completely robust engine, we can use an asyncio.TaskGroup or asyncio.gather with a dependency graph.
    # A simple approach: Keep looping and launching tasks that have their dependencies met.
    
    pending = set(modules_to_run.keys())
    completed = set()
    running_tasks = {}
    
    async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(ssl=False)) as session:
        while pending or running_tasks:
            # Check what we can start
            for name in list(pending):
                module = modules_to_run[name]
                # Can run if all dependencies are in the completed set
                if all(dep in completed for dep in module.dependencies if dep in selected_modules):
                    # Launch task
                    pending.remove(name)
                    task = asyncio.create_task(module.execute(target_url, session, shared_state))
                    running_tasks[name] = task
            
            if not running_tasks:
                if pending:
                    logger.warning(f"Deadlock detected! Outstanding modules: {pending}. Skipping them.")
                break
            
            # Wait for at least one task to finish
            done, _ = await asyncio.wait(running_tasks.values(), return_when=asyncio.FIRST_COMPLETED)
            
            for finished_task in done:
                # Find which module this belonged to
                name = [k for k, v in running_tasks.items() if v == finished_task][0]
                del running_tasks[name]
                
                try:
                    result = finished_task.result()
                    results[name] = result.model_dump()
                    if result.status == "success":
                        shared_state[name] = result.data
                        completed.add(name)
                    
                    # Update Celery task state for SSE stream
                    if hasattr(task_context, "update_state"):
                        task_context.update_state(state='PROGRESS', meta={'status': 'running', 'completed': list(completed), 'results': results})
                except Exception as e:
                    logger.error(f"Module {name} failed catastrophically: {e}")
                    results[name] = {"module_name": name, "status": "error", "error": str(e)}
                    
    return results

@celery_app.task(bind=True)
def run_scan_task(self, target_url: str, selected_modules: List[str], scan_options: Dict[str, Any]) -> str:
    """
    Celery task entry point. Starts an async event loop for aiohttp.
    """
    self.update_state(state='PROGRESS', meta={'status': 'Starting scan...'})
    
    logger.info(f"Starting scan for {target_url} with modules {selected_modules}")
    
    try:
        loop = asyncio.get_event_loop()
    except RuntimeError:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        
    results = loop.run_until_complete(
        run_scan_async(target_url, selected_modules, scan_options, self)
    )
    
    # Save to database
    import sqlite3
    from datetime import datetime
    db_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'aegis.db')
    try:
        db = sqlite3.connect(db_path)
        cur = db.cursor()
        cur.execute(
            'INSERT INTO scans (url, results, scan_date) VALUES (?, ?, ?)',
            (target_url, json.dumps(results), datetime.now().isoformat())
        )
        db.commit()
        scan_id = cur.lastrowid
        db.close()
        results['_meta'] = {'scan_id': scan_id}
    except Exception as e:
        logger.error(f"Failed to save scan to database: {e}")
    
    # Send final complete notification to SSE / Redis PUB/SUB could also be done here
    import redis
    redis_url = os.environ.get("REDIS_URL", "redis://localhost:6379/0")
    try:
        r = redis.Redis.from_url(redis_url)
        r.publish(f"scan_{self.request.id}", json.dumps({"status": "completed", "results": results}))
    except Exception as e:
        logger.error(f"Failed to publish to redis: {e}")
        
    return json.dumps(results)
