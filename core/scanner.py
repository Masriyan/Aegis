import json
import logging
import os
import sqlite3
from datetime import datetime
from typing import Dict, Any, List

logger = logging.getLogger(__name__)

DB_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'aegis.db')


def _update_task(task_id: str, **fields):
    """Helper to update task row in DB from a worker thread."""
    sets = ", ".join(f"{k}=?" for k in fields)
    vals = list(fields.values()) + [task_id]
    try:
        db = sqlite3.connect(DB_PATH)
        db.execute(f"UPDATE tasks SET {sets} WHERE id=?", vals)
        db.commit()
        db.close()
    except Exception as e:
        logger.error(f"Failed to update task {task_id}: {e}")


def run_scan_task(task_id: str, target_url: str, selected_modules: List[str], scan_options: Dict[str, Any]) -> str:
    """
    Background task entry-point.  Runs the main synchronous run_scan() engine
    from aegis.py (which contains all 70+ inline modules).  Progress is written
    to the tasks table so the SSE stream and global status bar can pick it up.
    """
    # Late import to avoid circular — aegis imports core.scanner at module level,
    # but we only need aegis.run_scan at *call* time inside a worker thread.
    import aegis

    logger.info(f"Starting scan {task_id} for {target_url} with modules {selected_modules}")

    _update_task(task_id, state="PROGRESS", completed_modules="[]")

    def on_module_done(completed_modules):
        """Called after each module completes so SSE/polling can show progress."""
        _update_task(task_id, completed_modules=json.dumps(completed_modules))

    try:
        mode = scan_options.get("mode", "defensive")
        results, url_norm = aegis.run_scan(
            target_url,
            selected_modules,
            mode,
            extra_subdomain_words=scan_options.get("extra_subdomains"),
            extra_exposure_paths=scan_options.get("extra_exposures"),
            workflow_steps=scan_options.get("workflow_steps"),
            progress_callback=on_module_done,
        )

        # Persist scan results
        db = sqlite3.connect(DB_PATH)
        cur = db.cursor()
        cur.execute(
            "INSERT INTO scans (url, results, scan_date) VALUES (?, ?, ?)",
            (url_norm, json.dumps(results), datetime.now().isoformat()),
        )
        scan_id = cur.lastrowid
        db.commit()

        results["_meta"] = results.get("_meta", {})
        results["_meta"]["scan_id"] = scan_id

        cur.execute(
            "UPDATE tasks SET state='SUCCESS', results=? WHERE id=?",
            (json.dumps(results), task_id),
        )
        db.commit()
        db.close()

        logger.info(f"Scan {task_id} completed — scan_id={scan_id}")

    except Exception as e:
        logger.error(f"Scan {task_id} failed: {e}", exc_info=True)
        _update_task(task_id, state="FAILURE", error=str(e))
        return json.dumps({"error": str(e)})

    return json.dumps(results)
