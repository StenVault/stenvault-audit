"""
CloudVault Audit Dashboard — Web UI for the audit pipeline.
Run with: python app.py
Access at: http://localhost:7800
"""

import os
import json
import asyncio
import subprocess
from pathlib import Path
from datetime import datetime

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse

# Paths
BASE_DIR = Path(__file__).parent.parent  # local-audit/
REPORTS_DIR = BASE_DIR / "reports"
CHECKLISTS_DIR = BASE_DIR / "checklists"

app = FastAPI(title="CloudVault Audit Dashboard")

# Serve static files
STATIC_DIR = Path(__file__).parent / "static"
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

# Track running processes
running_processes: dict[str, subprocess.Popen] = {}


@app.get("/")
async def index():
    return FileResponse(str(STATIC_DIR / "index.html"))


# --- Reports API ---

@app.get("/api/reports")
async def list_reports():
    """List all report files, newest first."""
    REPORTS_DIR.mkdir(exist_ok=True)
    reports = []
    for f in sorted(REPORTS_DIR.glob("*.json"), reverse=True):
        try:
            stat = f.stat()
            # Read just the metadata (not full findings)
            with open(f) as fh:
                data = json.load(fh)

            report_info = {
                "filename": f.name,
                "size_kb": round(stat.st_size / 1024, 1),
                "modified": datetime.fromtimestamp(stat.st_mtime).isoformat(),
                "type": _classify_report(f.name),
                "total_findings": data.get("total_findings", len(data.get("findings", []))),
            }

            # Add type-specific metadata
            if "triage_summary" in data:
                report_info["triage_summary"] = data["triage_summary"]
            if "by_severity" in data:
                report_info["by_severity"] = data["by_severity"]
            if "stages_run" in data:
                report_info["stages_run"] = data["stages_run"]
            if "features" in data:
                report_info["features"] = data["features"]
            if "model" in data:
                report_info["model"] = data.get("model", "")
            if "models_used" in data:
                report_info["models_used"] = data.get("models_used", [])

            reports.append(report_info)
        except (json.JSONDecodeError, OSError):
            reports.append({
                "filename": f.name,
                "size_kb": round(f.stat().st_size / 1024, 1),
                "type": "error",
                "total_findings": 0,
            })

    return reports


@app.get("/api/reports/{filename}")
async def get_report(filename: str):
    """Get full report contents."""
    report_path = REPORTS_DIR / filename
    if not report_path.exists() or not report_path.name.endswith(".json"):
        return JSONResponse({"error": "Report not found"}, status_code=404)

    try:
        with open(report_path) as f:
            return json.load(f)
    except json.JSONDecodeError:
        return JSONResponse({"error": "Invalid JSON"}, status_code=500)


@app.delete("/api/reports/{filename}")
async def delete_report(filename: str):
    """Delete a report file."""
    report_path = REPORTS_DIR / filename
    if not report_path.exists():
        return JSONResponse({"error": "Report not found"}, status_code=404)
    report_path.unlink()
    return {"status": "deleted", "filename": filename}


@app.get("/api/stats")
async def get_stats():
    """Dashboard summary stats."""
    REPORTS_DIR.mkdir(exist_ok=True)

    all_reports = list(REPORTS_DIR.glob("*.json"))
    triaged = sorted(REPORTS_DIR.glob("triaged_*.json"), reverse=True)
    combined = sorted(REPORTS_DIR.glob("combined_*.json"), reverse=True)
    semgrep = sorted(REPORTS_DIR.glob("semgrep_*.json"), reverse=True)

    stats = {
        "total_reports": len(all_reports),
        "latest_triaged": None,
        "latest_combined": None,
        "latest_semgrep": None,
        "is_running": bool(running_processes),
        "running_tasks": list(running_processes.keys()),
    }

    # Latest triaged report summary
    if triaged:
        try:
            with open(triaged[0]) as f:
                data = json.load(f)
            stats["latest_triaged"] = {
                "filename": triaged[0].name,
                "timestamp": data.get("timestamp", ""),
                "total_input": data.get("total_input", 0),
                "triage_summary": data.get("triage_summary", {}),
            }
        except (json.JSONDecodeError, OSError):
            pass

    if combined:
        try:
            with open(combined[0]) as f:
                data = json.load(f)
            stats["latest_combined"] = {
                "filename": combined[0].name,
                "total_findings": data.get("total_findings", 0),
                "by_severity": data.get("by_severity", {}),
                "by_stage": data.get("by_stage", {}),
                "stages_run": data.get("stages_run", []),
                "features": data.get("features", {}),
            }
        except (json.JSONDecodeError, OSError):
            pass

    if semgrep:
        try:
            with open(semgrep[0]) as f:
                data = json.load(f)
            stats["latest_semgrep"] = {
                "filename": semgrep[0].name,
                "total_findings": data.get("total_findings", 0),
            }
        except (json.JSONDecodeError, OSError):
            pass

    return stats


@app.get("/api/checklists")
async def list_checklists():
    """List available checklist files and their items."""
    checklists = []
    for f in sorted(CHECKLISTS_DIR.glob("*.yaml")):
        try:
            import yaml
            with open(f) as fh:
                data = yaml.safe_load(fh)
            if data:
                checklists.append({
                    "filename": f.name,
                    "checklist_id": data.get("checklist_id", ""),
                    "stage": data.get("stage", ""),
                    "items_count": len(data.get("items", [])),
                })
        except Exception:
            checklists.append({"filename": f.name, "error": True})
    return checklists


# --- Run Audit API ---

@app.post("/api/run")
async def start_run(config: dict):
    """Start an audit run with the given configuration."""
    task_id = datetime.now().strftime("%Y%m%d_%H%M%S")

    if running_processes:
        return JSONResponse(
            {"error": "An audit is already running. Wait for it to finish."},
            status_code=409,
        )

    # Build the command
    command = config.get("command", "full")
    stages = config.get("stages", [])
    env_vars = dict(os.environ)

    # Feature flags
    env_vars["ENABLE_DEPGRAPH"] = str(config.get("depgraph", True)).lower()
    env_vars["ENABLE_SEMGREP"] = str(config.get("semgrep", True)).lower()
    env_vars["ENABLE_ADVERSARIAL"] = str(config.get("adversarial", True)).lower()
    env_vars["ENABLE_FEW_SHOT"] = str(config.get("few_shot", True)).lower()

    # Models
    models = config.get("models", "")
    if models:
        env_vars["MODELS"] = models

    # Build shell command
    if command == "full":
        cmd = ["bash", "run.sh", "full"]
    elif command == "audit":
        cmd = ["bash", "run.sh", "audit"] + stages
    elif command == "audit-quick":
        cmd = ["bash", "run.sh", "audit-quick"] + stages
    elif command == "semgrep":
        cmd = ["bash", "run.sh", "semgrep"]
    elif command == "triage":
        cmd = ["bash", "run.sh", "triage"]
    elif command == "build":
        cmd = ["bash", "run.sh", "build"]
    else:
        return JSONResponse({"error": f"Unknown command: {command}"}, status_code=400)

    try:
        proc = subprocess.Popen(
            cmd,
            cwd=str(BASE_DIR),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            env=env_vars,
            bufsize=1,
        )
        running_processes[task_id] = proc
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=500)

    return {"task_id": task_id, "command": " ".join(cmd), "status": "started"}


@app.post("/api/stop")
async def stop_run():
    """Stop any running audit."""
    stopped = []
    for task_id, proc in list(running_processes.items()):
        proc.terminate()
        stopped.append(task_id)
        del running_processes[task_id]
    return {"stopped": stopped}


@app.get("/api/status")
async def get_status():
    """Check if any audit is running."""
    # Clean up finished processes
    for task_id in list(running_processes.keys()):
        if running_processes[task_id].poll() is not None:
            del running_processes[task_id]

    return {
        "is_running": bool(running_processes),
        "tasks": list(running_processes.keys()),
    }


# --- WebSocket for live logs ---

@app.websocket("/ws/logs/{task_id}")
async def log_stream(websocket: WebSocket, task_id: str):
    """Stream logs from a running audit process."""
    await websocket.accept()

    proc = running_processes.get(task_id)
    if not proc:
        await websocket.send_json({"type": "error", "message": "Task not found"})
        await websocket.close()
        return

    try:
        while True:
            if proc.stdout is None:
                break

            line = await asyncio.get_event_loop().run_in_executor(
                None, proc.stdout.readline
            )

            if not line and proc.poll() is not None:
                # Process finished
                exit_code = proc.returncode
                await websocket.send_json({
                    "type": "finished",
                    "exit_code": exit_code,
                    "message": f"Process finished with exit code {exit_code}",
                })
                # Clean up
                running_processes.pop(task_id, None)
                break

            if line:
                await websocket.send_json({
                    "type": "log",
                    "data": line.rstrip(),
                })

    except WebSocketDisconnect:
        pass
    except Exception as e:
        try:
            await websocket.send_json({"type": "error", "message": str(e)})
        except Exception:
            pass


# --- Helpers ---

def _classify_report(filename: str) -> str:
    if filename.startswith("triaged_"):
        return "triaged"
    if filename.startswith("combined_"):
        return "combined"
    if filename.startswith("semgrep_"):
        return "semgrep"
    return "stage"


if __name__ == "__main__":
    import uvicorn
    print("=" * 50)
    print("  CloudVault Audit Dashboard")
    print("  http://localhost:7800")
    print("=" * 50)
    uvicorn.run(app, host="0.0.0.0", port=7800)
