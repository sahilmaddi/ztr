import io
import os
import shutil
import subprocess
import tarfile
import tempfile
import threading
import time
import zipfile
from datetime import datetime, timezone
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path, PurePosixPath
from typing import Any, TypedDict
from urllib.parse import quote, urlsplit

import requests
from fastapi import FastAPI, File, Form, HTTPException, UploadFile
from langgraph.graph import END, StateGraph
from selenium import webdriver
from selenium.webdriver.chrome.options import Options

app = FastAPI(title="Zero-Touch Regression and Security Testing")

FILE_SERVER_PORT = 8101
FILE_SERVER: ThreadingHTTPServer | None = None
FILE_ROOT = ""
RUN_LOCK = threading.Lock()  # ZAP and the file server are shared, so runs are serialized.

MAX_UPLOAD_BYTES = 200 * 1024 * 1024
MAX_EXTRACTED_BYTES = 500 * 1024 * 1024
MAX_ARCHIVE_FILES = 20000

ZAP_URL = os.getenv("ZAP_URL", "http://zap:8080").rstrip("/")
ZAP_API_KEY = os.getenv("ZAP_API_KEY", "ztr-local-scan-key")

RISK_RANK = {"Informational": 0, "Low": 1, "Medium": 2, "High": 3}
# Lowest ZAP risk that fails a run. "Medium" (default) or "High".
FAIL_ON_RISK = os.getenv("ZTR_FAIL_ON_RISK", "Medium")
if FAIL_ON_RISK not in {"Medium", "High"}:
    FAIL_ON_RISK = "Medium"

ALLOWED_LAB_HOSTS = {"juice-shop", "host.docker.internal"}


class LabHandler(SimpleHTTPRequestHandler):
    """Static file handler that sends the security headers a well-configured host would send.

    Headers are added in end_headers so they also appear on 404/error pages,
    which ZAP's passive rules inspect as well.
    """

    def version_string(self) -> str:
        return "ztr"  # do not leak the Python/server version

    def end_headers(self) -> None:
        self.send_header(
            "Content-Security-Policy",
            "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
            "object-src 'none'; base-uri 'self'; frame-ancestors 'none'; form-action 'self'",
        )
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
        self.send_header("Cross-Origin-Opener-Policy", "same-origin")
        self.send_header("Cross-Origin-Resource-Policy", "same-origin")
        self.send_header("Cache-Control", "no-store")
        super().end_headers()


def is_generated_path(name: str) -> bool:
    return any(part in {"node_modules", "dist", ".angular", ".git", "__pycache__"} for part in Path(name).parts)


class RegressionState(TypedDict, total=False):
    archive_path: str
    repo_path: str
    commit_id: str
    patch_path: str
    workspace: str
    target_url: str
    active_scan: bool
    files: list[str]
    entry_point: str
    url: str
    title: str
    functional_status: str
    functional_error: str
    security_status: str
    security_error: str
    security_alerts: list[dict[str, Any]]
    high_count: int
    medium_count: int
    low_count: int
    info_count: int
    status: str
    workflow: list[dict[str, Any]]


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def ensure_stage(state: RegressionState, name: str) -> dict[str, Any]:
    workflow = state.setdefault("workflow", [])
    stage = next((entry for entry in workflow if entry.get("name") == name), None)
    if stage is None:
        stage = {"name": name, "status": "running", "started_at": utc_now_iso(), "logs": []}
        workflow.append(stage)
    else:
        stage["status"] = "running"
        stage.setdefault("started_at", utc_now_iso())
    return stage


def stage_log(state: RegressionState, stage_name: str, message: str, level: str = "INFO") -> None:
    stage = ensure_stage(state, stage_name)
    stage.setdefault("logs", []).append({
        "timestamp": utc_now_iso(),
        "level": level,
        "message": message,
    })


def stage_complete(state: RegressionState, stage_name: str, status: str, message: str | None = None, level: str = "INFO") -> None:
    stage = ensure_stage(state, stage_name)
    stage["status"] = status
    stage["finished_at"] = utc_now_iso()
    if message is not None:
        stage_log(state, stage_name, message, level)


def list_project_files(workspace: str) -> list[str]:
    files: list[str] = []
    for root, dirs, filenames in os.walk(workspace):
        dirs[:] = [name for name in dirs if not is_generated_path(os.path.relpath(os.path.join(root, name), workspace))]
        for filename in filenames:
            relative = os.path.relpath(os.path.join(root, filename), workspace).replace("\\", "/")
            if is_generated_path(relative):
                continue
            files.append(relative)
    return sorted(files)


def inspect_repository(state: RegressionState) -> RegressionState:
    stage_name = "inspect_archive"
    stage_log(state, stage_name, "Preparing repository workspace for regression analysis.")
    repo_path = state.get("repo_path") or "."
    commit_id = (state.get("commit_id") or "").strip()
    workspace = tempfile.mkdtemp(prefix="regression-")
    try:
        source_path = os.path.abspath(os.path.expanduser(repo_path))
        stage_log(state, stage_name, f"Using repository path: {source_path}")
        if not os.path.exists(source_path):
            raise ValueError(f"Repository path does not exist: {repo_path}")

        if commit_id:
            stage_log(state, stage_name, f"Resolving commit/ref {commit_id} in repository.")
            result = subprocess.run(
                ["git", "-C", source_path, "rev-parse", "--verify", commit_id],
                capture_output=True,
                text=True,
                check=False,
            )
            if result.returncode != 0:
                raise ValueError(f"Commit or ref not found in repository: {commit_id}")
            archive = subprocess.run(
                ["git", "-C", source_path, "archive", "--format=tar", commit_id],
                capture_output=True,
                check=False,
            )
            if archive.returncode != 0:
                raise ValueError(f"Unable to archive revision {commit_id}")
            with tarfile.open(fileobj=io.BytesIO(archive.stdout), mode="r:") as archive_file:
                archive_file.extractall(path=workspace)
        else:
            stage_log(state, stage_name, "Copying working tree into a clean regression workspace.")
            shutil.copytree(source_path, workspace, dirs_exist_ok=True)

        patch_path = state.get("patch_path")
        if patch_path:
            stage_log(state, stage_name, f"Applying patch file: {patch_path}")
            subprocess.run(["git", "apply", "--unsafe-paths", "--directory", workspace, patch_path], check=True)

        files = list_project_files(workspace)
        candidates = [name for name in files if PurePosixPath(name).name.lower() == "index.html"]
        if not candidates:
            raise ValueError("Zero-touch demo currently requires an index.html entry point.")
        entry = min(candidates, key=lambda name: (len(PurePosixPath(name).parts), name))
        stage_log(state, stage_name, f"Detected entry point: {entry}")
        stage_complete(state, stage_name, "passed", f"Repository inspection completed for {entry}.")
        return {"workspace": workspace, "files": files, "entry_point": entry}
    except Exception as error:
        stage_complete(state, stage_name, "failed", str(error), "ERROR")
        shutil.rmtree(workspace, ignore_errors=True)
        raise


def inspect_archive(state: RegressionState) -> RegressionState:
    stage_name = "inspect_archive"
    stage_log(state, stage_name, "Starting archive or repository inspection for the regression package.")
    workspace = tempfile.mkdtemp(prefix="regression-")
    try:
        archive_path = state.get("archive_path")
        if archive_path:
            files: list[str] = []
            total_size = 0
            stage_log(state, stage_name, f"Opening ZIP archive: {archive_path}")
            with zipfile.ZipFile(archive_path) as archive:
                entries = archive.infolist()
                if len(entries) > MAX_ARCHIVE_FILES:
                    raise ValueError(f"ZIP contains too many entries (maximum {MAX_ARCHIVE_FILES}).")
                for member in entries:
                    normalized_name = member.filename.replace("\\", "/")
                    path = Path(normalized_name)
                    if path.is_absolute() or ".." in path.parts:
                        raise ValueError("Archive contains an unsafe path.")
                    if member.file_size < 0:
                        raise ValueError("Archive contains an invalid file size.")
                    if not member.is_dir() and not is_generated_path(normalized_name):
                        total_size += member.file_size
                        files.append(normalized_name)
                if total_size > MAX_EXTRACTED_BYTES:
                    raise ValueError("Uncompressed project exceeds the 500 MB safety limit.")

                candidates = [name for name in files if PurePosixPath(name).name.lower() == "index.html"]
                if not candidates:
                    raise ValueError("Zero-touch demo currently requires an index.html entry point.")
                entry = min(candidates, key=lambda name: (len(PurePosixPath(name).parts), name))

                written = 0
                for member in entries:
                    normalized_name = member.filename.replace("\\", "/")
                    if is_generated_path(normalized_name):
                        continue
                    target = Path(workspace) / normalized_name
                    if member.is_dir():
                        target.mkdir(parents=True, exist_ok=True)
                        continue
                    target.parent.mkdir(parents=True, exist_ok=True)
                    with archive.open(member) as source, target.open("wb") as destination:
                        while chunk := source.read(1024 * 1024):
                            written += len(chunk)
                            if written > MAX_EXTRACTED_BYTES:
                                raise ValueError("Uncompressed project exceeds the 500 MB safety limit.")
                            destination.write(chunk)
            stage_log(state, stage_name, f"Extracted {len(files)} files and detected entry point {entry}.")
            stage_complete(state, stage_name, "passed", "Archive inspection completed successfully.")
            return {"workspace": workspace, "files": sorted(files), "entry_point": entry}

        repo_path = state.get("repo_path")
        if repo_path or state.get("commit_id"):
            return inspect_repository(state)
        raise ValueError("No ZIP package or repository path was provided.")
    except Exception as error:
        stage_complete(state, stage_name, "failed", str(error), "ERROR")
        shutil.rmtree(workspace, ignore_errors=True)
        raise


def serve_application(state: RegressionState) -> RegressionState:
    stage_name = "serve_application"
    stage_log(state, stage_name, "Starting the static file server for the extracted web project.")
    global FILE_SERVER, FILE_ROOT
    FILE_ROOT = state["workspace"]
    if FILE_SERVER is None:
        handler = lambda *args, **kwargs: LabHandler(*args, directory=FILE_ROOT, **kwargs)
        FILE_SERVER = ThreadingHTTPServer(("0.0.0.0", FILE_SERVER_PORT), handler)
        threading.Thread(target=FILE_SERVER.serve_forever, daemon=True).start()
    url = f"http://regression:{FILE_SERVER_PORT}/{quote(state['entry_point'])}"
    stage_log(state, stage_name, f"Application is being served at {url}")
    stage_complete(state, stage_name, "passed", "Static app server ready.")
    return {"url": url}


def run_browser_regression(state: RegressionState) -> RegressionState:
    stage_name = "run_browser_regression"
    stage_log(state, stage_name, "Launching Selenium headless browser to smoke-test the application.")
    options = Options()
    options.add_argument("--headless=new")
    options.add_argument("--no-sandbox")
    options.add_argument("--disable-dev-shm-usage")
    driver = None
    selenium_url = os.getenv("SELENIUM_URL", "http://browser:4444")
    page_url = state.get("target_url") or state["url"]
    try:
        last_error = None
        for _ in range(30):
            try:
                stage_log(state, stage_name, f"Connecting to Selenium at {selenium_url}")
                driver = webdriver.Remote(command_executor=selenium_url, options=options)
                break
            except Exception as error:
                last_error = error
                time.sleep(2)
        if driver is None:
            raise RuntimeError(f"Selenium browser did not become ready: {last_error}")
        driver.set_page_load_timeout(45)
        stage_log(state, stage_name, f"Loading page: {page_url}")
        driver.get(page_url)
        if driver.current_url.startswith("chrome-error:"):
            raise ValueError("The browser could not load the page.")
        if driver.title == "Error response" or not driver.find_elements("tag name", "body"):
            raise ValueError("The page did not render a usable document.")
        title = driver.title
        stage_log(state, stage_name, f"Smoke test passed; document title: {title}")
        stage_complete(state, stage_name, "passed", "Browser smoke test passed.")
        return {"title": title, "functional_status": "passed", "functional_error": ""}
    except Exception as error:
        message = str(error)[:500]
        stage_complete(state, stage_name, "failed", message, "ERROR")
        return {"functional_status": "failed", "functional_error": message}
    finally:
        if driver:
            driver.quit()


def zap_request(path: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
    query = {"apikey": ZAP_API_KEY, **(params or {})}
    response = requests.get(f"{ZAP_URL}{path}", params=query, timeout=15)
    response.raise_for_status()
    return response.json()


def run_security_scan(state: RegressionState) -> RegressionState:
    """Run ZAP spider + passive rules; active scanning is opt-in and limited to the Juice Shop lab."""
    stage_name = "run_security_scan"
    stage_log(state, stage_name, "Starting OWASP ZAP security scan pipeline.")
    target = state.get("target_url") or state["url"]
    stage_log(state, stage_name, f"Target: {target}")
    parsed = urlsplit(target)
    if parsed.scheme != "http" or parsed.hostname not in ({"regression"} | ALLOWED_LAB_HOSTS):
        stage_complete(state, stage_name, "failed", "Target is outside the allowed local lab hosts.", "ERROR")
        return {"security_status": "not_run", "security_error": "Target is outside the allowed local lab hosts.", "security_alerts": []}
    if parsed.hostname in ALLOWED_LAB_HOSTS and parsed.port != 3000:
        stage_complete(state, stage_name, "failed", "The Juice Shop lab target must use port 3000.", "ERROR")
        return {"security_status": "not_run", "security_error": "The Juice Shop lab target must use port 3000.", "security_alerts": []}
    if parsed.hostname == "regression" and parsed.port != FILE_SERVER_PORT:
        stage_complete(state, stage_name, "failed", "The uploaded-package target must use port 8101.", "ERROR")
        return {"security_status": "not_run", "security_error": "The uploaded-package target must use port 8101.", "security_alerts": []}
    if state.get("active_scan") and parsed.hostname not in ALLOWED_LAB_HOSTS:
        stage_complete(state, stage_name, "failed", "Active scanning is allowed only for the configured local Juice Shop lab target.", "ERROR")
        return {"security_status": "not_run", "security_error": "Active scanning is allowed only for the configured local Juice Shop lab target.", "security_alerts": []}

    origin = f"{parsed.scheme}://{parsed.netloc}"
    try:
        ready = False
        for _ in range(30):
            try:
                zap_request("/JSON/core/view/version/")
                ready = True
                break
            except requests.RequestException:
                time.sleep(2)
        if not ready:
            raise RuntimeError("OWASP ZAP did not become ready. Check the zap container logs.")

        stage_log(state, stage_name, "OWASP ZAP is ready; clearing prior alerts and beginning passively targeted crawl.")
        # ZAP keeps alerts between runs; clear them so this report only shows this run.
        zap_request("/JSON/core/action/deleteAllAlerts/")

        spider = zap_request("/JSON/spider/action/scan/", {"url": target, "maxChildren": 10, "recurse": "true"})
        scan_id = spider.get("scan")
        if scan_id is None:
            raise RuntimeError(f"ZAP did not start its spider: {spider}")
        stage_log(state, stage_name, f"Spider scan started with ID {scan_id}")
        for _ in range(90):
            progress = zap_request("/JSON/spider/view/status/", {"scanId": scan_id})
            if int(progress.get("status", 0)) >= 100:
                break
            time.sleep(2)
        else:
            raise RuntimeError("ZAP spider timed out after 3 minutes.")

        for _ in range(60):
            pending = zap_request("/JSON/pscan/view/recordsToScan/")
            if int(pending.get("recordsToScan", 0)) <= 0:
                break
            time.sleep(2)

        if state.get("active_scan"):
            active = zap_request("/JSON/ascan/action/scan/", {"url": target, "recurse": "true", "inScopeOnly": "false"})
            active_id = active.get("scan")
            if active_id is None:
                raise RuntimeError(f"ZAP did not start the active scan: {active}")
            stage_log(state, stage_name, f"Active scan started with ID {active_id}")
            for _ in range(240):
                progress = zap_request("/JSON/ascan/view/status/", {"scanId": active_id})
                if int(progress.get("status", 0)) >= 100:
                    break
                time.sleep(2)
            else:
                raise RuntimeError("ZAP active scan timed out after 8 minutes.")

        # Query by origin so alerts on sibling URLs (robots.txt, assets) are included.
        raw = zap_request("/JSON/core/view/alerts/", {"baseurl": origin, "start": 0, "count": 1000})
        cleaned = [{
            "name": item.get("name", "Unspecified alert"),
            "risk": item.get("risk", "Informational"),
            "confidence": item.get("confidence", ""),
            "url": item.get("url", ""),
            "description": (item.get("description", "") or "")[:350],
            "solution": (item.get("solution", "") or "")[:250],
        } for item in raw.get("alerts", [])]
        cleaned.sort(key=lambda item: -RISK_RANK.get(item["risk"], 0))

        counts = {"High": 0, "Medium": 0, "Low": 0, "Informational": 0}
        for item in cleaned:
            if item["risk"] in counts:
                counts[item["risk"]] += 1
        threshold = RISK_RANK[FAIL_ON_RISK]
        failing = any(RISK_RANK.get(item["risk"], 0) >= threshold for item in cleaned)
        message = "No medium/high alerts found." if not failing else f"Detected {sum(1 for item in cleaned if RISK_RANK.get(item['risk'], 0) >= threshold)} failing alert(s)."
        stage_complete(state, stage_name, "passed" if not failing else "failed", message)
        return {
            "security_status": "findings" if failing else "passed",
            "security_alerts": cleaned,
            "high_count": counts["High"],
            "medium_count": counts["Medium"],
            "low_count": counts["Low"],
            "info_count": counts["Informational"],
        }
    except Exception as error:
        message = str(error)[:500]
        stage_complete(state, stage_name, "failed", message, "ERROR")
        return {"security_status": "not_run", "security_error": message, "security_alerts": []}


def build_report(state: RegressionState) -> RegressionState:
    stage_name = "build_report"
    stage_log(state, stage_name, "Synthesizing final regression status from the stage results.")
    functional = state.get("functional_status", "failed")
    security = state.get("security_status", "not_run")
    if functional != "passed" or security == "findings":
        overall = "failed"
    elif security != "passed":
        overall = "incomplete"
    else:
        overall = "passed"
    stage_complete(state, stage_name, overall, f"Overall regression status: {overall}.")
    return {"status": overall}


def create_graph():
    graph = StateGraph(RegressionState)
    graph.add_node("inspect_archive", inspect_archive)
    graph.add_node("serve_application", serve_application)
    graph.add_node("run_browser_regression", run_browser_regression)
    graph.add_node("run_security_scan", run_security_scan)
    graph.add_node("build_report", build_report)
    graph.set_entry_point("inspect_archive")
    graph.add_edge("inspect_archive", "serve_application")
    graph.add_edge("serve_application", "run_browser_regression")
    graph.add_edge("run_browser_regression", "run_security_scan")
    graph.add_edge("run_security_scan", "build_report")
    graph.add_edge("build_report", END)
    return graph.compile()


REGRESSION_GRAPH = create_graph()


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


# Plain `def` (not async): FastAPI runs it in a worker thread, so the long blocking
# scan does not freeze the event loop or /health.
@app.post("/regress")
def regress(
    file: UploadFile | None = File(None),
    source_type: str = Form("zip"),
    repo_path: str | None = Form(None),
    commit_id: str | None = Form(None),
    target_url: str | None = Form(None),
    active_scan: bool = Form(False),
) -> dict[str, Any]:
    source_type = (source_type or "zip").strip().lower()
    if source_type not in {"zip", "repo"}:
        raise HTTPException(status_code=400, detail="Choose a project source of 'zip' or 'repo'.")

    if source_type == "zip":
        if file is None or not file.filename or not file.filename.lower().endswith(".zip"):
            raise HTTPException(status_code=400, detail="Upload a ZIP project package.")
    else:
        repo_path = (repo_path or ".").strip() or "."

    temporary = None
    result: dict[str, Any] = {}
    try:
        if source_type == "zip":
            temporary = tempfile.NamedTemporaryFile(delete=False, suffix=".zip")
            uploaded = 0
            while chunk := file.file.read(1024 * 1024):
                uploaded += len(chunk)
                if uploaded > MAX_UPLOAD_BYTES:
                    raise HTTPException(status_code=413, detail="ZIP upload exceeds the 200 MB limit.")
                temporary.write(chunk)
            temporary.close()

        target_url = (target_url or "").strip()
        if target_url:
            try:
                parsed_target = urlsplit(target_url)
                allowed = (
                    parsed_target.scheme == "http"
                    and parsed_target.hostname in ALLOWED_LAB_HOSTS
                    and parsed_target.port == 3000
                    and not parsed_target.username
                    and not parsed_target.password
                )
            except ValueError:
                allowed = False
            if not allowed:
                raise HTTPException(status_code=400, detail="Use the local Juice Shop lab URL http://juice-shop:3000 or http://host.docker.internal:3000.")
        elif active_scan:
            raise HTTPException(status_code=400, detail="Enter the local Juice Shop URL before enabling active scanning.")

        graph_input: dict[str, Any] = {"target_url": target_url, "active_scan": active_scan}
        if source_type == "zip":
            graph_input["archive_path"] = temporary.name
        else:
            graph_input["repo_path"] = repo_path
            graph_input["commit_id"] = (commit_id or "").strip()

        with RUN_LOCK:
            result = REGRESSION_GRAPH.invoke(graph_input)

        scan_type = "OWASP ZAP spider + passive rules"
        if result.get("active_scan"):
            scan_type += " + active scan (Juice Shop lab)"
        return {
            "status": result.get("status", "incomplete"),
            "fileName": file.filename if file else (repo_path or "repo"),
            "fileCount": len(result.get("files", [])),
            "entryPoint": result.get("entry_point"),
            "url": result.get("url"),
            "title": result.get("title", ""),
            "engine": "LangGraph + Selenium + OWASP ZAP",
            "functionalStatus": result.get("functional_status", "failed"),
            "functionalError": result.get("functional_error", ""),
            "securityStatus": result.get("security_status", "not_run"),
            "securityError": result.get("security_error", ""),
            "securityCounts": {
                "high": result.get("high_count", 0),
                "medium": result.get("medium_count", 0),
                "low": result.get("low_count", 0),
                "informational": result.get("info_count", 0),
            },
            "securityAlerts": result.get("security_alerts", []),
            "failOnRisk": FAIL_ON_RISK,
            "scanType": scan_type,
            "scanTarget": result.get("target_url") or result.get("url"),
            "activeScan": result.get("active_scan", False),
            "sourceType": source_type,
            "repoPath": repo_path,
            "commitId": commit_id,
            "workflow": result.get("workflow", []),
        }
    except HTTPException:
        raise
    except (ValueError, zipfile.BadZipFile) as error:
        raise HTTPException(status_code=422, detail=str(error)) from error
    except Exception as error:
        raise HTTPException(status_code=502, detail=f"Regression failed: {error}") from error
    finally:
        if temporary is not None:
            temporary.close()
            Path(temporary.name).unlink(missing_ok=True)
        workspace = result.get("workspace")
        if workspace:
            shutil.rmtree(workspace, ignore_errors=True)