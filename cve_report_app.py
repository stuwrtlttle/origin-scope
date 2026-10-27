#!/usr/bin/env python3
"""Local, dependency-free browser UI for cve-report.

The server binds only to localhost and stores each run in a private local data
directory.  It is intentionally a browser application rather than a platform
native toolkit so the same command works on macOS and Linux distributions.
"""

import argparse
import contextlib
import hashlib
import json
import os
import re
import sqlite3
import subprocess
import sys
import threading
import traceback
import uuid
import webbrowser
from dataclasses import dataclass, field
from datetime import datetime, timezone
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

import scanner_csv
import vex_cache
import assessment_policy


APP_ROOT = Path(__file__).resolve().parent
CLI_PATH = APP_ROOT / "cve_report.py"
MAX_UPLOAD_BYTES = 100 * 1024 * 1024
SAFE_FILENAME = re.compile(r"[^A-Za-z0-9._-]+")
SAFE_JOB_ID = re.compile(r"^[0-9a-f]{32}$")
ANALYSIS_MODES = {"holistic", "scanner"}
ARCHITECTURES = {"amd64", "arm64", "ppc64le", "s390x"}
UI_WORKERS = 8
VEX_CACHE_PATH = APP_ROOT / ".cache" / "vex.sqlite3"
ASSESSMENT_BUNDLE_SCHEMA = "originscope-assessment-bundle/v1"
ASSESSMENT_BUNDLE_VERSION = "1.0"


def utc_now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def safe_filename(value):
    """Return a filename that cannot escape a job's private directory."""
    value = Path(value or "sbom.json").name
    value = SAFE_FILENAME.sub("-", value).strip(".-")
    return value or "sbom.json"


def sha256_file(path):
    """Return the content digest for a run artifact without loading it at once."""
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def artifact_evidence(path):
    """Return portable integrity metadata; never expose a local absolute path."""
    path = Path(path)
    if not path.is_file():
        return None
    return {
        "file": path.name,
        "bytes": path.stat().st_size,
        "sha256": sha256_file(path),
    }


def vex_cache_evidence(cache_path):
    """Capture cache identity cheaply; hashing a multi-GB cache per run is impractical."""
    cache_path = Path(cache_path)
    if not cache_path.is_file():
        return {"present": False}
    evidence = {
        "present": True,
        "bytes": cache_path.stat().st_size,
        "modifiedAt": datetime.fromtimestamp(cache_path.stat().st_mtime, timezone.utc).isoformat(timespec="seconds"),
    }
    try:
        connection = sqlite3.connect(f"file:{cache_path}?mode=ro", uri=True, timeout=1)
        metadata = dict(connection.execute("SELECT key, value FROM cache_metadata"))
        connection.close()
        evidence["metadata"] = {
            key: metadata.get(key)
            for key in ("schema_version", "scope", "feed_url", "build_state", "last_sync_at")
            if metadata.get(key) is not None
        }
    except sqlite3.Error:
        evidence["metadata"] = {"state": "unavailable during capture"}
    return evidence


def default_data_dir():
    return Path(os.environ.get("CVE_REPORT_UI_DATA_DIR", Path.home() / ".cache" / "cve-report-ui"))


@dataclass
class Job:
    job_id: str
    directory: Path
    filename: str
    options: dict
    created_at: str = field(default_factory=utc_now)
    status: str = "awaiting upload"
    started_at: str | None = None
    finished_at: str | None = None
    return_code: int | None = None
    error: str | None = None
    image_candidates: list[dict] = field(default_factory=list)

    @property
    def input_path(self):
        return self.directory / self.filename

    @property
    def report_path(self):
        return self.directory / "report.md"

    @property
    def vex_path(self):
        return self.directory / "vex.json"

    @property
    def results_path(self):
        return self.directory / "results.json"

    @property
    def catalog_sbom_path(self):
        return self.directory / "catalog-sbom.cdx.json"

    @property
    def scanner_evidence_path(self):
        return self.directory / "scanner-evidence.json"

    @property
    def scanner_csv_path(self):
        return self.directory / "scanner-review.csv"

    @property
    def scanner_cves_path(self):
        return self.directory / "scanner-cves.txt"

    @property
    def scanner_components_path(self):
        return self.directory / "scanner-components.txt"

    @property
    def log_path(self):
        return self.directory / "progress.log"

    @property
    def assessment_bundle_path(self):
        return self.directory / "assessment-bundle.json"

    def snapshot(self):
        return {
            "id": self.job_id,
            "filename": self.filename,
            "analysisMode": self.options["analysisMode"],
            "status": self.status,
            "createdAt": self.created_at,
            "startedAt": self.started_at,
            "finishedAt": self.finished_at,
            "returnCode": self.return_code,
            "error": self.error,
            "imageCandidates": self.image_candidates,
            "imageConfirmed": bool(self.options.get("imageConfirmed")),
            "reportReady": self.report_path.is_file() and self.report_path.stat().st_size > 0,
            "resultsReady": self.results_path.is_file() and self.results_path.stat().st_size > 0,
            "vexReady": self.vex_path.is_file() and self.vex_path.stat().st_size > 0,
            "catalogSbomReady": self.catalog_sbom_path.is_file() and self.catalog_sbom_path.stat().st_size > 0,
            "scannerEvidenceReady": self.scanner_evidence_path.is_file() and self.scanner_evidence_path.stat().st_size > 0,
            "scannerCsvReady": self.scanner_csv_path.is_file() and self.scanner_csv_path.stat().st_size > 0,
            "assessmentBundleReady": self.assessment_bundle_path.is_file() and self.assessment_bundle_path.stat().st_size > 0,
            "log": tail_text(self.log_path),
        }


def tail_text(path, limit=14_000):
    try:
        with path.open("rb") as handle:
            handle.seek(0, os.SEEK_END)
            size = handle.tell()
            handle.seek(max(0, size - limit))
            text = handle.read().decode("utf-8", errors="replace")
            return text if size <= limit else "…\n" + text
    except FileNotFoundError:
        return ""


def validate_options(payload):
    """Validate UI options before they are translated to a subprocess argv."""
    if not isinstance(payload, dict):
        raise ValueError("Configuration must be an object.")
    filename = safe_filename(payload.get("filename"))
    analysis_mode = payload.get("analysisMode", "holistic")
    image_reference = (payload.get("imageReference") or "").strip()
    architecture = payload.get("architecture", "amd64")
    assessment_profile = payload.get("assessmentProfile", assessment_policy.DEFAULT_PROFILE_ID)
    if analysis_mode not in ANALYSIS_MODES:
        raise ValueError("Choose holistic reporting or scanner findings review.")
    if analysis_mode == "scanner":
        if not filename.lower().endswith((".csv", ".json", ".out", ".txt")):
            raise ValueError("Scanner findings review requires a CSV, JSON, or supported text vulnerability report.")
    elif filename.lower().endswith(".csv"):
        raise ValueError("Use Scanner findings review for a vulnerability report CSV.")
    if architecture not in ARCHITECTURES:
        raise ValueError("Choose a supported image architecture.")
    assessment_policy.profile(assessment_profile)
    return {
        "filename": filename,
        "analysisMode": analysis_mode,
        "source": "osidb",
        "imageReference": image_reference,
        "imageConfirmed": False,
        "architecture": architecture,
        "assessmentProfile": assessment_profile,
        "workers": UI_WORKERS,
    }


class VexCacheStore:
    """Own the shared VEX cache independently from individual analyses."""

    def __init__(self, cache_path, log_path):
        self.cache_path = Path(cache_path)
        self.log_path = Path(log_path)
        self.lock = threading.Lock()
        self.operation = None
        self.started_at = None
        self.finished_at = None
        self.error = None

    def _database_snapshot(self):
        if not self.cache_path.is_file():
            return {"buildState": "missing", "schemaVersion": None, "documents": 0, "unavailable": 0, "lastSyncAt": None}
        try:
            connection = sqlite3.connect(f"file:{self.cache_path}?mode=ro", uri=True, timeout=1)
            metadata = dict(connection.execute("SELECT key, value FROM cache_metadata"))
            documents = connection.execute("SELECT COUNT(*) FROM documents").fetchone()[0]
            try:
                unavailable = connection.execute("SELECT COUNT(*) FROM unavailable_documents").fetchone()[0]
            except sqlite3.OperationalError:
                unavailable = 0
            connection.close()
            return {
                "buildState": metadata.get("build_state", "unknown"),
                "schemaVersion": metadata.get("schema_version"),
                "documents": documents,
                "unavailable": unavailable,
                "lastSyncAt": metadata.get("last_sync_at"),
            }
        except sqlite3.Error:
            # A writer may be committing a bulk batch.  Keep the action state
            # useful even if this one read cannot obtain a snapshot.
            return {"buildState": "reading", "schemaVersion": None, "documents": None, "unavailable": None, "lastSyncAt": None}

    @staticmethod
    def _progress_from_activity(activity):
        """Read the newest import counter from the cache worker's log."""
        counters = re.findall(r"VEX cache: indexed (\d+)/(\d+) documents", activity)
        if not counters:
            return None
        processed, total = counters[-1]
        return {"processed": int(processed), "total": int(total)}

    def snapshot(self):
        database = self._database_snapshot()
        activity = tail_text(self.log_path, limit=7_000)
        with self.lock:
            operation = self.operation
            error = self.error
            started_at = self.started_at
            finished_at = self.finished_at
        if operation:
            state = "rebuilding" if operation == "rebuild" else "updating"
            message = "Rebuilding the local cache…" if operation == "rebuild" else "Updating the local cache…"
        elif error:
            state = "failed"
            message = "Cache maintenance failed. Review cache activity and try again."
        elif (database["buildState"] != "missing"
              and database["schemaVersion"] != vex_cache.CACHE_SCHEMA_VERSION):
            state = "outdated"
            message = "The local cache needs a quick in-place update before analysis."
        elif database["buildState"] == "ready":
            state = "ready"
            message = "Local cache is ready for analysis."
        elif database["buildState"] == "building":
            state = "incomplete"
            message = "A previous cache build did not finish. Resume it before analysis."
        else:
            state = "missing"
            message = "Build the local cache before running an analysis."
        return {
            "state": state,
            "message": message,
            "operation": operation,
            "startedAt": started_at,
            "finishedAt": finished_at,
            "error": error,
            "documents": database["documents"],
            "unavailable": database["unavailable"],
            "lastSyncAt": database["lastSyncAt"],
            "progress": self._progress_from_activity(activity),
            "activity": activity,
        }

    def is_ready(self):
        return self.snapshot()["state"] == "ready"

    def is_busy(self):
        with self.lock:
            return self.operation is not None

    def start(self, operation, analysis_running):
        if operation not in {"refresh", "rebuild"}:
            raise ValueError("Unknown cache operation.")
        with self.lock:
            if self.operation:
                raise RuntimeError("VEX cache maintenance is already running.")
            if analysis_running:
                raise RuntimeError("Wait for the active analysis to finish before changing the VEX cache.")
            self.operation = operation
            self.started_at = utc_now()
            self.finished_at = None
            self.error = None
        threading.Thread(target=self._run, args=(operation,), daemon=True, name=f"vex-cache-{operation}").start()

    def _run(self, operation):
        try:
            self.log_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            with self.log_path.open("w", encoding="utf-8") as log, contextlib.redirect_stderr(log):
                print(f"{operation.title()}ing public Red Hat CSAF VEX cache…", file=log, flush=True)
                if operation == "rebuild":
                    vex_cache.rebuild(self.cache_path, None, workers=UI_WORKERS)
                else:
                    vex_cache.sync(self.cache_path, None, workers=UI_WORKERS)
                print("VEX cache maintenance completed.", file=log, flush=True)
            with self.lock:
                self.operation = None
                self.finished_at = utc_now()
        except Exception as exc:
            with self.log_path.open("a", encoding="utf-8") as log:
                traceback.print_exc(file=log)
            with self.lock:
                self.operation = None
                self.error = str(exc)
                self.finished_at = utc_now()


class JobStore:
    def __init__(self, data_dir, source="osidb", product_name="CVE report workbench"):
        if source not in {"osidb", "vex", "vex-direct"}:
            raise ValueError("Choose OSIDB, public VEX, or direct public VEX as the analysis source.")
        self.data_dir = Path(data_dir)
        self.data_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.source = source
        self.product_name = product_name
        self.jobs = {}
        self.lock = threading.Lock()

    def create(self, options):
        with self.lock:
            job_id = uuid.uuid4().hex
            directory = self.data_dir / "jobs" / job_id
            directory.mkdir(parents=True, mode=0o700)
            job = Job(job_id, directory, options["filename"], options)
            self.jobs[job_id] = job
            return job

    def get(self, job_id):
        with self.lock:
            return self.jobs.get(job_id)

    def is_running(self):
        with self.lock:
            return any(item.status == "running" for item in self.jobs.values())

    def start(self, job):
        with self.lock:
            if job.status != "ready":
                raise ValueError("Upload an analysis input before starting.")
            if job.options["analysisMode"] == "scanner" and not job.options.get("imageConfirmed"):
                raise ValueError("Confirm the Red Hat Catalog image match before starting scanner findings review.")
            if any(item.status == "running" for item in self.jobs.values()):
                raise RuntimeError("One analysis is already running. Wait for it to finish first.")
            job.status = "running"
            job.started_at = utc_now()
        threading.Thread(target=self._run, args=(job,), daemon=True, name=f"cve-report-{job.job_id}").start()

    def match_image(self, job):
        """Infer Catalog images only after the user has uploaded the report."""
        with self.lock:
            if job.status != "ready":
                raise ValueError("Upload a vulnerability report before matching its image.")
            if job.options["analysisMode"] != "scanner":
                raise ValueError("Image matching is available for scanner findings review only.")
        candidates = scanner_csv.suggest_image_candidates(job.input_path, job.options["architecture"])
        evidence = [candidate.evidence() for candidate in candidates]
        with self.lock:
            job.image_candidates = evidence
        return evidence

    def confirm_image(self, job, reference):
        """Record the user's explicit approval of a suggested or entered image."""
        if job.options["analysisMode"] != "scanner":
            raise ValueError("Image confirmation is available for scanner findings review only.")
        reference = (reference or "").strip()
        scanner_csv.parse_image_reference(reference)
        with self.lock:
            if job.status != "ready":
                raise ValueError("Upload a vulnerability report before confirming its image.")
            job.options["imageReference"] = reference
            job.options["imageConfirmed"] = True
        return job.snapshot()

    def _write_assessment_bundle(self, job, return_code):
        """Write a self-contained evidence manifest after report reconciliation."""
        try:
            results = json.loads(job.results_path.read_text(encoding="utf-8"))
            results_error = None
        except (OSError, json.JSONDecodeError) as exc:
            results = None
            results_error = str(exc)

        profile = assessment_policy.profile(job.options["assessmentProfile"])
        policy = assessment_policy.evaluate(profile, results)
        artifacts = {
            name: artifact_evidence(path)
            for name, path in {
                "input": job.input_path,
                "markdownReport": job.report_path,
                "structuredResults": job.results_path,
                "derivedVex": job.vex_path,
                "catalogSbom": job.catalog_sbom_path,
                "scannerEvidence": job.scanner_evidence_path,
                "scannerReviewCsv": job.scanner_csv_path,
            }.items()
        }
        evidence = {
            "analysisSource": self.source,
            "vexCache": vex_cache_evidence(VEX_CACHE_PATH),
        }
        module = results.get("summary", {}).get("module") if isinstance(results, dict) else None
        if self.source == "osidb" and module:
            bomq_cache = APP_ROOT / ".cache" / f"bomq-{module}.json"
            evidence["bomqCache"] = artifact_evidence(bomq_cache) or {"present": False}
        bundle = {
            "schema": ASSESSMENT_BUNDLE_SCHEMA,
            "version": ASSESSMENT_BUNDLE_VERSION,
            "createdAt": utc_now(),
            "tool": {
                "name": self.product_name,
                "uiSourceSha256": sha256_file(Path(__file__)),
                "checkerSourceSha256": sha256_file(CLI_PATH),
            },
            "run": {
                "id": job.job_id,
                "analysisMode": job.options["analysisMode"],
                "source": self.source,
                "startedAt": job.started_at,
                "finishedAt": utc_now(),
                "returnCode": return_code,
            },
            "profile": profile,
            "policy": policy,
            "evidence": evidence,
            "artifacts": {name: item for name, item in artifacts.items() if item is not None},
            "resultSummary": results.get("summary") if isinstance(results, dict) else None,
        }
        if results_error:
            bundle["resultsError"] = results_error
        temporary = job.assessment_bundle_path.with_suffix(".json.tmp")
        temporary.write_text(json.dumps(bundle, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        temporary.chmod(0o600)
        temporary.replace(job.assessment_bundle_path)
        job.assessment_bundle_path.chmod(0o400)

    def _run(self, job):
        try:
            analysis_input = job.input_path
            scanner_evidence = None
            with job.log_path.open("wb") as log:
                if job.options["analysisMode"] == "scanner":
                    log.write(b"Parsing vulnerability report and resolving the scanned image in Red Hat Catalog...\n")
                    try:
                        podman = scanner_csv.podman_status()
                        if podman["available"]:
                            log.write(b"Podman is available; validating the confirmed image's installed RPM database...\n")
                            image_validator = lambda subject: scanner_csv.inspect_image_with_podman(
                                subject, availability=podman
                            )
                        else:
                            log.write(f"WARNING: {podman['message']} Catalog RPM evidence will be used instead.\n".encode())
                            image_validator = lambda subject: {**podman, "rpms": []}
                        subject, scanner_evidence = scanner_csv.prepare_scanner_analysis(
                            job.input_path, job.options["imageReference"], job.options["architecture"],
                            job.catalog_sbom_path, job.scanner_evidence_path, image_validator=image_validator,
                        )
                    except scanner_csv.ScannerInputError as exc:
                        raise ValueError(str(exc)) from exc
                    analysis_input = job.catalog_sbom_path
                    scanner_cves = sorted({record["cve_id"] for record in scanner_evidence["findings"]})
                    scanner_components = sorted({
                        record["scanner"]["component"] for record in scanner_evidence["findings"]
                        if record["scanner"].get("component")
                    })
                    job.scanner_cves_path.write_text("\n".join(scanner_cves) + "\n", encoding="utf-8")
                    job.scanner_components_path.write_text("\n".join(scanner_components) + "\n", encoding="utf-8")
                    log.write(f"Resolved image: {subject.resolved_reference}\n".encode())
                    log.write(f"Local image validation: {scanner_evidence.get('podman', {}).get('message', 'not requested')}\n".encode())
                    log.write(b"Wrote a local CycloneDX export from the published Catalog RPM manifest.\n")
            command = [sys.executable, str(CLI_PATH), str(analysis_input), "--workers", str(job.options["workers"]),
                       "--report-json", str(job.results_path)]
            if self.source in {"vex", "vex-direct"}:
                command.append("--vex")
            if self.source == "vex-direct":
                command.append("--vex-direct-components")
                if job.options.get("pyxisImageReference"):
                    command.extend([
                        "--pyxis-image", job.options["pyxisImageReference"],
                        "--pyxis-architecture", job.options.get("pyxisArchitecture", "amd64"),
                    ])
            if not scanner_evidence:
                command.extend(["--vex-output", str(job.vex_path)])
            if scanner_evidence:
                command.extend([
                    "--only-cves-file", str(job.scanner_cves_path),
                    "--only-components-file", str(job.scanner_components_path),
                ])
            with job.report_path.open("wb") as report, job.log_path.open("ab") as log:
                completed = subprocess.run(command, cwd=APP_ROOT, stdout=report, stderr=log, check=False)
            if scanner_evidence and job.results_path.is_file():
                scanner_csv.reconcile_scanner_results(job.results_path, scanner_evidence)
                scanner_csv.write_scanner_review_csv(
                    job.scanner_csv_path, job.results_path, scanner_evidence
                )
            if scanner_evidence and job.report_path.is_file():
                inventory_report = job.report_path.read_text(encoding="utf-8", errors="replace")
                scanner_report = scanner_csv.render_scanner_evidence_markdown(scanner_evidence)
                job.report_path.write_text(f"{scanner_report}\n---\n\n{inventory_report}", encoding="utf-8")
            if job.results_path.is_file() and job.results_path.stat().st_size:
                self._write_assessment_bundle(job, completed.returncode)
            with self.lock:
                job.return_code = completed.returncode
                job.status = "completed" if completed.returncode == 0 else "failed"
                if completed.returncode:
                    job.error = f"The checker exited with status {completed.returncode}. See the progress log."
                job.finished_at = utc_now()
        except Exception as exc:  # Keep server alive and surface the failure in the UI.
            with job.log_path.open("a", encoding="utf-8") as log:
                traceback.print_exc(file=log)
            with self.lock:
                job.status = "failed"
                job.error = str(exc)
                job.finished_at = utc_now()


class AppHandler(BaseHTTPRequestHandler):
    server_version = "cve-report-ui/1.0"

    @property
    def store(self):
        return self.server.store

    @property
    def cache(self):
        return self.server.cache

    def log_message(self, format, *args):
        # Browser requests do not add value to the terminal; checker progress
        # is available in each job's dedicated log instead.
        return

    def do_GET(self):
        path = urlparse(self.path).path
        if path == "/":
            return self.send_bytes(HTTPStatus.OK, APP_HTML.encode(), "text/html; charset=utf-8")
        if path == "/api/vex-cache":
            return self.send_json(HTTPStatus.OK, self.cache.snapshot())
        if path == "/api/podman":
            return self.send_json(HTTPStatus.OK, scanner_csv.podman_status())
        match = re.fullmatch(r"/api/jobs/([0-9a-f]{32})", path)
        if match:
            job = self.store.get(match.group(1))
            return self.send_json(HTTPStatus.OK, job.snapshot()) if job else self.send_error_json(HTTPStatus.NOT_FOUND, "Run not found.")
        match = re.fullmatch(r"/api/jobs/([0-9a-f]{32})/(report|results|vex|catalog-sbom|scanner-evidence|scanner-csv|assessment-bundle)", path)
        if match:
            job = self.store.get(match.group(1))
            if not job:
                return self.send_error_json(HTTPStatus.NOT_FOUND, "Run not found.")
            artifact_name = match.group(2)
            artifact = {
                "report": job.report_path,
                "results": job.results_path,
                "vex": job.vex_path,
                "catalog-sbom": job.catalog_sbom_path,
                "scanner-evidence": job.scanner_evidence_path,
                "scanner-csv": job.scanner_csv_path,
                "assessment-bundle": job.assessment_bundle_path,
            }[artifact_name]
            if not artifact.is_file() or not artifact.stat().st_size:
                return self.send_error_json(HTTPStatus.NOT_FOUND, "Artifact is not ready.")
            content_type = {
                "report": "text/markdown; charset=utf-8",
                "scanner-csv": "text/csv; charset=utf-8",
            }.get(artifact_name, "application/json")
            return self.send_file(artifact, content_type)
        self.send_error_json(HTTPStatus.NOT_FOUND, "Not found.")

    def do_POST(self):
        cache_match = re.fullmatch(r"/api/vex-cache/(refresh|rebuild)", path := urlparse(self.path).path)
        if cache_match:
            try:
                self.cache.start(cache_match.group(1), self.store.is_running())
                self.send_json(HTTPStatus.ACCEPTED, self.cache.snapshot())
            except RuntimeError as exc:
                self.send_error_json(HTTPStatus.CONFLICT, str(exc))
            except ValueError as exc:
                self.send_error_json(HTTPStatus.BAD_REQUEST, str(exc))
            return
        if path == "/api/jobs":
            try:
                job = self.store.create(validate_options(self.read_json()))
                self.send_json(HTTPStatus.CREATED, {"id": job.job_id, "status": job.status})
            except ValueError as exc:
                self.send_error_json(HTTPStatus.BAD_REQUEST, str(exc))
            return
        match = re.fullmatch(r"/api/jobs/([0-9a-f]{32})/image-candidates", path)
        if match:
            job = self.store.get(match.group(1))
            if not job:
                return self.send_error_json(HTTPStatus.NOT_FOUND, "Run not found.")
            try:
                candidates = self.store.match_image(job)
                self.send_json(HTTPStatus.OK, {"candidates": candidates})
            except scanner_csv.ScannerInputError as exc:
                self.send_error_json(HTTPStatus.BAD_REQUEST, str(exc))
            except ValueError as exc:
                self.send_error_json(HTTPStatus.BAD_REQUEST, str(exc))
            return
        match = re.fullmatch(r"/api/jobs/([0-9a-f]{32})/confirm-image", path)
        if match:
            job = self.store.get(match.group(1))
            if not job:
                return self.send_error_json(HTTPStatus.NOT_FOUND, "Run not found.")
            try:
                payload = self.read_json()
                self.send_json(HTTPStatus.OK, self.store.confirm_image(job, payload.get("imageReference")))
            except scanner_csv.ScannerInputError as exc:
                self.send_error_json(HTTPStatus.BAD_REQUEST, str(exc))
            except ValueError as exc:
                self.send_error_json(HTTPStatus.BAD_REQUEST, str(exc))
            return
        match = re.fullmatch(r"/api/jobs/([0-9a-f]{32})/run", path)
        if match:
            job = self.store.get(match.group(1))
            if not job:
                return self.send_error_json(HTTPStatus.NOT_FOUND, "Run not found.")
            try:
                self.store.start(job)
                self.send_json(HTTPStatus.ACCEPTED, job.snapshot())
            except RuntimeError as exc:
                self.send_error_json(HTTPStatus.CONFLICT, str(exc))
            except ValueError as exc:
                self.send_error_json(HTTPStatus.BAD_REQUEST, str(exc))
            return
        self.send_error_json(HTTPStatus.NOT_FOUND, "Not found.")

    def do_PUT(self):
        match = re.fullmatch(r"/api/jobs/([0-9a-f]{32})/input", urlparse(self.path).path)
        if not match:
            return self.send_error_json(HTTPStatus.NOT_FOUND, "Not found.")
        job = self.store.get(match.group(1))
        if not job:
            return self.send_error_json(HTTPStatus.NOT_FOUND, "Run not found.")
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if not 0 < length <= MAX_UPLOAD_BYTES:
                raise ValueError("SBOM must be between 1 byte and 100 MB.")
            with job.input_path.open("wb") as handle:
                remaining = length
                while remaining:
                    chunk = self.rfile.read(min(64 * 1024, remaining))
                    if not chunk:
                        raise ValueError("Upload ended before the full SBOM was received.")
                    handle.write(chunk)
                    remaining -= len(chunk)
            with self.store.lock:
                job.status = "ready"
            self.send_json(HTTPStatus.CREATED, job.snapshot())
        except ValueError as exc:
            self.send_error_json(HTTPStatus.BAD_REQUEST, str(exc))

    def read_json(self):
        length = int(self.headers.get("Content-Length", "0"))
        if not 0 < length <= 64 * 1024:
            raise ValueError("Configuration is missing or too large.")
        try:
            return json.loads(self.rfile.read(length))
        except json.JSONDecodeError as exc:
            raise ValueError("Configuration is not valid JSON.") from exc

    def send_json(self, status, data):
        self.send_bytes(status, json.dumps(data).encode(), "application/json; charset=utf-8")

    def send_error_json(self, status, message):
        self.send_json(status, {"error": message})

    def send_file(self, path, content_type):
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(path.stat().st_size))
        self.send_header("Content-Disposition", f'attachment; filename="{path.name}"')
        self.end_headers()
        with path.open("rb") as artifact:
            while chunk := artifact.read(64 * 1024):
                self.wfile.write(chunk)

    def send_bytes(self, status, payload, content_type):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(payload)


APP_HTML = r"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>CVE report workbench</title><style>
:root { --paper:#f5f5f5; --panel:#ffffff; --panel-strong:#f2f2f2; --ink:#151515; --muted:#6a6e73; --line:#d2d2d2; --rail:#151515; --signal:#e92f22; --signal-soft:#fce3e3; --steel:#0066cc; --moss:#3e8635; --warning:#ec7a08; --white:#ffffff; --slate:#151515; --alert:#b14a18; --font-display:"Iowan Old Style","Palatino Linotype","Book Antiqua",Georgia,serif; --font-ui:"Avenir Next","Segoe UI","Helvetica Neue",Arial,sans-serif; }
* { box-sizing:border-box; } body { margin:0; min-height:100vh; color:var(--ink); background:var(--paper); font:16px/1.45 var(--font-ui); } header { display:grid; grid-template-columns:minmax(0,1fr) minmax(300px,440px); gap:24px; align-items:center; padding:12px clamp(20px,4vw,72px); color:var(--white); background:var(--rail); border-bottom:4px solid var(--signal); } header h1 { margin:0; font:700 clamp(1.25rem,1.9vw,1.7rem)/.94 var(--font-display); letter-spacing:0; } header p { max-width:760px; margin:6px 0 0; color:#c7c7c7; font-size:.9rem; }.cache-console { padding:9px 0 2px 18px; border-left:1px solid #555; }.cache-console h2 { margin:0; color:var(--white); font:700 .94rem/1.15 var(--font-ui); letter-spacing:0; }.cache-status { margin:3px 0 8px; color:#d5d5d5; font-size:.8rem; }.cache-actions { display:flex; align-items:center; gap:8px; }.cache-actions button { width:auto; margin:0; padding:7px 10px; color:var(--white); font-size:.8rem; background:#343434; border:1px solid #777; border-radius:2px; }.cache-actions button.primary { background:var(--signal); border-color:var(--signal); }.cache-actions button:hover { background:#555; }.cache-actions button.primary:hover { background:#bd2017; }.cache-console details { margin:7px 0 0; border:0; }.cache-console summary { padding:0; color:#c7c7c7; font-size:.76rem; font-weight:600; }.cache-console pre { max-height:150px; margin:7px 0 0; padding:8px; color:#d8e8f1; background:#242424; border-left:2px solid var(--steel); font-size:11px; }
.workspace,.evidence { width:calc(100% - clamp(24px,4vw,72px)); margin:clamp(18px,2vw,32px) auto; } .workspace { display:grid; grid-template-columns:minmax(0,1fr) minmax(0,2.4fr); gap:clamp(16px,1.7vw,30px); align-items:stretch; } .workbench,.analysis,.evidence { background:var(--panel); border:1px solid var(--line); border-radius:6px; } .workbench,.analysis,.evidence { padding:clamp(18px,1.7vw,30px); } .workbench,.analysis { display:flex; flex-direction:column; } .analysis { min-height:clamp(560px,55vh,760px); }
h2 { margin:0 0 6px; font-size:1.35rem; letter-spacing:-.025em; } .lede,.hint { margin:0; color:var(--muted); font-size:.92rem; } form { margin-top:24px; } fieldset { margin:0; padding:0; border:0; } legend { margin:0 0 10px; font-weight:700; font-size:.95rem; }
.mode-choice { display:grid; gap:9px; margin:18px 0 22px; } .mode-choice label { cursor:pointer; } .mode-choice input,.choice input { position:absolute; opacity:0; } .mode-choice span { display:block; padding:13px 14px; border:1px solid var(--line); border-left:5px solid var(--line); background:#f7fafc; } .mode-choice strong,.mode-choice small { display:block; } .mode-choice small { margin-top:2px; color:var(--muted); font-weight:400; } .mode-choice input:checked + span { border-color:var(--slate); border-left-color:var(--signal); background:#e8f3f5; } input:focus-visible + span { outline:3px solid #7ac5cc; outline-offset:2px; }
.workflow-divider { display:flex; align-items:center; gap:10px; margin:0 0 20px; color:var(--muted); font-size:.82rem; font-weight:650; } .workflow-divider::after { content:""; flex:1; height:1px; background:var(--line); }
.drop { display:flex; align-items:center; justify-content:space-between; gap:12px; margin:0 0 18px; padding:10px 12px; cursor:pointer; color:var(--ink); border:1px dashed var(--muted); border-radius:3px; background:var(--panel-strong); } .drop:focus-within { outline:3px solid #b7d4ef; outline-offset:3px; } .drop strong { max-width:58%; } .drop input { position:absolute; inline-size:1px; block-size:1px; opacity:0; } .file-name { max-width:42%; overflow:hidden; color:var(--muted); font-size:.84rem; font-weight:500; text-align:right; text-overflow:ellipsis; white-space:nowrap; }.choice { display:flex; gap:8px; margin:12px 0 20px; }.choice label { flex:1; cursor:pointer;}.choice span { display:block; padding:10px 12px; text-align:center; border:1px solid var(--line);}.choice input:checked + span { color:var(--white); background:var(--slate); border-color:var(--slate); }
.authority,.summary { padding:12px; color:var(--ink); background:#e7f1fa; border-left:5px solid var(--steel); font-size:.9rem; }.authority { margin:0 0 14px; padding:9px 11px; }.authority strong { display:block; }.hint.warning { margin-top:6px; color:#8a4600; }.workbench form { display:flex; flex:1; flex-direction:column; margin-top:18px; }.fields { display:grid; grid-template-columns:repeat(2,minmax(0,1fr)); gap:12px; }.fields .hint { grid-column:1 / -1; } label { display:block; font-weight:650; font-size:.9rem; } input[type=text],input[type=number],select { width:100%; margin-top:6px; padding:10px; color:var(--ink); font:inherit; background:var(--white); border:1px solid var(--line); border-radius:3px; }.toggle { display:flex; gap:9px; align-items:center; margin-top:14px; font-weight:500; }.toggle input { width:18px; height:18px; accent-color:var(--signal); }
.image-match { margin-top:14px; padding:12px; background:#f7fafc; border:1px solid var(--line); border-left:5px solid var(--steel); }.image-match > strong { display:block; }.image-match .hint { margin-top:3px; }.candidate-list { display:grid; gap:8px; margin:12px 0; }.candidate-choice { display:block; padding:10px; cursor:pointer; border:1px solid var(--line); background:var(--white); }.candidate-choice:has(input:checked) { border-color:var(--steel); box-shadow:inset 3px 0 var(--steel); }.candidate-choice input { margin-right:8px; accent-color:var(--steel); }.candidate-choice strong,.candidate-choice small { display:block; margin-left:22px; }.candidate-choice small { margin-top:2px; color:var(--muted); font-weight:400; }.image-match button { margin:0; padding:10px 12px; font-size:.9rem; }
button { width:100%; margin-top:auto; padding:14px 18px; cursor:pointer; color:var(--white); font:700 1rem/1.2 inherit; background:var(--signal); border:0; border-radius:3px; } button:hover { background:#bd2017; } button:disabled { cursor:wait; background:#a6a6a6; }.status { margin:17px 0 12px; padding:11px 12px; color:var(--ink); background:#e7f1fa; border-left:5px solid var(--steel); font-weight:650;}.status.error { color:#5b2408; background:#fff3e8; border-color:var(--warning); }
.analysis-head { display:flex; justify-content:space-between; gap:clamp(14px,2vw,28px); align-items:start; }.summary { flex:0 1 32%; }.filters { display:grid; grid-template-columns:1.5fr repeat(3,minmax(0,.7fr)); gap:clamp(8px,1vw,14px); margin:20px 0 12px; }.filters input,.filters select { margin:0; }.table-wrap { overflow:auto; border:1px solid var(--line); border-radius:3px; } table { width:100%; border-collapse:collapse; font-size:clamp(.8rem,.82vw,.92rem); } th { color:var(--ink); background:var(--panel-strong); text-align:left; white-space:nowrap; } th,td { padding:clamp(8px,.7vw,12px); vertical-align:top; border-bottom:1px solid var(--line); } td { max-width:clamp(11rem,18vw,28rem); } tbody tr:nth-child(even) { background:#f7f7f7; }.empty { padding:clamp(30px,4vw,58px) 22px; color:var(--muted); border:1px dashed var(--line); text-align:center; }.pagination { display:flex; justify-content:end; align-items:center; gap:10px; margin:12px 0 22px; color:var(--muted); font-size:.86rem; }.pagination button { width:auto; margin:0; padding:7px 10px; color:var(--ink); background:var(--paper); border:1px solid var(--line); border-radius:3px; font-size:.85rem; }.pagination button:hover { color:var(--white); background:var(--rail); }.pagination button:disabled { color:var(--muted); background:#eee; }.downloads { display:flex; flex-wrap:wrap; gap:10px; padding-top:16px; border-top:1px solid var(--line); }.downloads a { padding:9px 11px; color:var(--ink); border:1px solid var(--line); border-radius:3px; text-decoration:none; font-weight:700; }.downloads a:hover { color:var(--white); background:var(--rail); } pre { max-height:420px; margin:0 0 12px; padding:14px; overflow:auto; color:#262626; background:#f2f2f2; border-left:5px solid var(--steel); font:12px/1.48 ui-monospace,SFMono-Regular,Menlo,monospace; white-space:pre-wrap; }.evidence { margin-top:0; }.evidence pre { max-height:360px; color:#d8e8f1; background:#151515; border-left:0; } [hidden] { display:none !important; } footer { width:calc(100% - clamp(24px,4vw,72px)); margin:0 auto 30px; color:var(--muted); font-size:.85rem; }
@media (max-width:900px) { header { grid-template-columns:1fr; gap:14px; }.cache-console { padding:0; border-left:0; }.workspace { grid-template-columns:1fr; }.analysis { min-height:0; }.workbench form { display:block; }.workbench button { margin-top:26px; }.filters { grid-template-columns:1fr 1fr; }.analysis-head { display:block; }.summary { margin-top:16px; } } @media (max-width:560px) { .fields,.filters { grid-template-columns:1fr; } } @media (prefers-reduced-motion:reduce) { * { scroll-behavior:auto; } }
</style></head><body>
<header><div><h1>CVE report workbench</h1><p>Choose a complete image report or a scanner-finding review. OSIDB determines unresolved component status; provenance determines the RHEL release automatically from the input.</p></div></header>
<main class="workspace"><section class="workbench" aria-labelledby="run-title"><h2 id="run-title">Start an analysis</h2><p class="lede" id="mode-description">Assess every component in an SBOM or RPM manifest, then produce a full report and local CSAF VEX.</p><form id="run-form">
<fieldset class="mode-choice" id="analysis-mode"><legend>Analysis type</legend><label><input name="analysisMode" type="radio" value="holistic" checked><span><strong>Holistic image report</strong><small>Evaluate every SBOM component using OSIDB tracker status.</small></span></label><label><input name="analysisMode" type="radio" value="scanner"><span><strong>Scanner findings review</strong><small>Correlate a vulnerability report to a resolved Red Hat image and add per-finding provenance evidence.</small></span></label></fieldset>
<div class="workflow-divider" id="analysis-settings-divider">Analysis settings</div>
<label class="drop" for="input"><strong id="input-title">Choose an SBOM or RPM manifest</strong><span class="file-name" id="file-name">No file selected</span><input id="input" type="file" accept=".json,.spdx.json,.cdx.json,.txt" required></label>
<section class="authority"><strong>Analysis uses OSIDB tracker status.</strong> Results reflect unresolved Red Hat product affects and fixed-build evaluation for the image inventory.</section><section class="authority" id="scanner-authority" hidden><strong>Scanner review also links each finding to the resolved image.</strong> The report retains the original scanner assertion and matches it against the image's published RPM inventory.<p class="hint" id="podman-status" hidden></p></section>
<div class="fields" id="scanner-fields" hidden><label>Scanned container image<input id="image-reference" type="text" placeholder="registry.access.redhat.com/ubi10/ubi:10.2"></label><label>Image architecture<select id="architecture"><option value="amd64">x86_64 / amd64</option><option value="arm64">aarch64 / arm64</option><option value="ppc64le">ppc64le</option><option value="s390x">s390x</option></select></label><p class="hint">Leave the image blank to match the report name against Red Hat Catalog. You will review and explicitly confirm a suggested image before analysis.</p></div>
<section class="image-match" id="image-match" hidden aria-live="polite"><strong>Confirm registry image</strong><p class="hint" id="image-match-summary"></p><div class="candidate-list" id="image-candidates"></div><button id="confirm-image" type="button">Use selected image and run analysis</button></section>
<button id="run" type="submit">Run analysis</button></form></section>
<section class="analysis" aria-labelledby="results-title"><div class="analysis-head"><div><h2 id="results-title">Analysis results</h2><p class="lede" id="results-description">Completed findings will appear here as a sortable, filterable view.</p></div><div class="summary" id="summary" hidden></div></div><div id="results-empty" class="empty">Run an analysis to view findings and component provenance here.</div><section id="results-content" hidden><div class="filters"><input id="finding-filter" type="text" placeholder="Filter CVE, component, advisory, or stream"><select id="impact-filter"><option value="">All impacts</option><option>CRITICAL</option><option>IMPORTANT</option><option>MODERATE</option><option>LOW</option><option>UNSET</option></select><select id="status-filter"><option value="">All statuses</option><option value="unfixed">Unfixed</option><option value="fixed">Fixed</option><option value="not a bug">Not a bug</option><option value="unverified">Unverified</option></select><select id="sort-findings"><option value="impact">Sort: impact</option><option value="cve">Sort: CVE</option><option value="cvss">Sort: CVSS</option><option value="status">Sort: status</option></select></div><p class="hint" id="finding-count"></p><div class="table-wrap"><table><thead><tr><th>Impact</th><th>CVE</th><th>CVSS</th><th>Status</th><th>Advisory</th><th>Origin component</th><th>Upstream origin</th></tr></thead><tbody id="findings-body"></tbody></table></div><nav class="pagination" aria-label="Findings pages"><button id="previous-page" type="button">Previous</button><span id="page-summary"></span><button id="next-page" type="button">Next</button></nav><div class="downloads" id="downloads" hidden><a id="report-link" href="#">Download Markdown report</a><a id="results-link" href="#">Download structured results</a><a id="vex-link" href="#">Download derived image VEX</a><a id="catalog-sbom-link" href="#" hidden>Download Catalog-derived SBOM</a><a id="scanner-evidence-link" href="#" hidden>Download scanner provenance evidence</a><a id="scanner-csv-link" href="#" hidden>Download scanner review CSV</a></div><p class="hint" id="downloads-note" hidden></p></section></section></main>
<section class="evidence" aria-live="polite"><h2>Run evidence</h2><p class="hint">Execution log.</p><div id="status" class="status">Choose an analysis type and input to begin.</div><pre id="log">No run yet.</pre></section><footer>Local-only interface · One analysis runs at a time to avoid overwhelming backing services.</footer>
<script>
const $=id=>document.getElementById(id); let currentJob=null,poller=null,resultData=null,currentPage=1; const PAGE_SIZE=10; const fileInput=$('input'),modeInputs=[...document.querySelectorAll('input[name=analysisMode]')];
function mode(){return modeInputs.find(i=>i.checked).value} async function updatePodmanStatus(){const node=$('podman-status');try{const podman=await api('/api/podman');node.hidden=false;node.textContent=podman.available?`${podman.message} The confirmed image will be checked locally in addition to Catalog evidence.`:`${podman.message} Scanner review will use Catalog RPM evidence only.`;node.classList.toggle('warning',!podman.available)}catch(error){node.hidden=false;node.textContent=`Podman status could not be checked: ${error.message}. Scanner review will use Catalog RPM evidence only.`;node.classList.add('warning')}} function updateMode(){const scanner=mode()==='scanner';fileInput.value='';$('file-name').textContent=fileInput.files[0]?.name||'No file selected';$('input-title').textContent=scanner?'Choose a vulnerability report':'Choose an SBOM or RPM manifest';fileInput.accept=scanner?'.csv,.json,.out,.txt':'.json,.spdx.json,.cdx.json,.txt';$('scanner-authority').hidden=!scanner;$('scanner-fields').hidden=!scanner;$('podman-status').hidden=!scanner;if(scanner)updatePodmanStatus();$('image-match').hidden=true;$('run').hidden=false;$('run').disabled=false;currentJob=null;$('mode-description').textContent=scanner?'Review findings from a vulnerability report against the scanned image and retain evidence for each finding.':'Assess every component in an SBOM or RPM manifest against OSIDB tracker status; RHEL release is inferred from component provenance.'}
function setStatus(message,error=false){const node=$('status');node.textContent=message;node.classList.toggle('error',error)} function setFile(){const file=fileInput.files[0];$('file-name').textContent=file?file.name:'No file selected'} fileInput.addEventListener('change',setFile);modeInputs.forEach(i=>i.addEventListener('change',updateMode));updateMode();
async function api(url,options={}){const response=await fetch(url,options);const data=await response.json().catch(()=>({}));if(!response.ok)throw new Error(data.error||'Request failed.');return data}
function cell(row,text){const td=document.createElement('td');td.textContent=text||'—';row.append(td)}
function linkCell(row,text,url){const td=document.createElement('td');if(!text){td.textContent='—'}else{const link=document.createElement('a');link.href=url;link.target='_blank';link.rel='noopener';link.textContent=text;td.append(link)}row.append(td)}
function advisoryCell(row,advisories){const td=document.createElement('td');if(!advisories?.length){td.textContent='—'}else{advisories.forEach((advisory,index)=>{if(index)td.append(' ');const link=document.createElement('a');link.href=`https://access.redhat.com/errata/${encodeURIComponent(advisory)}`;link.target='_blank';link.rel='noopener';link.textContent=advisory.replace(/-(\d{4}):/,(_,year)=>`-${year.slice(2)}:`);td.append(link)})}row.append(td)}
function componentText(row,key,fallback='not found'){return row.components.flatMap(c=>c[key]||[]).filter(Boolean).join(', ')||fallback}
function filteredFindings(){if(!resultData)return[];const needle=$('finding-filter').value.trim().toLowerCase(),impact=$('impact-filter').value,status=$('status-filter').value,sort=$('sort-findings').value;const rows=resultData.findings.filter(row=>{const text=[row.cveId,row.remediationStatus,(row.advisories||[]).join(' '),componentText(row,'imageComponents'),componentText(row,'originNvrs'),componentText(row,'upstreamStreams')].join(' ').toLowerCase();return(!needle||text.includes(needle))&&(!impact||row.impact===impact)&&(!status||row.remediationStatus===status)});const order={CRITICAL:0,IMPORTANT:1,MODERATE:2,LOW:3,UNSET:4};return rows.sort((a,b)=>sort==='cve'?a.cveId.localeCompare(b.cveId):sort==='cvss'?(b.cvss??-1)-(a.cvss??-1):sort==='status'?(a.remediationStatus||'').localeCompare(b.remediationStatus||''):(order[a.impact]??9)-(order[b.impact]??9)||a.cveId.localeCompare(b.cveId))}
function renderFindings(){const body=$('findings-body');body.replaceChildren();const rows=filteredFindings(),pages=Math.max(1,Math.ceil(rows.length/PAGE_SIZE));currentPage=Math.min(currentPage,pages);const first=(currentPage-1)*PAGE_SIZE,visible=rows.slice(first,first+PAGE_SIZE);$('finding-count').textContent=`${rows.length} of ${resultData.findings.length} CVEs shown`;$('page-summary').textContent=`Page ${currentPage} of ${pages}`;$('previous-page').disabled=currentPage===1;$('next-page').disabled=currentPage===pages;for(const item of visible){const row=document.createElement('tr');cell(row,item.impact);linkCell(row,item.cveId,`https://access.redhat.com/security/cve/${encodeURIComponent(item.cveId)}`);cell(row,item.cvss==null?'N/A':item.cvss.toFixed(1));cell(row,item.remediationStatus);advisoryCell(row,item.advisories);cell(row,componentText(item,'originNvrs'));cell(row,componentText(item,'upstreamStreams'));body.append(row)}}
function renderResults(data){resultData=data;currentPage=1;const s=data.summary;$('summary').hidden=false;$('summary').textContent=`${s.unfixedCves??s.unresolvedCves} unfixed · ${s.fixedCves??0} fixed · ${s.unverifiedCves??0} unverified · ${s.componentsScanned} components · ${s.module} · ${s.source}`;$('results-empty').hidden=true;$('results-content').hidden=false;renderFindings()} function resetResultsPage(){currentPage=1;renderFindings()} ['finding-filter','impact-filter','status-filter','sort-findings'].forEach(id=>{ $(id).addEventListener('input',resetResultsPage); $(id).addEventListener('change',resetResultsPage); });$('previous-page').addEventListener('click',()=>{if(currentPage>1){currentPage--;renderFindings()}});$('next-page').addEventListener('click',()=>{const pages=Math.max(1,Math.ceil(filteredFindings().length/PAGE_SIZE));if(currentPage<pages){currentPage++;renderFindings()}});
function renderImageCandidates(candidates){const list=$('image-candidates');list.replaceChildren();$('image-match').hidden=false;$('image-match-summary').textContent=candidates.length?'Review the Catalog candidates below. The report name is evidence only; choose the image you want to analyze.':'No Catalog candidate was found. Enter the exact tagged image above, then confirm it.';for(const [index,candidate] of candidates.entries()){const label=document.createElement('label'),input=document.createElement('input'),title=document.createElement('strong'),detail=document.createElement('small');label.className='candidate-choice';input.type='radio';input.name='image-candidate';input.value=candidate.reference;input.checked=index===0;title.textContent=candidate.reference;detail.textContent=`Score ${candidate.score}/100 · ${candidate.reasons.join(' · ')}`;label.append(input,title,detail);list.append(label)}}
async function showCompleted(job){const base=`/api/jobs/${job.id}`;renderResults(await api(`${base}/results`))} async function finish(job){const scanner=job.analysisMode==='scanner',base=`/api/jobs/${job.id}`;$('report-link').href=`${base}/report`;$('results-link').href=`${base}/results`;$('vex-link').href=`${base}/vex`;$('catalog-sbom-link').href=`${base}/catalog-sbom`;$('scanner-evidence-link').href=`${base}/scanner-evidence`;$('scanner-csv-link').href=`${base}/scanner-csv`;$('downloads').hidden=!(job.reportReady||job.resultsReady||(!scanner&&job.vexReady)||job.catalogSbomReady||job.scannerEvidenceReady||job.scannerCsvReady);$('report-link').hidden=!job.reportReady;$('results-link').hidden=!job.resultsReady;$('vex-link').hidden=scanner||!job.vexReady;$('catalog-sbom-link').hidden=!job.catalogSbomReady;$('scanner-evidence-link').hidden=!job.scannerEvidenceReady;$('scanner-csv-link').hidden=!job.scannerCsvReady;$('downloads-note').hidden=false;$('downloads-note').textContent=scanner?'Scanner review includes only CVEs from the uploaded report. Unverified means no matching Red Hat origin affect was found.':'The report and derived VEX cover the full supplied inventory.';if(job.resultsReady)await showCompleted(job)}
async function poll(){if(!currentJob)return;try{const job=await api(`/api/jobs/${currentJob}`);$('log').textContent=job.log||'Preparing analysis…';setStatus(job.error||job.status,job.status==='failed');if(job.status==='completed'||job.status==='failed'){clearInterval(poller);poller=null;$('run').disabled=false;$('run').hidden=false;await finish(job)}}catch(error){setStatus(error.message,true)}} async function startAnalysis(){await api(`/api/jobs/${currentJob}/run`,{method:'POST'});$('image-match').hidden=true;setStatus('Analysis is running.');poller=setInterval(poll,1600);await poll()} $('confirm-image').addEventListener('click',async()=>{const selected=document.querySelector('input[name=image-candidate]:checked'),entered=$('image-reference').value.trim();const reference=entered||selected?.value;if(!reference)return setStatus('Choose a Catalog candidate or enter the exact tagged image.',true);$('confirm-image').disabled=true;try{await api(`/api/jobs/${currentJob}/confirm-image`,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({imageReference:reference})});await startAnalysis()}catch(error){$('confirm-image').disabled=false;setStatus(error.message,true)}});$('run-form').addEventListener('submit',async event=>{event.preventDefault();const file=fileInput.files[0],scanner=mode()==='scanner';if(!file)return setStatus(scanner?'Choose a vulnerability report first.':'Choose an SBOM or RPM manifest first.',true);$('run').disabled=true;$('downloads').hidden=true;$('downloads-note').hidden=true;$('results-empty').hidden=false;$('results-content').hidden=true;$('summary').hidden=true;$('log').textContent='Creating local run…';try{const job=await api('/api/jobs',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({filename:file.name,analysisMode:mode(),imageReference:$('image-reference').value,architecture:$('architecture').value})});currentJob=job.id;setStatus('Uploading input…');await api(`/api/jobs/${job.id}/input`,{method:'PUT',headers:{'Content-Type':'application/octet-stream'},body:file});if(scanner){$('run').hidden=true;setStatus('Matching the report to Red Hat Catalog…');try{const match=await api(`/api/jobs/${job.id}/image-candidates`,{method:'POST'});renderImageCandidates(match.candidates)}catch(error){renderImageCandidates([]);setStatus(error.message,true)}return}await startAnalysis()}catch(error){$('run').disabled=false;setStatus(error.message,true);$('log').textContent='No analysis started.'}});
</script></body></html>"""


def main():
    parser = argparse.ArgumentParser(description="Run the local cve-report browser application.")
    parser.add_argument("--port", type=int, default=8765, help="Local port (default: 8765).")
    parser.add_argument("--data-dir", type=Path, default=default_data_dir(), help="Local directory for uploaded SBOMs and results.")
    parser.add_argument("--no-browser", action="store_true", help="Do not open the local URL automatically.")
    args = parser.parse_args()
    if not 0 <= args.port <= 65535:
        parser.error("--port must be between 0 and 65535")
    server = ThreadingHTTPServer(("127.0.0.1", args.port), AppHandler)
    server.store = JobStore(args.data_dir)
    server.cache = VexCacheStore(VEX_CACHE_PATH, args.data_dir / "vex-cache.log")
    url = f"http://127.0.0.1:{server.server_port}/"
    print(f"CVE report workbench: {url}")
    print(f"Local run data: {args.data_dir}")
    if not args.no_browser:
        webbrowser.open(url)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping CVE report workbench.")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
