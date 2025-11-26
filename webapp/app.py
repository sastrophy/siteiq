"""
Security Test Web Application

A Jenkins-like web interface for running security tests against websites.
"""

import json
import os
import subprocess
import sys
import threading
import uuid
from datetime import datetime
from pathlib import Path
from queue import Queue

from flask import Flask, render_template, request, jsonify, Response, stream_with_context

app = Flask(__name__)
app.secret_key = os.urandom(24)

# Store for running tests and their status
tests_store = {}
tests_lock = threading.Lock()

# Base directory for security tests
BASE_DIR = Path(__file__).parent.parent
REPORTS_DIR = BASE_DIR / "reports"
REPORTS_DIR.mkdir(exist_ok=True)


class TestRun:
    """Represents a single test run."""

    def __init__(self, test_id, target_url, options):
        self.id = test_id
        self.target_url = target_url
        self.options = options
        self.status = "pending"  # pending, running, completed, failed
        self.started_at = None
        self.completed_at = None
        self.output_lines = []
        self.findings = []
        self.summary = {}
        self.process = None
        self.output_queue = Queue()

    def to_dict(self):
        return {
            "id": self.id,
            "target_url": self.target_url,
            "options": self.options,
            "status": self.status,
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "output_lines": self.output_lines[-100:],  # Last 100 lines
            "findings": self.findings,
            "summary": self.summary,
        }


# Available test categories
TEST_CATEGORIES = {
    # Security Tests
    "sql_injection": {
        "name": "SQL Injection",
        "description": "Test for SQL injection vulnerabilities",
        "marker": "sql_injection",
        "category": "security",
    },
    "xss": {
        "name": "Cross-Site Scripting (XSS)",
        "description": "Test for XSS vulnerabilities",
        "marker": "xss",
        "category": "security",
    },
    "headers": {
        "name": "Security Headers",
        "description": "Check security headers (CSP, HSTS, etc.)",
        "marker": "headers",
        "category": "security",
    },
    "ssl": {
        "name": "SSL/TLS",
        "description": "Test SSL/TLS configuration",
        "marker": "ssl",
        "category": "security",
    },
    "auth": {
        "name": "Authentication",
        "description": "Test authentication security",
        "marker": "auth",
        "category": "security",
    },
    "wordpress": {
        "name": "WordPress",
        "description": "WordPress-specific security tests",
        "marker": "wordpress",
        "category": "security",
    },
    "traversal": {
        "name": "Directory Traversal",
        "description": "Test for path traversal and file inclusion",
        "marker": "traversal",
        "category": "security",
    },
    "csrf": {
        "name": "CSRF & OWASP",
        "description": "CSRF, SSRF, and other OWASP tests",
        "marker": "csrf",
        "category": "security",
    },
    # SEO Tests
    "seo": {
        "name": "SEO Analysis",
        "description": "Full SEO analysis (meta, headings, images, etc.)",
        "marker": "seo",
        "category": "seo",
    },
    "meta_tags": {
        "name": "Meta Tags",
        "description": "Check title, description, and other meta tags",
        "marker": "meta_tags",
        "category": "seo",
    },
    "schema": {
        "name": "Schema Markup",
        "description": "Validate JSON-LD/structured data",
        "marker": "schema",
        "category": "seo",
    },
    "opengraph": {
        "name": "Open Graph",
        "description": "Check Open Graph and Twitter Card tags",
        "marker": "opengraph or twitter",
        "category": "seo",
    },
    "performance": {
        "name": "Performance SEO",
        "description": "Page speed and Core Web Vitals",
        "marker": "performance or pagespeed",
        "category": "seo",
    },
    "robots": {
        "name": "Robots & Sitemap",
        "description": "Validate robots.txt and sitemap.xml",
        "marker": "robots or sitemap",
        "category": "seo",
    },
    # GEO Tests
    "geo": {
        "name": "GEO Analysis",
        "description": "Full geo testing (accessibility, latency, content)",
        "marker": "geo",
        "category": "geo",
    },
    "geo_accessibility": {
        "name": "Geo Accessibility",
        "description": "Test site access from multiple regions",
        "marker": "accessibility",
        "category": "geo",
    },
    "geo_latency": {
        "name": "Latency by Region",
        "description": "Response time from different locations",
        "marker": "latency",
        "category": "geo",
    },
    "geo_compliance": {
        "name": "Regional Compliance",
        "description": "GDPR, CCPA and regional requirements",
        "marker": "compliance",
        "category": "geo",
    },
}


def run_tests_thread(test_run: TestRun):
    """Run tests in a background thread."""
    try:
        test_run.status = "running"
        test_run.started_at = datetime.now()

        # Build pytest command
        cmd = [
            sys.executable, "-m", "pytest",
            f"--target-url={test_run.target_url}",
            "-v",
            "--tb=short",
        ]

        # Add markers for selected tests
        if test_run.options.get("tests"):
            markers = " or ".join(test_run.options["tests"])
            cmd.extend(["-m", markers])

        # Add intensity
        if test_run.options.get("intensity"):
            cmd.extend([f"--intensity={test_run.options['intensity']}"])

        # Add WordPress path
        if test_run.options.get("wordpress_path"):
            cmd.extend([f"--wordpress-path={test_run.options['wordpress_path']}"])

        # Skip options
        if test_run.options.get("skip_ssl"):
            cmd.append("--skip-ssl")
        if test_run.options.get("skip_wordpress"):
            cmd.append("--skip-wordpress")

        # Add report ID so the report file is named after this test run
        cmd.append(f"--report-id={test_run.id}")

        test_run.output_lines.append(f"[INFO] Starting security tests for: {test_run.target_url}")
        test_run.output_lines.append(f"[INFO] Command: {' '.join(cmd)}")
        test_run.output_lines.append("")

        # Run pytest
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
            cwd=str(BASE_DIR),
            env={**os.environ, "PYTHONUNBUFFERED": "1"}
        )

        test_run.process = process

        # Read output line by line
        for line in iter(process.stdout.readline, ""):
            line = line.rstrip()
            if line:
                test_run.output_lines.append(line)
                test_run.output_queue.put(line)

        process.wait()

        test_run.completed_at = datetime.now()

        if process.returncode == 0:
            test_run.status = "completed"
            test_run.output_lines.append("")
            test_run.output_lines.append("[SUCCESS] All tests completed successfully!")
        elif process.returncode == 1:
            test_run.status = "completed"
            test_run.output_lines.append("")
            test_run.output_lines.append("[WARNING] Tests completed with some failures (findings detected)")
        else:
            test_run.status = "failed"
            test_run.output_lines.append("")
            test_run.output_lines.append(f"[ERROR] Tests failed with return code: {process.returncode}")

        # Load report if exists
        load_report_findings(test_run)

    except Exception as e:
        test_run.status = "failed"
        test_run.completed_at = datetime.now()
        test_run.output_lines.append(f"[ERROR] Exception: {str(e)}")


def load_report_findings(test_run: TestRun):
    """Load findings from the report file for this specific test run."""
    try:
        # Look for the report file specific to this test run
        report_file = REPORTS_DIR / f"report_{test_run.id}.json"

        if report_file.exists():
            with open(report_file) as f:
                report = json.load(f)
                test_run.findings = report.get("findings", [])
                test_run.summary = report.get("findings_by_severity", {})
        else:
            test_run.output_lines.append(f"[INFO] No findings report generated (no vulnerabilities detected or tests skipped)")
    except Exception as e:
        test_run.output_lines.append(f"[WARNING] Could not load report: {e}")


@app.route("/")
def index():
    """Main dashboard page."""
    return render_template("index.html", categories=TEST_CATEGORIES)


@app.route("/help")
def help_page():
    """User guide and documentation page."""
    return render_template("help.html")


@app.route("/api/scan", methods=["POST"])
def start_scan():
    """Start a new security scan."""
    data = request.json

    target_url = data.get("target_url", "").strip()
    if not target_url:
        return jsonify({"error": "Target URL is required"}), 400

    # Ensure URL has scheme
    if not target_url.startswith(("http://", "https://")):
        target_url = f"https://{target_url}"

    # Create test run
    test_id = str(uuid.uuid4())[:8]
    options = {
        "tests": data.get("tests", []),
        "intensity": data.get("intensity", "medium"),
        "wordpress_path": data.get("wordpress_path", "/blog"),
        "skip_ssl": data.get("skip_ssl", False),
        "skip_wordpress": data.get("skip_wordpress", False),
    }

    test_run = TestRun(test_id, target_url, options)

    with tests_lock:
        tests_store[test_id] = test_run

    # Start tests in background thread
    thread = threading.Thread(target=run_tests_thread, args=(test_run,))
    thread.daemon = True
    thread.start()

    return jsonify({"test_id": test_id, "status": "started"})


@app.route("/api/scan/<test_id>")
def get_scan_status(test_id):
    """Get the status of a scan."""
    with tests_lock:
        test_run = tests_store.get(test_id)

    if not test_run:
        return jsonify({"error": "Test not found"}), 404

    return jsonify(test_run.to_dict())


@app.route("/api/scan/<test_id>/stream")
def stream_scan_output(test_id):
    """Stream scan output using Server-Sent Events."""
    with tests_lock:
        test_run = tests_store.get(test_id)

    if not test_run:
        return jsonify({"error": "Test not found"}), 404

    def generate():
        # First, send existing output
        for line in test_run.output_lines:
            yield f"data: {json.dumps({'type': 'output', 'line': line})}\n\n"

        # Then stream new output
        last_index = len(test_run.output_lines)
        while test_run.status == "running":
            try:
                line = test_run.output_queue.get(timeout=1)
                yield f"data: {json.dumps({'type': 'output', 'line': line})}\n\n"
            except:
                # Send heartbeat
                yield f"data: {json.dumps({'type': 'heartbeat'})}\n\n"

        # Send completion
        yield f"data: {json.dumps({'type': 'complete', 'status': test_run.status, 'summary': test_run.summary, 'findings': test_run.findings})}\n\n"

    return Response(
        stream_with_context(generate()),
        mimetype="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
        }
    )


@app.route("/api/scan/<test_id>/stop", methods=["POST"])
def stop_scan(test_id):
    """Stop a running scan."""
    with tests_lock:
        test_run = tests_store.get(test_id)

    if not test_run:
        return jsonify({"error": "Test not found"}), 404

    if test_run.process and test_run.status == "running":
        test_run.process.terminate()
        test_run.status = "stopped"
        test_run.completed_at = datetime.now()
        test_run.output_lines.append("[INFO] Test stopped by user")
        return jsonify({"status": "stopped"})

    return jsonify({"status": test_run.status})


@app.route("/api/history")
def get_history():
    """Get scan history."""
    with tests_lock:
        history = [
            {
                "id": t.id,
                "target_url": t.target_url,
                "status": t.status,
                "started_at": t.started_at.isoformat() if t.started_at else None,
                "completed_at": t.completed_at.isoformat() if t.completed_at else None,
                "summary": t.summary,
            }
            for t in sorted(tests_store.values(), key=lambda x: x.started_at or datetime.min, reverse=True)
        ]

    return jsonify(history)


@app.route("/results/<test_id>")
def results_page(test_id):
    """Results page for a specific scan."""
    with tests_lock:
        test_run = tests_store.get(test_id)

    if not test_run:
        return "Test not found", 404

    return render_template("results.html", test=test_run.to_dict(), categories=TEST_CATEGORIES)


if __name__ == "__main__":
    app.run(debug=True, port=5000, threaded=True)
