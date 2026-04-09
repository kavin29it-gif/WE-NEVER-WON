from fastapi import FastAPI, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import requests
import re
import uuid
import time

app = FastAPI(title="VulnShield AI", version="1.0.0")

# Allow React frontend to talk to this backend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# In-memory storage for scan results
scan_results = {}

class ScanRequest(BaseModel):
    url: str

# ─── SCANNER LOGIC ────────────────────────────────────────────

def check_sqli(url: str):
    findings = []
    payloads = ["'", "' OR '1'='1", "\" OR \"1\"=\"1", "'; DROP TABLE users;--"]
    error_signatures = [
        "sql syntax", "mysql_fetch", "ora-", "syntax error",
        "unclosed quotation", "pg_query", "sqlite_", "sqlstate"
    ]
    for payload in payloads:
        test_url = url + payload
        try:
            resp = requests.get(test_url, timeout=5, verify=False)
            body = resp.text.lower()
            for sig in error_signatures:
                if sig in body:
                    findings.append({
                        "type": "SQL Injection",
                        "severity": "Critical",
                        "url": test_url,
                        "parameter": "URL parameter",
                        "description": f"SQL error signature '{sig}' found with payload: {payload}"
                    })
                    break
        except Exception:
            pass
    return findings

def check_xss(url: str):
    findings = []
    payloads = [
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert(1)>",
        "'\"><script>alert(1)</script>"
    ]
    for payload in payloads:
        test_url = url + payload
        try:
            resp = requests.get(test_url, timeout=5, verify=False)
            if payload in resp.text:
                findings.append({
                    "type": "Cross-Site Scripting (XSS)",
                    "severity": "High",
                    "url": test_url,
                    "parameter": "URL parameter",
                    "description": f"Payload reflected in response: {payload[:40]}"
                })
        except Exception:
            pass
    return findings

def check_headers(url: str):
    findings = []
    try:
        resp = requests.get(url, timeout=5, verify=False)
        headers = resp.headers
        security_headers = {
            "X-Frame-Options": "Clickjacking protection missing",
            "X-Content-Type-Options": "MIME sniffing protection missing",
            "Content-Security-Policy": "CSP header missing — XSS risk",
            "Strict-Transport-Security": "HSTS missing — downgrade attack risk",
        }
        for header, desc in security_headers.items():
            if header not in headers:
                findings.append({
                    "type": "Missing Security Header",
                    "severity": "Medium",
                    "url": url,
                    "parameter": header,
                    "description": desc
                })
        # Check for server info disclosure
        if "Server" in headers:
            findings.append({
                "type": "Information Disclosure",
                "severity": "Low",
                "url": url,
                "parameter": "Server header",
                "description": f"Server version exposed: {headers['Server']}"
            })
    except Exception:
        pass
    return findings

def check_jwt(url: str):
    findings = []
    try:
        resp = requests.get(url, timeout=5, verify=False)
        cookies = resp.cookies
        for cookie in cookies:
            if cookie.name.lower() in ["token", "jwt", "auth", "access_token"]:
                findings.append({
                    "type": "JWT in Cookie",
                    "severity": "Medium",
                    "url": url,
                    "parameter": cookie.name,
                    "description": "JWT token found in cookie. Check for HttpOnly and Secure flags."
                })
            if not cookie.has_nonstandard_attr("HttpOnly"):
                findings.append({
                    "type": "Cookie Missing HttpOnly",
                    "severity": "Medium",
                    "url": url,
                    "parameter": cookie.name,
                    "description": "Cookie does not have HttpOnly flag — vulnerable to XSS theft."
                })
    except Exception:
        pass
    return findings

def ai_filter(findings):
    """Simple AI-style false positive reduction"""
    filtered = []
    for f in findings:
        # Low confidence heuristic: if description is vague, downgrade
        if f["severity"] == "Critical" and len(f["description"]) < 20:
            f["severity"] = "High"
            f["description"] += " [AI: confidence reduced — verify manually]"
        filtered.append(f)
    return filtered

def run_scan(scan_id: str, url: str):
    scan_results[scan_id]["status"] = "running"
    all_findings = []
    all_findings += check_headers(url)
    all_findings += check_sqli(url)
    all_findings += check_xss(url)
    all_findings += check_jwt(url)
    all_findings = ai_filter(all_findings)

    severity_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
    all_findings.sort(key=lambda x: severity_order.get(x["severity"], 4))

    scan_results[scan_id]["findings"] = all_findings
    scan_results[scan_id]["status"] = "complete"
    scan_results[scan_id]["total"] = len(all_findings)
    scan_results[scan_id]["summary"] = {
        "Critical": sum(1 for f in all_findings if f["severity"] == "Critical"),
        "High":     sum(1 for f in all_findings if f["severity"] == "High"),
        "Medium":   sum(1 for f in all_findings if f["severity"] == "Medium"),
        "Low":      sum(1 for f in all_findings if f["severity"] == "Low"),
    }

# ─── API ENDPOINTS ─────────────────────────────────────────────

@app.get("/")
def root():
    return {"message": "VulnShield AI is running ✅"}

@app.post("/scan")
def start_scan(req: ScanRequest, background_tasks: BackgroundTasks):
    scan_id = str(uuid.uuid4())
    scan_results[scan_id] = {
        "scan_id": scan_id,
        "url": req.url,
        "status": "queued",
        "findings": [],
        "total": 0,
        "summary": {}
    }
    background_tasks.add_task(run_scan, scan_id, req.url)
    return {"scan_id": scan_id, "message": "Scan started"}

@app.get("/results")
def get_all_results():
    return list(scan_results.values())

@app.get("/results/{scan_id}")
def get_result(scan_id: str):
    if scan_id not in scan_results:
        return {"error": "Scan not found"}
    return scan_results[scan_id]
