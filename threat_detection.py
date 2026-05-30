# ─── AI Threat Detection System ───────────────────────────
# SecureChat — Advanced Threat Detection Engine
# Detects: Spam, Brute Force, SQL Injection, XSS, Flooding

import re
import time
from datetime import datetime, timedelta
from collections import defaultdict

# ── Suspicious Keywords ──
SUSPICIOUS_KEYWORDS = [
    # SQL Injection
    "select", "insert", "update", "delete", "drop", "union", "exec",
    "execute", "xp_", "sp_", "cast(", "convert(", "char(", "nchar(",
    # XSS
    "<script", "javascript:", "onerror=", "onload=", "alert(", "document.cookie",
    "window.location", "eval(", "innerHTML", "onclick=",
    # Path Traversal
    "../", "..\\", "/etc/passwd", "c:\\windows",
    # Command Injection
    "; ls", "; cat", "| whoami", "& net user", "`id`",
]

SPAM_KEYWORDS = [
    "buy now", "click here", "free money", "win prize",
    "limited offer", "act now", "guaranteed", "no risk",
]

# ── Rate Limiting Storage ──
message_history = defaultdict(list)     # user_id -> [timestamps]
login_attempts = defaultdict(list)      # ip -> [timestamps]
threat_scores = defaultdict(int)        # user_id -> score
threat_events = []                      # Global threat log

# ── Threat Level ──
def get_threat_level(score):
    if score >= 80: return "CRITICAL", "#ff3c5a"
    if score >= 50: return "HIGH", "#ff6b35"
    if score >= 25: return "MEDIUM", "#ffb700"
    if score >= 10: return "LOW", "#58a6ff"
    return "SAFE", "#3fb950"

def log_threat(user_id, username, threat_type, detail, score, ip=None):
    level, color = get_threat_level(score)
    event = {
        "id": len(threat_events) + 1,
        "user_id": user_id,
        "username": username or "Unknown",
        "threat_type": threat_type,
        "detail": detail,
        "score": score,
        "level": level,
        "color": color,
        "ip": ip or "Unknown",
        "timestamp": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"),
        "blocked": score >= 50
    }
    threat_events.append(event)
    if len(threat_events) > 200:
        threat_events.pop(0)
    return event

# ── Message Threat Analysis ──
def analyze_message(user_id, username, message, ip=None):
    threats = []
    total_score = 0

    # 1. SQL Injection Detection
    msg_lower = message.lower()
    sql_hits = [kw for kw in SUSPICIOUS_KEYWORDS[:14] if kw in msg_lower]
    if sql_hits:
        score = min(90, len(sql_hits) * 30)
        threats.append({
            "type": "SQL_INJECTION_ATTEMPT",
            "detail": f"SQL keywords detected: {', '.join(sql_hits[:3])}",
            "score": score
        })
        total_score += score

    # 2. XSS Detection
    xss_hits = [kw for kw in SUSPICIOUS_KEYWORDS[14:24] if kw in msg_lower]
    if xss_hits:
        score = min(85, len(xss_hits) * 25)
        threats.append({
            "type": "XSS_ATTEMPT",
            "detail": f"XSS pattern detected: {', '.join(xss_hits[:3])}",
            "score": score
        })
        total_score += score

    # 3. Spam Detection
    spam_hits = [kw for kw in SPAM_KEYWORDS if kw in msg_lower]
    if spam_hits:
        score = min(40, len(spam_hits) * 15)
        threats.append({
            "type": "SPAM_DETECTED",
            "detail": f"Spam keywords: {', '.join(spam_hits[:3])}",
            "score": score
        })
        total_score += score

    # 4. Message Flooding Detection
    now = time.time()
    message_history[user_id].append(now)
    message_history[user_id] = [t for t in message_history[user_id] if now - t < 60]
    msg_count = len(message_history[user_id])

    if msg_count > 20:
        score = 80
        threats.append({
            "type": "MESSAGE_FLOODING",
            "detail": f"{msg_count} messages in last 60 seconds",
            "score": score
        })
        total_score += score
    elif msg_count > 10:
        score = 40
        threats.append({
            "type": "RAPID_MESSAGING",
            "detail": f"{msg_count} messages in last 60 seconds",
            "score": score
        })
        total_score += score

    # 5. Long message anomaly
    if len(message) > 2000:
        score = 20
        threats.append({
            "type": "ANOMALOUS_MESSAGE_LENGTH",
            "detail": f"Message length: {len(message)} chars",
            "score": score
        })
        total_score += score

    # Update threat score
    threat_scores[user_id] = min(100, threat_scores[user_id] + total_score)

    # Log if threat found
    logged_events = []
    for t in threats:
        event = log_threat(user_id, username, t["type"], t["detail"], t["score"], ip)
        logged_events.append(event)

    return {
        "safe": total_score == 0,
        "total_score": total_score,
        "threats": threats,
        "events": logged_events,
        "level": get_threat_level(total_score)[0],
        "blocked": total_score >= 50
    }

# ── Login Threat Analysis ──
def analyze_login(username, ip, success, failed_count=0):
    threats = []
    total_score = 0

    # Brute force detection
    now = time.time()
    login_attempts[ip].append(now)
    login_attempts[ip] = [t for t in login_attempts[ip] if now - t < 300]
    attempt_count = len(login_attempts[ip])

    if not success:
        if attempt_count > 10:
            score = 90
            threats.append({
                "type": "BRUTE_FORCE_ATTACK",
                "detail": f"{attempt_count} failed attempts from IP {ip} in 5 minutes",
                "score": score
            })
            total_score += score
        elif attempt_count > 5:
            score = 60
            threats.append({
                "type": "CREDENTIAL_STUFFING",
                "detail": f"{attempt_count} failed attempts from IP {ip}",
                "score": score
            })
            total_score += score
        elif failed_count >= 2:
            score = 30
            threats.append({
                "type": "MULTIPLE_FAILED_LOGINS",
                "detail": f"{failed_count} consecutive failures for {username}",
                "score": score
            })
            total_score += score

    logged_events = []
    for t in threats:
        event = log_threat(None, username, t["type"], t["detail"], t["score"], ip)
        logged_events.append(event)

    return {
        "safe": total_score == 0,
        "total_score": total_score,
        "threats": threats,
        "events": logged_events,
        "level": get_threat_level(total_score)[0],
        "blocked": total_score >= 80
    }

# ── IDS: Request Analysis ──
def analyze_request(path, method, user_agent, ip, body=None):
    threats = []
    total_score = 0

    # Path traversal
    if "../" in path or "..\\" in path:
        threats.append({"type": "PATH_TRAVERSAL", "detail": f"Path traversal: {path}", "score": 80})
        total_score += 80

    # Scanner detection
    scanners = ["sqlmap", "nikto", "nmap", "masscan", "zap", "burp", "dirbuster"]
    ua_lower = (user_agent or "").lower()
    for scanner in scanners:
        if scanner in ua_lower:
            threats.append({"type": "SECURITY_SCANNER", "detail": f"Scanner detected: {scanner}", "score": 70})
            total_score += 70
            break

    # Body analysis
    if body:
        body_lower = str(body).lower()
        sql_hits = [kw for kw in SUSPICIOUS_KEYWORDS[:14] if kw in body_lower]
        if sql_hits:
            threats.append({"type": "SQL_IN_REQUEST", "detail": f"SQL in body: {sql_hits[:2]}", "score": 85})
            total_score += 85
        xss_hits = [kw for kw in SUSPICIOUS_KEYWORDS[14:24] if kw in body_lower]
        if xss_hits:
            threats.append({"type": "XSS_IN_REQUEST", "detail": f"XSS in body: {xss_hits[:2]}", "score": 80})
            total_score += 80

    logged_events = []
    for t in threats:
        event = log_threat(None, f"IP:{ip}", t["type"], t["detail"], t["score"], ip)
        logged_events.append(event)

    return {
        "safe": total_score == 0,
        "total_score": total_score,
        "threats": threats,
        "events": logged_events,
        "blocked": total_score >= 50
    }

# ── Get Threat Stats ──
def get_threat_stats():
    total = len(threat_events)
    critical = sum(1 for e in threat_events if e["level"] == "CRITICAL")
    high = sum(1 for e in threat_events if e["level"] == "HIGH")
    medium = sum(1 for e in threat_events if e["level"] == "MEDIUM")
    blocked = sum(1 for e in threat_events if e["blocked"])
    types = defaultdict(int)
    for e in threat_events:
        types[e["threat_type"]] += 1
    top_threats = sorted(types.items(), key=lambda x: x[1], reverse=True)[:5]
    return {
        "total": total,
        "critical": critical,
        "high": high,
        "medium": medium,
        "blocked": blocked,
        "top_threats": [{"type": t, "count": c} for t, c in top_threats],
        "recent": list(reversed(threat_events[-10:]))
    }

def get_all_threats():
    return list(reversed(threat_events))