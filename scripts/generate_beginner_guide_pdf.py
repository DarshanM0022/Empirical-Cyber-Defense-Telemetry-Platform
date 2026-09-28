import os
import sys
import base64
import tempfile
import subprocess
from pathlib import Path

def encode_image_to_base64(img_path):
    if not os.path.exists(img_path):
        print(f"[!] Warning: Image not found at {img_path}")
        return ""
    with open(img_path, "rb") as f:
        encoded = base64.b64encode(f.read()).decode("utf-8")
        return f"data:image/png;base64,{encoded}"

def build_html_content(base_dir):
    screenshots_dir = os.path.join(base_dir, "docs", "assets", "screenshots")

    img_soc = encode_image_to_base64(os.path.join(screenshots_dir, "poc_soc_dashboard_full.png"))
    img_findings = encode_image_to_base64(os.path.join(screenshots_dir, "poc_findings_evidence.png"))
    img_siem = encode_image_to_base64(os.path.join(screenshots_dir, "poc_siem_pipeline.png"))
    img_incidents = encode_image_to_base64(os.path.join(screenshots_dir, "poc_incidents_war_room.png"))
    img_audit = encode_image_to_base64(os.path.join(screenshots_dir, "poc_tamper_audit.png"))
    img_report = encode_image_to_base64(os.path.join(screenshots_dir, "poc_audit_report.png"))
    img_api = encode_image_to_base64(os.path.join(screenshots_dir, "poc_api_docs.png"))

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>AegisX — The Beginner's Guide to Empirical Cyber Defense</title>
  <style>
    @page {{
      size: A4;
      margin: 18mm 16mm 18mm 16mm;
      @bottom-right {{
        content: counter(page);
      }}
    }}
    
    * {{
      box-sizing: border-box;
      -webkit-print-color-adjust: exact;
      print-color-adjust: exact;
    }}
    
    body {{
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
      color: #1e293b;
      background-color: #ffffff;
      line-height: 1.55;
      font-size: 10.5pt;
      margin: 0;
      padding: 0;
    }}
    
    h1, h2, h3, h4 {{
      color: #0f172a;
      font-weight: 700;
      line-height: 1.25;
      margin-top: 1.2em;
      margin-bottom: 0.4em;
    }}
    
    h1 {{ font-size: 20pt; border-bottom: 2px solid #0284c7; padding-bottom: 6px; }}
    h2 {{ font-size: 15pt; color: #0369a1; border-bottom: 1px solid #e2e8f0; padding-bottom: 4px; }}
    h3 {{ font-size: 12.5pt; color: #0f172a; }}
    h4 {{ font-size: 11pt; color: #334155; }}
    
    p {{
      margin-top: 0;
      margin-bottom: 0.8em;
    }}
    
    .page-break {{
      page-break-before: always;
      break-before: page;
    }}
    
    .avoid-break {{
      page-break-inside: avoid;
      break-inside: avoid;
    }}
    
    /* Cover Page */
    .cover {{
      text-align: center;
      padding-top: 40px;
      padding-bottom: 40px;
      height: 90vh;
      display: flex;
      flex-direction: column;
      justify-content: center;
      align-items: center;
    }}
    
    .cover-badge {{
      display: inline-block;
      background: #e0f2fe;
      color: #0369a1;
      padding: 6px 14px;
      border-radius: 9999px;
      font-size: 9pt;
      font-weight: 700;
      letter-spacing: 1px;
      text-transform: uppercase;
      margin-bottom: 20px;
    }}
    
    .cover-title {{
      font-size: 28pt;
      color: #0f172a;
      margin: 0 0 10px 0;
      font-weight: 800;
      border: none;
      padding: 0;
      line-height: 1.15;
    }}
    
    .cover-subtitle {{
      font-size: 15pt;
      color: #0284c7;
      font-weight: 600;
      margin-bottom: 25px;
    }}
    
    .cover-desc {{
      font-size: 11.5pt;
      color: #475569;
      max-width: 580px;
      line-height: 1.6;
      margin-bottom: 40px;
    }}
    
    .cover-meta {{
      background: #f8fafc;
      border: 1px solid #e2e8f0;
      border-radius: 12px;
      padding: 16px 24px;
      width: 85%;
      text-align: left;
      font-size: 9.5pt;
      color: #334155;
    }}
    
    .cover-meta table {{
      width: 100%;
      border-collapse: collapse;
    }}
    
    .cover-meta td {{
      padding: 5px 8px;
    }}
    
    .cover-meta td.label {{
      font-weight: 700;
      color: #64748b;
      width: 32%;
    }}
    
    /* Callout Boxes */
    .callout {{
      border-radius: 8px;
      padding: 12px 16px;
      margin: 14px 0;
      font-size: 10pt;
      page-break-inside: avoid;
    }}
    
    .callout-analogy {{
      background-color: #f0fdf4;
      border-left: 4px solid #16a34a;
      color: #14532d;
    }}
    
    .callout-analogy h4 {{
      color: #15803d;
      margin-top: 0;
      margin-bottom: 4px;
      font-size: 10.5pt;
    }}
    
    .callout-problem {{
      background-color: #fef2f2;
      border-left: 4px solid #dc2626;
      color: #7f1d1d;
    }}
    
    .callout-problem h4 {{
      color: #b91c1c;
      margin-top: 0;
      margin-bottom: 4px;
      font-size: 10.5pt;
    }}
    
    .callout-concept {{
      background-color: #eff6ff;
      border-left: 4px solid #2563eb;
      color: #1e3a8a;
    }}
    
    .callout-concept h4 {{
      color: #1d4ed8;
      margin-top: 0;
      margin-bottom: 4px;
      font-size: 10.5pt;
    }}
    
    /* Tables */
    table.data-table {{
      width: 100%;
      border-collapse: collapse;
      margin: 12px 0;
      font-size: 9.5pt;
      page-break-inside: avoid;
    }}
    
    table.data-table th {{
      background-color: #f1f5f9;
      color: #0f172a;
      font-weight: 700;
      text-align: left;
      padding: 8px 10px;
      border: 1px solid #cbd5e1;
    }}
    
    table.data-table td {{
      padding: 7px 10px;
      border: 1px solid #e2e8f0;
      vertical-align: top;
    }}
    
    table.data-table tr:nth-child(even) {{
      background-color: #f8fafc;
    }}
    
    /* Screenshot card */
    .screenshot-card {{
      background: #ffffff;
      border: 1px solid #cbd5e1;
      border-radius: 8px;
      padding: 8px;
      margin: 14px 0;
      box-shadow: 0 1px 3px rgba(0,0,0,0.05);
      page-break-inside: avoid;
    }}
    
    .screenshot-card img {{
      width: 100%;
      height: auto;
      border-radius: 4px;
      border: 1px solid #e2e8f0;
      display: block;
    }}
    
    .screenshot-caption {{
      font-size: 8.5pt;
      color: #475569;
      margin-top: 6px;
      text-align: center;
      font-style: italic;
    }}
    
    /* Badges */
    .badge {{
      display: inline-block;
      padding: 2px 8px;
      border-radius: 4px;
      font-size: 8pt;
      font-weight: 700;
    }}
    .badge-green {{ background: #dcfce7; color: #166534; }}
    .badge-red {{ background: #fee2e2; color: #991b1b; }}
    .badge-blue {{ background: #e0f2fe; color: #075985; }}
    .badge-yellow {{ background: #fef9c3; color: #854d0e; }}
    
    code {{
      font-family: "Consolas", "Courier New", monospace;
      font-size: 9pt;
      background: #f1f5f9;
      color: #0f172a;
      padding: 2px 4px;
      border-radius: 4px;
      border: 1px solid #e2e8f0;
    }}
    
    pre {{
      font-family: "Consolas", "Courier New", monospace;
      font-size: 8.5pt;
      background: #0f172a;
      color: #f8fafc;
      padding: 10px 12px;
      border-radius: 6px;
      overflow-x: auto;
      margin: 10px 0;
      page-break-inside: avoid;
    }}
    
    ul, ol {{
      margin-top: 0;
      margin-bottom: 0.8em;
      padding-left: 20px;
    }}
    
    li {{
      margin-bottom: 0.35em;
    }}
    
    .qa-box {{
      background: #f8fafc;
      border-radius: 8px;
      border: 1px solid #e2e8f0;
      padding: 12px 16px;
      margin: 12px 0;
      page-break-inside: avoid;
    }}
    
    .qa-question {{
      font-weight: 700;
      color: #0284c7;
      font-size: 10.5pt;
      margin-bottom: 6px;
    }}
    
    .qa-answer {{
      color: #334155;
      font-size: 9.5pt;
      margin: 0;
    }}
  </style>
</head>
<body>

  <!-- COVER PAGE -->
  <div class="cover">
    <div class="cover-badge">Enterprise Cybersecurity Blueprint & Learning Guide</div>
    <div class="cover-title">Empirical Cyber Defense &<br>Telemetry Platform</div>
    <div class="cover-subtitle">AegisX: The Beginner-Friendly Guide to Verifiable Cyber Security</div>
    <div class="cover-desc">
      How to understand, explain, and present next-generation cyber defense, real-time SIEM log monitoring, non-destructive vulnerability auditing, and cryptographic proof — without confusing jargon or fake alerts.
    </div>
    
    <div class="cover-meta">
      <table>
        <tr>
          <td class="label">Project Name:</td>
          <td><strong>AegisX (Empirical Cyber Defense & Telemetry Platform)</strong></td>
        </tr>
        <tr>
          <td class="label">Primary Standard:</td>
          <td><span class="badge badge-green">Zero Fabricated Events</span> (100% Real Evidence & Cryptographic Hashes)</td>
        </tr>
        <tr>
          <td class="label">Author / Creator:</td>
          <td><strong>Darshan M</strong> (GitHub: <a href="https://github.com/DarshanM0022/Empirical-Cyber-Defense-Telemetry-Platform.git" style="color:#0284c7; text-decoration:none;">DarshanM0022</a>)</td>
        </tr>
        <tr>
          <td class="label">Core Architecture:</td>
          <td>FastAPI, SQLite/PostgreSQL, Non-Destructive Scanner, SIEM Telemetry, SHA-256 Digest Engine</td>
        </tr>
        <tr>
          <td class="label">Target Audience:</td>
          <td>Cybersecurity Beginners, Students, Junior SOC Analysts, Recruiters, and Technical Evaluators</td>
        </tr>
      </table>
    </div>
  </div>

  <!-- TABLE OF CONTENTS & INTRODUCTION -->
  <div class="page-break"></div>
  <h1>Executive Summary & Quick Navigation</h1>
  <p>
    Welcome! If you are new to cybersecurity, you might find the field intimidating: acronyms like <em>SIEM, SOC, OWASP, CVSS, MITRE ATT&CK, HSTS, CSP, and SHA-256</em> are thrown around constantly.
  </p>
  <p>
    <strong>AegisX was designed to solve a huge problem in cybersecurity today:</strong> Most security tools pretend to find things or produce hundreds of fake alarms ("alert fatigue"). When a boss asks: <em>"Can you prove this vulnerability actually exists?"</em>, the scanner usually cannot show proof.
  </p>
  <p>
    <strong>AegisX operates on one golden rule: Zero Fabricated Events.</strong> Every single alert, vulnerability, and detection is backed by actual network wire receipts and cryptographic math that anyone can verify.
  </p>

  <div class="callout callout-concept">
    <h4>What You Will Learn in This Document:</h4>
    <ol>
      <li><strong>Chapter 1: The Big Picture</strong> — What does this platform actually do, explained using simple real-world analogies?</li>
      <li><strong>Chapter 2: The 4 Core Pillars</strong> — How the Authorization Barrier, Safe Scanner, SIEM Engine, and Risk Calculator work.</li>
      <li><strong>Chapter 3: Visual Tour of the Platform</strong> — Real screenshots from our live running server with clear explanations of every button and graph.</li>
      <li><strong>Chapter 4: Real Attack Scenarios</strong> — How AegisX detects brute force password guessing, credential spraying, and weird logins.</li>
      <li><strong>Chapter 5: Cryptographic Proof (SHA-256)</strong> — Why our evidence is 100% tamper-proof (explained like a digital wax seal).</li>
      <li><strong>Chapter 6: Presentation & Interview Master Guide</strong> — The 30-second elevator pitch, top questions beginners ask, and a simple glossary.</li>
      <li><strong>Chapter 7: How to Run It in 4 Steps</strong> — Quick terminal commands to test it yourself.</li>
    </ol>
  </div>

  <hr style="border: none; border-top: 1px solid #e2e8f0; margin: 24px 0;">

  <!-- CHAPTER 1 -->
  <h1>Chapter 1: The Big Picture — What is AegisX?</h1>
  
  <h3>The Real-World Analogy: The Home Security System & The Honest Mechanic</h3>
  <p>
    Imagine you own a modern house. To keep it safe, you need two things:
  </p>
  <ul>
    <li><strong>A Regular Physical Inspection:</strong> A professional inspector checks if the front door is locked, if the windows have safety latches, and if the alarm batteries are full. But the inspector <em>does not kick the door down</em> to test it.</li>
    <li><strong>A 24/7 Security Camera & Alarm System:</strong> Sensors on your doors that alert you if someone is trying 20 different keys on your doorknob at 3:00 AM.</li>
  </ul>
  <p>
    Now imagine your car mechanic tells you: <em>"Your brakes are completely broken! That will be $2,000."</em> You ask to see the broken brake pads, and they reply: <em>"Trust me, our proprietary AI software thinks they are broken."</em> You would immediately walk away! You want to <strong>see the actual broken parts</strong>.
  </p>

  <div class="callout callout-problem">
    <h4>The Big Problem in Cybersecurity Today</h4>
    <p>
      Traditional cybersecurity tools act like that untrustworthy mechanic. They run speculative tests, produce 500 pages of warning badges, and cause <strong>Alert Fatigue</strong> — security teams get so overwhelmed by false alarms that they ignore real hackers. Even worse, many tools scan random websites on the internet without authorization, which is illegal.
    </p>
  </div>

  <div class="callout callout-analogy">
    <h4>The AegisX Solution: "Zero Fabricated Events"</h4>
    <p>
      AegisX unifies two worlds: <strong>Safe Vulnerability Auditing</strong> (checking the locks) and <strong>Real-Time SIEM Telemetry</strong> (monitoring the security cameras). But every single finding includes a <strong>digital receipt</strong>: the exact network wire capture and a mathematical SHA-256 fingerprint. If AegisX says a door is unlocked, it shows you the exact photo and keyhole measurement.
    </p>
  </div>

  <table class="data-table">
    <thead>
      <tr>
        <th style="width: 25%;">Feature</th>
        <th style="width: 37%;">Typical Vulnerability Scanners</th>
        <th style="width: 38%;">AegisX Platform</th>
      </tr>
    </thead>
    <tbody>
      <tr>
        <td><strong>Authorization</strong></td>
        <td>Will blindly scan any IP you enter, risking legal liability.</td>
        <td><strong>Strict Barrier:</strong> 0 packets sent unless a verified authorization contract exists.</td>
      </tr>
      <tr>
        <td><strong>Proof of Findings</strong></td>
        <td>Theoretical descriptions ("Vulnerability X might exist").</td>
        <td><strong>Empirical Proof:</strong> Preserves exact raw HTTP response headers and status codes.</td>
      </tr>
      <tr>
        <td><strong>Evidence Integrity</strong></td>
        <td>Stored as plain database text; anyone can edit or delete it.</td>
        <td><strong>Cryptographic SHA-256:</strong> Canonical JSON hashing guarantees evidence is tamper-evident.</td>
      </tr>
      <tr>
        <td><strong>Threat Monitoring</strong></td>
        <td>Disconnected from scanner; separate expensive tools needed.</td>
        <td><strong>Unified SIEM:</strong> Correlates live authentication logs with scan findings in real time.</td>
      </tr>
      <tr>
        <td><strong>Risk Scoring</strong></td>
        <td>Proprietary "magic AI number" with zero explanation.</td>
        <td><strong>Transparent Math:</strong> Explicit point deltas (+10 baseline, +8 medium header, etc.).</td>
      </tr>
    </tbody>
  </table>

  <!-- CHAPTER 2 -->
  <div class="page-break"></div>
  <h1>Chapter 2: The 4 Core Pillars Made Super Simple</h1>

  <h3>Pillar 1: The Mandatory Authorization Barrier</h3>
  <p>
    <strong>Analogy:</strong> A security guard standing at the gate of a private company. If a stranger asks to test the locks, the guard says: <em>"Show me your signed authorization badge."</em> If they don't have one, the guard doesn't even let them step onto the grass.
  </p>
  <p>
    In AegisX, before the scanner sends a single network packet (TCP SYN or HTTP request), it checks the database for an active, verified authorization record. If the asset is unauthorized or authorization is pending, the scan is immediately aborted with status <code>rejected_unauthorized</code>. <strong>Exactly 0 network packets are sent.</strong>
  </p>

  <h3>Pillar 2: Safe, Non-Destructive Vulnerability Auditing</h3>
  <p>
    <strong>Analogy:</strong> A doctor checking your reflexes with a soft rubber mallet rather than taking a sledgehammer to your knee.
  </p>
  <p>
    Many aggressive scanners send millions of malformed packets or malicious payloads that crash production websites. AegisX performs <strong>non-destructive audits aligned with OWASP standards</strong>:
  </p>
  <ul>
    <li><strong>Security Headers Check:</strong> Checks if the website includes protective headers like HSTS (forces encrypted HTTPS), CSP (prevents hackers from running malicious scripts), and X-Frame-Options (prevents clickjacking where a hacker puts an invisible layer over a button).</li>
    <li><strong>TLS/SSL Certificate Chain:</strong> Checks if the website's encryption certificate is valid, not expired, and issued by a trusted authority.</li>
    <li><strong>Safe Method Probes:</strong> Sends standard HTTP GET and HEAD requests that never corrupt or delete database records.</li>
  </ul>

  <h3>Pillar 3: Real-Time SIEM Telemetry & Threat Detections</h3>
  <p>
    <strong>Analogy:</strong> The building's central security room where all sensors feed into one dashboard.
  </p>
  <p>
    <strong>SIEM</strong> stands for <em>Security Information and Event Management</em>. In plain English, whenever an employee logs into a website, fails a password, or connects from a new laptop, a message called an <strong>Event</strong> is sent to the SIEM.
  </p>
  <p>
    AegisX normalizes all events into the industry-standard <strong>Elastic Common Schema (ECS)</strong>. Then, it evaluates <strong>Deterministic Detection Rules</strong>. Instead of "guessing", the rules are crystal-clear math:
  </p>
  <ul>
    <li><em>Rule: Brute Force Authentication</em> $\rightarrow$ If 5 or more failed logins occur for the same username within 10 minutes, raise a HIGH severity alert!</li>
    <li><em>Rule: Credential Spraying</em> $\rightarrow$ If 1 IP address attacks 3 or more different usernames within 15 minutes, raise a HIGH severity alert!</li>
    <li><em>Rule: Suspicious Device Login</em> $\rightarrow$ If a user logs in from a brand-new device immediately after several password failures, raise an alert!</li>
  </ul>

  <h3>Pillar 4: Transparent Mathematical Risk Scoring</h3>
  <p>
    <strong>Analogy:</strong> An honest credit score report. You can see: <em>"+20 points for paying your credit card on time, -15 points for a late utility bill."</em> You know exactly why your score is 720.
  </p>
  <p>
    AegisX calculates risk using a transparent equation where every point is documented:
  </p>
  <pre>Risk Score = Baseline (10) + Exposure Factors + Finding Penalties + Incident Penalties - Compensating Controls</pre>
  <p>
    If an asset has a score of <strong>80 / 100 (CRITICAL)</strong>, the dashboard displays the exact line-item breakdown:
  </p>
  <ul>
    <li><code>+10</code> Baseline operational score</li>
    <li><code>+10</code> Production environment exposure</li>
    <li><code>+10</code> High business criticality</li>
    <li><code>+24</code> Three Medium-severity missing headers (3 &times; 8 points)</li>
    <li><code>+6</code> Two Low-severity configuration advisories (2 &times; 3 points)</li>
    <li><code>+20</code> Active, unresolved security incident</li>
  </ul>
  <p>
    When the security analyst resolves the incident, the <code>+20</code> points are removed, and the risk score automatically drops to <strong>60 / 100 (MEDIUM)</strong>!
  </p>

  <!-- CHAPTER 3 -->
  <div class="page-break"></div>
  <h1>Chapter 3: Tour of the Platform (Real Platform Captures)</h1>
  <p>
    All screenshots below were taken directly from our live running platform. No mockups or AI-generated images were used.
  </p>

  <div class="screenshot-card">
    <img src="{img_soc}" alt="SOC Command Center">
    <div class="screenshot-caption">Figure 1: The AegisX SOC Command Center Dashboard showing the live Posture Arc Gauge, active HUD metrics, and streaming telemetry.</div>
  </div>

  <p><strong>What to look for on this screen:</strong></p>
  <ul>
    <li><strong>The Posture Gauge (top-left):</strong> Displays the real-time security posture score (e.g. 60/100 Medium). As vulnerabilities are fixed or attacks occur, this needle updates dynamically.</li>
    <li><strong>Active Threat HUD Counters:</strong> Shows total monitored assets (1), total authentication attempts (19), failed logins (17), detections triggered (4), and active incidents (1).</li>
    <li><strong>Live Telemetry Stream (bottom):</strong> Displays every single login attempt streaming in live, color-coded by success (green) or failure (red).</li>
  </ul>

  <div class="screenshot-card">
    <img src="{img_findings}" alt="Verifiable Findings">
    <div class="screenshot-caption">Figure 2: Verifiable Security Findings & Evidence Ledger. Every finding displays its CVSS severity, category, and unique SHA-256 evidence digest.</div>
  </div>

  <p><strong>What to look for on this screen:</strong></p>
  <ul>
    <li><strong>Finding Title & Severity:</strong> Shows missing headers like <code>Missing HSTS</code> (Medium), <code>Missing Content-Security-Policy</code> (Medium), and <code>Missing X-Content-Type-Options</code> (Low).</li>
    <li><strong>Cryptographic Evidence SHA-256:</strong> Look at the rightmost column: <code>aca4dd263ff0f248...</code>. This is the SHA-256 hash of the exact network packet headers observed by the scanner. Anyone can re-hash the data to verify it is authentic.</li>
  </ul>

  <div class="page-break"></div>
  <div class="screenshot-card">
    <img src="{img_siem}" alt="SIEM Pipeline">
    <div class="screenshot-caption">Figure 3: SIEM Telemetry Ingestion & Deterministic Detection Engine. Ingests normalized authentication events and triggers high-fidelity alerts.</div>
  </div>

  <p><strong>What to look for on this screen:</strong></p>
  <ul>
    <li><strong>Live Detection Cards:</strong> Shows active triggered rules like <code>brute_force_authentication</code> (T1110.001) and <code>ip_credential_spray</code> (T1110.003) with timestamp and affected account names.</li>
    <li><strong>MITRE ATT&CK Mapping:</strong> Every detection maps to an official MITRE ATT&CK technique code so enterprise SOC teams know the exact adversary tactic.</li>
  </ul>

  <div class="screenshot-card">
    <img src="{img_incidents}" alt="Incident War Room">
    <div class="screenshot-caption">Figure 4: The Incident Response War Room. Correlates multiple alerts into single actionable tickets and tracks analyst investigation progress.</div>
  </div>

  <p><strong>What to look for on this screen:</strong></p>
  <ul>
    <li><strong>Status Progression:</strong> Incidents move cleanly through stages: <code>OPEN</code> &rarr; <code>INVESTIGATING</code> &rarr; <code>RESOLVED</code>.</li>
    <li><strong>Actionable Remediation Playbook:</strong> Instead of vague advice, it gives analysts clear steps: <em>"1. Block IP 198.51.100.99 at perimeter WAF. 2. Invalidate sessions for targeted service accounts."</em></li>
  </ul>

  <div class="page-break"></div>
  <div class="screenshot-card">
    <img src="{img_audit}" alt="Tamper-Evident Audit Ledger">
    <div class="screenshot-caption">Figure 5: The Tamper-Evident Cryptographic Audit Ledger. An immutable log of every administrative authorization, scan, and incident update.</div>
  </div>

  <div class="screenshot-card">
    <img src="{img_report}" alt="Executive Audit Report">
    <div class="screenshot-caption">Figure 6: Verifiable Executive Audit Report view formatted for CISOs, regulators, and compliance officers.</div>
  </div>

  <div class="screenshot-card">
    <img src="{img_api}" alt="Interactive REST API Documentation">
    <div class="screenshot-caption">Figure 7: Interactive OpenAPI / Swagger REST API specification available at <code>/docs</code> for developer automation.</div>
  </div>

  <!-- CHAPTER 4 -->
  <div class="page-break"></div>
  <h1>Chapter 4: Real Attack Scenarios & How AegisX Catches Them</h1>

  <h3>Scenario 1: The Brute Force Password Guessing Attack</h3>
  <div class="callout callout-analogy">
    <h4>Analogy: The Burglar Trying 50 Keys on Your Front Door</h4>
    <p>
      A burglar stands at your front door with a ring of 50 stolen keys. They try key #1 (fail), key #2 (fail), key #3 (fail), key #4 (fail)... On the 5th attempt, the alarm sounds!
    </p>
  </div>
  <p>
    <strong>How AegisX catches it:</strong>
  </p>
  <ol>
    <li>Attacker targets user <code>finance_director_01</code> from IP <code>203.0.113.45</code>.</li>
    <li>The web server sends failed login events to AegisX.</li>
    <li>Attempts 1, 2, 3, and 4 are logged, but no alarm is triggered yet (to avoid false alarms from a typo).</li>
    <li>On the <strong>5th failed login</strong> within 10 minutes, rule <code>brute_force_authentication</code> fires!</li>
    <li>A HIGH-severity detection is created and mapped to MITRE ATT&CK <strong>T1110.001</strong>.</li>
  </ol>

  <h3>Scenario 2: The Sneaky Credential Spraying Attack</h3>
  <div class="callout callout-analogy">
    <h4>Analogy: The Burglar Walking Down the Street Trying 1 Key on Every House</h4>
    <p>
      Smart burglars know that trying 10 keys on one door triggers the alarm. So instead, they take 1 common password (like <code>Spring2026!</code>) and try it on House A, then House B, then House C.
    </p>
  </div>
  <p>
    <strong>How AegisX catches it:</strong>
  </p>
  <ol>
    <li>Attacker from IP <code>198.51.100.99</code> tries to log in once as <code>db_admin_root</code> (fail).</li>
    <li>Then they try once as <code>billing_service_svc</code> (fail).</li>
    <li>Then they try once as <code>hr_manager_lead</code> (fail).</li>
    <li>No individual account reached 5 failures. But AegisX tracks <strong>unique accounts targeted by the same IP address</strong>!</li>
    <li>As soon as the 3rd distinct account fails, rule <code>ip_credential_spray</code> fires with HIGH severity (MITRE ATT&CK <strong>T1110.003</strong>).</li>
  </ol>

  <h3>Scenario 3: The Full Incident Lifecycle & Posture Recalculation</h3>
  <p>
    What happens after an attack is detected? In AegisX, detections automatically group into a <strong>Security Incident</strong>:
  </p>
  <ol>
    <li><strong>Incident Opened:</strong> Status = <code>OPEN</code>. Risk score jumps by <code>+20</code> points to <strong>80/100 (CRITICAL)</strong>.</li>
    <li><strong>Investigation:</strong> Analyst updates status to <code>INVESTIGATING</code> and deploys WAF firewall blocks.</li>
    <li><strong>Resolution:</strong> The attacker's IP is blocked and compromised passwords are reset. Analyst marks status = <code>RESOLVED</code>.</li>
    <li><strong>Recalculation:</strong> AegisX mathematically recalculates the asset score: the $+20$ penalty vanishes, and the score drops back to <strong>60/100 (MEDIUM)</strong>!</li>
  </ol>

  <!-- CHAPTER 5 -->
  <div class="page-break"></div>
  <h1>Chapter 5: The Cryptographic Magic (SHA-256 Made Easy)</h1>

  <h3>What is a Cryptographic Hash? (The Digital Blender)</h3>
  <p>
    Imagine you put a banana, an apple, and three strawberries into a blender. It makes a very specific pink smoothie. If you change even half a strawberry, the color and taste are completely different. And you can never turn the smoothie back into an apple!
  </p>
  <p>
    <strong>SHA-256</strong> is a mathematical blender. You give it any piece of text (like website headers), and it produces a unique 64-character string called a <strong>digest</strong>.
  </p>
  <ul>
    <li>The same input ALWAYS produces the exact same hash.</li>
    <li>If even one letter or space changes, the entire hash changes completely (the "avalanche effect").</li>
    <li>It is mathematically impossible to reverse-engineer the original text from the hash.</li>
  </ul>

  <div class="callout callout-concept">
    <h4>How AegisX Uses SHA-256 for Tamper-Proof Evidence</h4>
    <p>
      When AegisX checks a website and finds that the <code>X-Content-Type-Options</code> header is missing, it takes the exact response received over the wire:
    </p>
    <pre>{{
  "timestamp": "2026-09-28T18:02:44.200Z",
  "url": "http://127.0.0.1:8000/",
  "status": 200,
  "headers": {{
    "server": "uvicorn",
    "content-type": "text/html; charset=utf-8",
    "content-length": "41248"
  }}
}}</pre>
    <p>
      It sorts the keys canonically and runs SHA-256. The resulting hash is:
      <br>
      <code>aca4dd263ff0f2489c629f121d50c6bf23fa1544ff8bc85923c8a9f3b14d451a</code>
    </p>
    <p>
      This hash is stored in the database. If a rogue administrator tries to secretly edit the headers in the database, the hash won't match anymore! Any auditor can run 3 lines of Python to prove the evidence is 100% genuine.
    </p>
  </div>

  <!-- CHAPTER 6 -->
  <div class="page-break"></div>
  <h1>Chapter 6: Presentation & Interview Master Guide</h1>
  <p>
    Use these talking points when presenting this project to a teacher, recruiter, or colleague!
  </p>

  <h3>The 30-Second Elevator Pitch</h3>
  <div class="callout callout-analogy">
    <p style="font-size: 10.5pt; line-height: 1.6; margin: 0;">
      <em>"I built <strong>AegisX</strong>, an enterprise-grade defensive cybersecurity platform engineered on one foundational standard: <strong>Zero Fabricated Events</strong>. Unlike traditional scanners that guess or create false alarms, AegisX unifies non-destructive, OWASP-aligned vulnerability auditing with real-time SIEM log monitoring. Every vulnerability is cryptographically bound to raw network wire captures with SHA-256 digests, and the scanner enforces a mandatory authorization barrier so unauthorized systems are never scanned."</em>
    </p>
  </div>

  <h3>Top 6 Questions Beginners & Interviewers Ask</h3>

  <div class="qa-box">
    <div class="qa-question">1. Is this a hacking tool or a defense tool?</div>
    <div class="qa-answer">
      It is strictly a <strong>defensive cyber security platform</strong>. It is built for Security Operations Centers (SOCs) and compliance auditors. Its scans are non-destructive (safe) and its SIEM monitors real-time logs to stop hackers.
    </div>
  </div>

  <div class="qa-box">
    <div class="qa-question">2. Why can't we just use existing scanners like Nmap or Nessus?</div>
    <div class="qa-answer">
      Existing scanners scan without verifying permission, which can cause legal issues or crash servers. Furthermore, their reports are often plain text summaries that lack cryptographic proof. AegisX enforces authorization barriers, produces tamper-proof evidence, and connects findings directly to a live SIEM.
    </div>
  </div>

  <div class="qa-box">
    <div class="qa-question">3. What is an HTTP Security Header and why does it matter?</div>
    <div class="qa-answer">
      Think of HTTP security headers as built-in safety rules sent by a website to your browser. For example, <strong>HSTS</strong> tells your browser <em>"Only connect via encrypted HTTPS, never plain HTTP"</em>. <strong>CSP</strong> tells your browser <em>"Only run scripts from trusted sources"</em>. Missing these headers allows hackers to steal cookies or inject malicious scripts.
    </div>
  </div>

  <div class="qa-box">
    <div class="qa-question">4. What is the difference between an Event, a Detection, and an Incident?</div>
    <div class="qa-answer">
      <ul>
        <li><strong>Event:</strong> Any normal activity that happens on a system (e.g. <em>"User Alice logged in from IP 1.2.3.4"</em>).</li>
        <li><strong>Detection:</strong> When events match a threat rule (e.g. <em>"5 failed logins occurred for Alice in 5 minutes"</em>).</li>
        <li><strong>Incident:</strong> A confirmed security problem that requires human analysts to investigate and fix (e.g. <em>"Credential spray attack against 3 executive accounts"</em>).</li>
      </ul>
    </div>
  </div>

  <div class="qa-box">
    <div class="qa-question">5. Why don't you use AI to detect attacks?</div>
    <div class="qa-answer">
      AI models in cybersecurity are prone to "hallucinations" (inventing things that aren't there) and false positives. In high-stakes enterprise defense, you need <strong>deterministic, explainable rules</strong> where every alert can be audited and proven in a court of law.
    </div>
  </div>

  <div class="qa-box">
    <div class="qa-question">6. What is MITRE ATT&CK?</div>
    <div class="qa-answer">
      MITRE ATT&CK is a globally recognized encyclopedia of real-world hacker tactics and techniques. By tagging our detections with codes like <code>T1110.001</code> (Password Guessing) and <code>T1110.003</code> (Credential Spraying), any security team in the world immediately knows the adversary's playbook.
    </div>
  </div>

  <!-- GLOSSARY & REPRODUCTION -->
  <div class="page-break"></div>
  <h1>Chapter 7: Cybersecurity Glossary & Quickstart</h1>

  <h3>Essential Terms Explained for Beginners</h3>
  <table class="data-table">
    <thead>
      <tr>
        <th style="width: 25%;">Term</th>
        <th style="width: 75%;">Plain English Meaning</th>
      </tr>
    </thead>
    <tbody>
      <tr>
        <td><strong>SOC (Security Operations Center)</strong></td>
        <td>The command room where cybersecurity analysts monitor computers and defend against live attacks.</td>
      </tr>
      <tr>
        <td><strong>SIEM</strong></td>
        <td><em>Security Information & Event Management</em>. A central software hub that collects log files from everywhere to spot attacks.</td>
      </tr>
      <tr>
        <td><strong>ECS (Elastic Common Schema)</strong></td>
        <td>A standard format for writing log files so different computers (Windows, Linux, firewalls) speak the same language.</td>
      </tr>
      <tr>
        <td><strong>Vulnerability</strong></td>
        <td>A flaw, bug, or missing security lock in software that hackers could exploit.</td>
      </tr>
      <tr>
        <td><strong>Non-Destructive Scanning</strong></td>
        <td>Testing a system gently without breaking it, overloading it, or erasing any customer data.</td>
      </tr>
      <tr>
        <td><strong>SHA-256</strong></td>
        <td>A mathematical hashing algorithm that generates a 64-character digital fingerprint. Used to prove data hasn't been modified.</td>
      </tr>
      <tr>
        <td><strong>CVSS</strong></td>
        <td><em>Common Vulnerability Scoring System</em>. A standard scale from 0.0 to 10.0 measuring how dangerous a security flaw is.</td>
      </tr>
      <tr>
        <td><strong>WAF (Web Application Firewall)</strong></td>
        <td>A digital security shield that inspects web traffic and blocks malicious IP addresses before they reach the server.</td>
      </tr>
    </tbody>
  </table>

  <h3>How to Run and Test This Project Locally</h3>
  <p>
    Anyone with Python 3.10+ can download and run this platform in less than 2 minutes:
  </p>
  
  <pre># 1. Clone the repository
git clone https://github.com/DarshanM0022/Empirical-Cyber-Defense-Telemetry-Platform.git
cd Empirical-Cyber-Defense-Telemetry-Platform

# 2. Install dependencies
python -m pip install -r requirements.txt

# 3. Launch the platform server
python -m uvicorn backend.app.main:app --host 127.0.0.1 --port 8000

# 4. In a second terminal, run the automated attack simulation & empirical scan:
python scripts/populate_poc_data.py
python scripts/run_advanced_poc.py

# 5. Open your browser:
# SOC Dashboard : http://127.0.0.1:8000/
# API Docs      : http://127.0.0.1:8000/docs</pre>

  <div style="margin-top: 30px; text-align: center; color: #64748b; font-size: 8.5pt; border-top: 1px solid #e2e8f0; padding-top: 12px;">
    Empirical Cyber Defense & Telemetry Platform (AegisX) &bull; Built by Darshan M &bull; Verified 2026
  </div>

</body>
</html>
"""
    return html

def main():
    print("=" * 70)
    print("AegisX — Beginner's Guide PDF Generation Engine")
    print("=" * 70)

    base_dir = r"C:\Users\darsh\AegisX"
    html_file = os.path.join(base_dir, "docs", "AegisX_Beginners_Guide.html")
    pdf_file = os.path.join(base_dir, "docs", "AegisX_Beginners_Guide_Empirical_Cyber_Defense.pdf")

    print("[*] Generating comprehensive HTML guide with embedded base64 screenshots...")
    html_content = build_html_content(base_dir)

    with open(html_file, "w", encoding="utf-8") as f:
        f.write(html_content)
    print(f"[OK] HTML Guide created: {html_file} ({len(html_content)} bytes)")

    print("[*] Launching headless Microsoft Edge to render pixel-perfect PDF...")
    edge_path = r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"
    temp_dir = tempfile.mkdtemp()

    cmd = [
        edge_path,
        "--headless",
        "--no-sandbox",
        "--disable-gpu",
        f"--user-data-dir={temp_dir}",
        f"--print-to-pdf={pdf_file}",
        html_file
    ]

    res = subprocess.run(cmd, capture_output=True, text=True)
    if os.path.exists(pdf_file) and os.path.getsize(pdf_file) > 1000:
        size_kb = os.path.getsize(pdf_file) / 1024
        print(f"[OK] PDF successfully generated: {pdf_file}")
        print(f"     File Size: {size_kb:.1f} KB")
    else:
        print(f"[!] Error generating PDF: {res.stderr}")

    print("=" * 70)

if __name__ == "__main__":
    main()
