#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Threat Hunter Swiss Army Knife — Pro Windows Build (2025-08)

Features
- Passive & semi-offensive modules (opt-in)
- Subdomain scanner:
    * Defensive: CT logs via crt.sh (passive)
    * Semi: adds DNS brute-force (limited, concurrent)
- Presets picker (Recon / Passive / Semi-offensive)
- Results filter + expand/collapse all
- History & permalinks (/history, /view/<id>)
- Summary header + per-module timings
- Per-module export: Subdomains CSV
- Human-readable rendering for all modules
- Export CSV/JSON; PDF via WeasyPrint if installed (optional)
- Windows-friendly: DB path anchored to script folder

IMPORTANT: For educational and authorized testing only.
"""

import asyncio
import base64
import csv
import io
import json
import os
import re
import socket
import ssl
import sqlite3
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta
from urllib.parse import urljoin, urlparse

import requests
from bs4 import BeautifulSoup
from flask import Flask, render_template_string, request, Response, g, make_response

# Optional .env support
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

# Optional PDF support (WeasyPrint is tricky on Windows; optional)
try:
    from weasyprint import HTML
except ImportError:
    HTML = None

import dns.resolver
import whois

# ---------------- Config ----------------
HERE = os.path.dirname(os.path.abspath(__file__))
DATABASE = os.path.join(HERE, 'aegis.db')  # Windows-safe path
DEFAULT_TIMEOUT = 15
USER_AGENT = "Mozilla/5.0 (AegisSparks/6.0; +https://security-life.org)"
SESSION = requests.Session()
SESSION.headers.update({"User-Agent": USER_AGENT})

# API keys (optional)
VT_API_KEY = os.getenv("VT_API_KEY", "")
OTX_API_KEY = os.getenv("OTX_API_KEY", "")
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN", "")
SHODAN_API_KEY = os.getenv("SHODAN_API_KEY", "")
GREYNOISE_API_KEY = os.getenv("GREYNOISE_API_KEY", "")
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY", "")
SECURITYTRAILS_API_KEY = os.getenv("SECURITYTRAILS_API_KEY", "")
HIBP_API_KEY = os.getenv("HIBP_API_KEY", "")
SLACK_WEBHOOK_URL = os.getenv("SLACK_WEBHOOK_URL", "")
SCREENSHOT_TIMEOUT = int(os.getenv("SCREENSHOT_TIMEOUT", "20"))
ALERT_THRESHOLD = int(os.getenv("ALERT_THRESHOLD", "60"))
AWS_REGION = os.getenv("AWS_REGION", "us-east-1")
MALWARE_SANDBOX_URL = os.getenv("MALWARE_SANDBOX_URL", "")
MALWARE_SANDBOX_KEY = os.getenv("MALWARE_SANDBOX_KEY", "")
TICKET_WEBHOOK_URL = os.getenv("TICKET_WEBHOOK_URL", "")
AUTO_TICKET_THRESHOLD = int(os.getenv("AUTO_TICKET_THRESHOLD", "70"))
WORKFLOW_MAX_STEPS = int(os.getenv("WORKFLOW_MAX_STEPS", "15"))

try:
    from pyppeteer import launch
except ImportError:
    launch = None

try:
    import boto3
except ImportError:
    boto3 = None

try:
    from playwright.sync_api import sync_playwright
except ImportError:
    sync_playwright = None

# ---------------- Flask & DB ----------------
app = Flask(__name__)
app.config.from_object(__name__)
app.config["_processing_schedule"] = False

def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row
    return db

def init_db():
    schema = """
    CREATE TABLE IF NOT EXISTS scans (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        url TEXT NOT NULL,
        results TEXT NOT NULL,
        scan_date TIMESTAMP NOT NULL
    );
    CREATE TABLE IF NOT EXISTS scheduled_scans (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        url TEXT NOT NULL,
        services TEXT NOT NULL,
        mode TEXT NOT NULL,
        extras TEXT,
        interval_minutes INTEGER NOT NULL,
        next_run TEXT NOT NULL,
        last_run TEXT,
        last_results TEXT
    );
    """
    db = get_db()
    db.cursor().executescript(schema)
    db.commit()

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

# ---------------- HTML ----------------
INDEX_HTML = r"""
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>AEGIS — Automated Enrichment &amp; Global Intelligence Scanner</title>
  <script src="https://cdn.tailwindcss.com"></script>
  <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css" rel="stylesheet">
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&display=swap" rel="stylesheet">
  <style>
    :root {
      --primary: #3b82f6;
      --primary-glow: rgba(59, 130, 246, 0.5);
      --accent: #8b5cf6;
      --accent-glow: rgba(139, 92, 246, 0.4);
      --success: #10b981;
      --warning: #f59e0b;
      --danger: #ef4444;
      --glass-bg: rgba(17, 24, 39, 0.7);
      --glass-border: rgba(75, 85, 99, 0.4);
    }
    * { font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif; }
    body { 
      background: linear-gradient(135deg, #0f172a 0%, #1e1b4b 50%, #0f172a 100%);
      min-height: 100vh;
      position: relative;
      overflow-x: hidden;
    }
    body::before {
      content: '';
      position: fixed;
      top: 0; left: 0; right: 0; bottom: 0;
      background: 
        radial-gradient(ellipse at 20% 20%, rgba(59, 130, 246, 0.15) 0%, transparent 50%),
        radial-gradient(ellipse at 80% 80%, rgba(139, 92, 246, 0.15) 0%, transparent 50%),
        radial-gradient(ellipse at 50% 50%, rgba(16, 185, 129, 0.08) 0%, transparent 60%);
      pointer-events: none;
      z-index: 0;
    }
    .content-wrapper { position: relative; z-index: 1; }
    
    /* Glassmorphism Cards */
    .glass-card {
      background: var(--glass-bg);
      backdrop-filter: blur(20px);
      -webkit-backdrop-filter: blur(20px);
      border: 1px solid var(--glass-border);
      border-radius: 1.5rem;
      box-shadow: 
        0 8px 32px rgba(0, 0, 0, 0.3),
        inset 0 1px 0 rgba(255, 255, 255, 0.05);
    }
    .glass-card-sm {
      background: rgba(30, 41, 59, 0.6);
      backdrop-filter: blur(12px);
      border: 1px solid rgba(71, 85, 105, 0.4);
      border-radius: 0.75rem;
    }
    
    /* Animated Gradient Title */
    .gradient-title {
      background: linear-gradient(135deg, #60a5fa, #a78bfa, #34d399, #60a5fa);
      background-size: 300% 300%;
      -webkit-background-clip: text;
      -webkit-text-fill-color: transparent;
      background-clip: text;
      animation: gradientFlow 8s ease infinite;
    }
    @keyframes gradientFlow {
      0%, 100% { background-position: 0% 50%; }
      50% { background-position: 100% 50%; }
    }
    
    /* Glow Effects */
    .glow-blue { box-shadow: 0 0 20px var(--primary-glow), 0 0 40px rgba(59, 130, 246, 0.2); }
    .glow-purple { box-shadow: 0 0 20px var(--accent-glow); }
    .text-glow { text-shadow: 0 0 30px var(--primary-glow); }
    
    /* Button Styles */
    .btn-primary {
      background: linear-gradient(135deg, var(--primary), var(--accent));
      border: none;
      position: relative;
      overflow: hidden;
      transition: all 0.3s ease;
    }
    .btn-primary::before {
      content: '';
      position: absolute;
      top: 0; left: -100%; width: 100%; height: 100%;
      background: linear-gradient(90deg, transparent, rgba(255,255,255,0.2), transparent);
      transition: left 0.5s ease;
    }
    .btn-primary:hover::before { left: 100%; }
    .btn-primary:hover { transform: translateY(-2px); box-shadow: 0 10px 40px var(--primary-glow); }
    
    .btn-glass {
      background: rgba(55, 65, 81, 0.5);
      backdrop-filter: blur(8px);
      border: 1px solid rgba(107, 114, 128, 0.3);
      transition: all 0.3s ease;
    }
    .btn-glass:hover {
      background: rgba(75, 85, 99, 0.6);
      border-color: var(--primary);
      transform: translateY(-1px);
    }
    
    /* Module Cards */
    .module-card {
      background: rgba(30, 41, 59, 0.5);
      border: 1px solid rgba(71, 85, 105, 0.3);
      border-radius: 0.75rem;
      transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
      position: relative;
      overflow: hidden;
    }
    .module-card::before {
      content: '';
      position: absolute;
      top: 0; left: 0; right: 0;
      height: 2px;
      background: linear-gradient(90deg, var(--primary), var(--accent));
      opacity: 0;
      transition: opacity 0.3s ease;
    }
    .module-card:hover {
      background: rgba(45, 55, 72, 0.6);
      border-color: rgba(99, 102, 241, 0.4);
      transform: translateY(-2px);
    }
    .module-card:hover::before { opacity: 1; }
    .module-card.selected {
      background: rgba(59, 130, 246, 0.15);
      border-color: var(--primary);
    }
    .module-card.selected::before { opacity: 1; }
    
    /* Input Styles */
    .input-glass {
      background: rgba(30, 41, 59, 0.6);
      border: 1px solid rgba(71, 85, 105, 0.4);
      transition: all 0.3s ease;
    }
    .input-glass:focus {
      border-color: var(--primary);
      box-shadow: 0 0 0 3px rgba(59, 130, 246, 0.2), 0 0 20px rgba(59, 130, 246, 0.1);
      outline: none;
    }
    .input-glass::placeholder { color: rgba(156, 163, 175, 0.6); }
    
    /* Loading Overlay */
    #loadingOverlay {
      display: none;
      position: fixed;
      inset: 0;
      background: rgba(0, 0, 0, 0.95);
      backdrop-filter: blur(10px);
      z-index: 9999;
    }
    .loader-ring {
      width: 80px; height: 80px;
      border-radius: 50%;
      border: 3px solid transparent;
      border-top-color: var(--primary);
      border-right-color: var(--accent);
      animation: spin 1.2s cubic-bezier(0.5, 0, 0.5, 1) infinite;
      position: relative;
    }
    .loader-ring::before, .loader-ring::after {
      content: '';
      position: absolute;
      border-radius: 50%;
      border: 3px solid transparent;
    }
    .loader-ring::before {
      top: 8px; left: 8px; right: 8px; bottom: 8px;
      border-top-color: var(--success);
      animation: spin 1.8s cubic-bezier(0.5, 0, 0.5, 1) infinite reverse;
    }
    .loader-ring::after {
      top: 18px; left: 18px; right: 18px; bottom: 18px;
      border-top-color: var(--warning);
      animation: spin 2.4s cubic-bezier(0.5, 0, 0.5, 1) infinite;
    }
    @keyframes spin { 0% { transform: rotate(0deg); } 100% { transform: rotate(360deg); } }
    
    .progress-bar {
      height: 4px;
      background: rgba(55, 65, 81, 0.5);
      border-radius: 2px;
      overflow: hidden;
      margin-top: 1.5rem;
      width: 200px;
    }
    .progress-fill {
      height: 100%;
      background: linear-gradient(90deg, var(--primary), var(--accent), var(--success));
      background-size: 200% 100%;
      animation: progressGradient 2s ease infinite, progressWidth 10s ease-in-out infinite;
      border-radius: 2px;
    }
    @keyframes progressGradient {
      0%, 100% { background-position: 0% 50%; }
      50% { background-position: 100% 50%; }
    }
    @keyframes progressWidth {
      0% { width: 5%; }
      50% { width: 70%; }
      100% { width: 95%; }
    }
    
    /* Floating Particles */
    .particle {
      position: fixed;
      width: 4px; height: 4px;
      background: var(--primary);
      border-radius: 50%;
      pointer-events: none;
      opacity: 0.3;
      animation: float 20s infinite linear;
    }
    @keyframes float {
      0% { transform: translateY(100vh) rotate(0deg); opacity: 0; }
      10% { opacity: 0.3; }
      90% { opacity: 0.3; }
      100% { transform: translateY(-100vh) rotate(720deg); opacity: 0; }
    }
    
    /* Category Headers */
    .category-header {
      display: flex;
      align-items: center;
      gap: 0.75rem;
      padding: 0.75rem 0;
      margin-bottom: 0.75rem;
      border-bottom: 1px solid rgba(71, 85, 105, 0.3);
    }
    .category-icon {
      width: 32px; height: 32px;
      display: flex;
      align-items: center;
      justify-content: center;
      border-radius: 8px;
      font-size: 0.875rem;
    }
    
    /* Smooth Scrollbar */
    ::-webkit-scrollbar { width: 8px; height: 8px; }
    ::-webkit-scrollbar-track { background: rgba(17, 24, 39, 0.5); border-radius: 4px; }
    ::-webkit-scrollbar-thumb { background: rgba(75, 85, 99, 0.6); border-radius: 4px; }
    ::-webkit-scrollbar-thumb:hover { background: rgba(107, 114, 128, 0.8); }
    
    /* Animations */
    .fade-in { animation: fadeIn 0.5s ease forwards; }
    @keyframes fadeIn { from { opacity: 0; transform: translateY(10px); } to { opacity: 1; transform: translateY(0); } }
    .stagger-1 { animation-delay: 0.1s; }
    .stagger-2 { animation-delay: 0.2s; }
    .stagger-3 { animation-delay: 0.3s; }
    
    /* Tooltip */
    [data-tooltip] { position: relative; }
    [data-tooltip]:hover::after {
      content: attr(data-tooltip);
      position: absolute;
      bottom: 100%;
      left: 50%;
      transform: translateX(-50%);
      padding: 0.5rem 0.75rem;
      background: rgba(17, 24, 39, 0.95);
      border: 1px solid rgba(75, 85, 99, 0.5);
      border-radius: 0.5rem;
      font-size: 0.75rem;
      white-space: nowrap;
      z-index: 100;
      margin-bottom: 0.5rem;
    }
  </style>
</head>
<body class="text-gray-200">
  <!-- Floating Particles -->
  <div class="particle" style="left: 10%; animation-delay: 0s;"></div>
  <div class="particle" style="left: 25%; animation-delay: 3s; background: var(--accent);"></div>
  <div class="particle" style="left: 45%; animation-delay: 7s;"></div>
  <div class="particle" style="left: 65%; animation-delay: 2s; background: var(--success);"></div>
  <div class="particle" style="left: 85%; animation-delay: 5s; background: var(--accent);"></div>
  <div class="particle" style="left: 5%; animation-delay: 10s;"></div>
  <div class="particle" style="left: 75%; animation-delay: 12s; background: var(--success);"></div>
  <div class="particle" style="left: 35%; animation-delay: 15s;"></div>
  
  <!-- Loading Overlay -->
  <div id="loadingOverlay" class="flex items-center justify-center">
    <div class="text-center">
      <div class="loader-ring mx-auto"></div>
      <div class="text-white text-xl font-semibold mt-6 text-glow">Hunting for Threats...</div>
      <div class="text-gray-400 text-sm mt-2">Analyzing and enriching intelligence data</div>
      <div class="progress-bar mx-auto">
        <div class="progress-fill"></div>
      </div>
      <div id="loadingModules" class="text-gray-500 text-xs mt-3">Initializing modules...</div>
    </div>
  </div>

  <div class="content-wrapper container mx-auto p-4 md:p-8 max-w-7xl">
    <!-- Header -->
    <header class="flex flex-col md:flex-row items-start md:items-center justify-between mb-8 fade-in">
      <div class="mb-4 md:mb-0">
        <div class="flex items-center gap-3 mb-2">
          <div class="w-12 h-12 rounded-xl bg-gradient-to-br from-blue-500 to-purple-600 flex items-center justify-center glow-blue">
            <i class="fas fa-shield-halved text-2xl text-white"></i>
          </div>
          <div>
            <h1 class="text-3xl md:text-4xl font-bold gradient-title">AEGIS</h1>
            <p class="text-xs text-gray-500 uppercase tracking-wider">by sudo3rs</p>
          </div>
        </div>
        <p class="text-gray-400 text-sm md:text-base max-w-xl">
          <span class="text-blue-400 font-medium">A</span>utomated <span class="text-blue-400 font-medium">E</span>nrichment &amp; 
          <span class="text-purple-400 font-medium">G</span>lobal <span class="text-purple-400 font-medium">I</span>ntelligence 
          <span class="text-green-400 font-medium">S</span>canner
        </p>
      </div>
      <nav class="flex items-center gap-3">
        <a href="/history" class="btn-glass px-4 py-2 rounded-lg text-sm font-medium flex items-center gap-2">
          <i class="fas fa-clock-rotate-left text-blue-400"></i> History
        </a>
        <a href="/scheduled" class="btn-glass px-4 py-2 rounded-lg text-sm font-medium flex items-center gap-2">
          <i class="fas fa-calendar-check text-purple-400"></i> Scheduled
        </a>
        <button id="themeToggle" class="btn-glass p-2 rounded-lg" data-tooltip="Toggle Theme">
          <i class="fas fa-moon text-yellow-400"></i>
        </button>
      </nav>
    </header>

    <!-- Main Form -->
    <form id="scanForm" action="/scan" method="post" class="glass-card p-6 md:p-8 fade-in stagger-1">
      <!-- Target Input Section -->
      <div class="grid md:grid-cols-4 gap-6 mb-8">
        <div class="md:col-span-2">
          <label class="block text-sm font-semibold mb-2 text-gray-300">
            <i class="fas fa-crosshairs text-blue-400 mr-2"></i>Target URL
          </label>
          <div class="relative">
            <input type="url" name="url" placeholder="https://example.com" required
                   class="w-full rounded-xl input-glass px-4 py-3 text-white placeholder-gray-500 pr-12" />
            <div class="absolute right-3 top-1/2 -translate-y-1/2 text-gray-500">
              <i class="fas fa-globe"></i>
            </div>
          </div>
        </div>
        <div>
          <label class="block text-sm font-semibold mb-2 text-gray-300">
            <i class="fas fa-sliders text-purple-400 mr-2"></i>Scan Mode
          </label>
          <select name="mode" class="w-full rounded-xl input-glass px-4 py-3 text-white cursor-pointer">
            <option value="defensive" selected>🛡️ Defensive</option>
            <option value="semi">⚔️ Semi-offensive</option>
          </select>
        </div>
        <div>
          <label class="block text-sm font-semibold mb-2 text-gray-300">
            <i class="fas fa-wand-magic-sparkles text-green-400 mr-2"></i>Quick Preset
          </label>
          <select id="presetSelect" class="w-full rounded-xl input-glass px-4 py-3 text-white cursor-pointer">
            <option value="">Select preset...</option>
            <option value="recon">🔍 Recon (Passive OSINT)</option>
            <option value="passive">🔒 Passive (Safe Defaults)</option>
            <option value="semi">⚡ Semi-offensive (Authorized)</option>
          </select>
        </div>
      </div>

      <!-- Modules Section -->
      <div class="mb-8">
        <div class="flex items-center justify-between mb-4">
          <h3 class="text-lg font-semibold text-white flex items-center gap-2">
            <i class="fas fa-puzzle-piece text-blue-400"></i> Reconnaissance Modules
          </h3>
          <div class="flex gap-2">
            <button type="button" id="selectAll" class="text-xs btn-glass px-3 py-1.5 rounded-lg">
              <i class="fas fa-check-double mr-1"></i> Select All
            </button>
            <button type="button" id="clearAll" class="text-xs btn-glass px-3 py-1.5 rounded-lg">
              <i class="fas fa-times mr-1"></i> Clear All
            </button>
          </div>
        </div>
        
        <!-- Discovery Modules -->
        <div class="mb-6">
          <div class="category-header">
            <div class="category-icon bg-blue-500/20 text-blue-400"><i class="fas fa-magnifying-glass"></i></div>
            <span class="text-sm font-medium text-gray-400">Discovery & Fingerprinting</span>
          </div>
          <div class="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-5 gap-3">
            {% for label, val, icon in [
              ('Crawler', 'crawler', 'fa-spider'),
              ('Tech Fingerprint', 'tech', 'fa-microchip'),
              ('HTTP Headers', 'headers', 'fa-server'),
              ('Security Headers', 'sec_headers', 'fa-shield'),
              ('TLS Certificate', 'tls', 'fa-lock')
            ] %}
            <label class="module-card px-3 py-2.5 cursor-pointer flex items-center gap-3 group">
              <input type="checkbox" name="services" value="{{ val }}" class="hidden peer">
              <div class="w-8 h-8 rounded-lg bg-blue-500/10 flex items-center justify-center text-blue-400 group-hover:bg-blue-500/20 peer-checked:bg-blue-500 peer-checked:text-white transition-all">
                <i class="fas {{ icon }} text-sm"></i>
              </div>
              <span class="text-sm text-gray-300 group-hover:text-white transition-colors">{{ label }}</span>
            </label>
            {% endfor %}
          </div>
        </div>
        
        <!-- DNS & Domain Modules -->
        <div class="mb-6">
          <div class="category-header">
            <div class="category-icon bg-purple-500/20 text-purple-400"><i class="fas fa-network-wired"></i></div>
            <span class="text-sm font-medium text-gray-400">DNS & Domain Intelligence</span>
          </div>
          <div class="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-5 gap-3">
            {% for label, val, icon in [
              ('DNS Records', 'dns', 'fa-diagram-project'),
              ('WHOIS Lookup', 'whois', 'fa-address-card'),
              ('Subdomain Scan', 'subdomains', 'fa-sitemap'),
              ('SecurityTrails', 'securitytrails', 'fa-route'),
              ('Cloud Assets', 'cloud_assets', 'fa-cloud')
            ] %}
            <label class="module-card px-3 py-2.5 cursor-pointer flex items-center gap-3 group">
              <input type="checkbox" name="services" value="{{ val }}" class="hidden peer">
              <div class="w-8 h-8 rounded-lg bg-purple-500/10 flex items-center justify-center text-purple-400 group-hover:bg-purple-500/20 peer-checked:bg-purple-500 peer-checked:text-white transition-all">
                <i class="fas {{ icon }} text-sm"></i>
              </div>
              <span class="text-sm text-gray-300 group-hover:text-white transition-colors">{{ label }}</span>
            </label>
            {% endfor %}
          </div>
        </div>
        
        <!-- Threat Intel Modules -->
        <div class="mb-6">
          <div class="category-header">
            <div class="category-icon bg-red-500/20 text-red-400"><i class="fas fa-biohazard"></i></div>
            <span class="text-sm font-medium text-gray-400">Threat Intelligence</span>
          </div>
          <div class="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-5 gap-3">
            {% for label, val, icon in [
              ('VirusTotal', 'virustotal', 'fa-virus'),
              ('urlscan.io', 'urlscan', 'fa-eye'),
              ('AlienVault OTX', 'otx', 'fa-user-secret'),
              ('Shodan', 'shodan', 'fa-satellite-dish'),
              ('GreyNoise', 'greynoise', 'fa-broadcast-tower'),
              ('AbuseIPDB', 'abuseipdb', 'fa-ban'),
              ('GitHub Code', 'github', 'fa-brands fa-github'),
              ('Code Scan', 'code_scan', 'fa-code'),
              ('Archive.org', 'archive', 'fa-box-archive'),
              ('HIBP Check', 'hibp', 'fa-user-lock')
            ] %}
            <label class="module-card px-3 py-2.5 cursor-pointer flex items-center gap-3 group">
              <input type="checkbox" name="services" value="{{ val }}" class="hidden peer">
              <div class="w-8 h-8 rounded-lg bg-red-500/10 flex items-center justify-center text-red-400 group-hover:bg-red-500/20 peer-checked:bg-red-500 peer-checked:text-white transition-all">
                <i class="{{ 'fab' if 'brands' in icon else 'fas' }} {{ icon.replace('fa-brands ', '') }} text-sm"></i>
              </div>
              <span class="text-sm text-gray-300 group-hover:text-white transition-colors">{{ label }}</span>
            </label>
            {% endfor %}
          </div>
        </div>
        
        <!-- Security Analysis Modules -->
        <div class="mb-6">
          <div class="category-header">
            <div class="category-icon bg-yellow-500/20 text-yellow-400"><i class="fas fa-triangle-exclamation"></i></div>
            <span class="text-sm font-medium text-gray-400">Security Analysis</span>
          </div>
          <div class="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-5 gap-3">
            {% for label, val, icon in [
              ('security.txt', 'security_txt', 'fa-file-shield'),
              ('Robots.txt', 'robots_txt', 'fa-robot'),
              ('Signature Scan', 'signatures', 'fa-fingerprint'),
              ('CVE Alerts', 'cve_alerts', 'fa-bug'),
              ('OWASP Top 10', 'owasp_top10', 'fa-list-check'),
              ('Exposure Probe', 'exposure_checks', 'fa-door-open'),
              ('Param Fuzzer', 'fuzzer', 'fa-shuffle'),
              ('WAF Detection', 'waf_detect', 'fa-shield-halved'),
              ('Email Security', 'email_security', 'fa-envelope-circle-check'),
              ('Port Scanner', 'port_scan', 'fa-network-wired'),
              ('ASN Lookup', 'asn_lookup', 'fa-building'),
              ('Favicon Hash', 'favicon_hash', 'fa-image'),
              ('SSL/TLS Audit', 'ssl_tls', 'fa-lock'),
              ('Takeover Check', 'subdomain_takeover', 'fa-skull-crossbones'),
              ('HTTP Methods', 'http_methods', 'fa-arrows-left-right'),
              ('CORS Check', 'cors', 'fa-link-slash'),
              ('Cookie Audit', 'cookie_audit', 'fa-cookie-bite'),
              ('JS Secrets', 'js_secrets', 'fa-key')
            ] %}
            <label class="module-card px-3 py-2.5 cursor-pointer flex items-center gap-3 group">
              <input type="checkbox" name="services" value="{{ val }}" class="hidden peer">
              <div class="w-8 h-8 rounded-lg bg-yellow-500/10 flex items-center justify-center text-yellow-400 group-hover:bg-yellow-500/20 peer-checked:bg-yellow-500 peer-checked:text-white transition-all">
                <i class="fas {{ icon }} text-sm"></i>
              </div>
              <span class="text-sm text-gray-300 group-hover:text-white transition-colors">{{ label }}</span>
            </label>
            {% endfor %}
          </div>
        </div>
        
        <!-- Automation Modules -->
        <div>
          <div class="category-header">
            <div class="category-icon bg-green-500/20 text-green-400"><i class="fas fa-robot"></i></div>
            <span class="text-sm font-medium text-gray-400">Automation & Capture</span>
          </div>
          <div class="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-5 gap-3">
            {% for label, val, icon in [
              ('Screenshot', 'screenshot', 'fa-camera'),
              ('Workflow Runner', 'workflow', 'fa-gears'),
              ('Sandbox Submit', 'sandbox', 'fa-flask')
            ] %}
            <label class="module-card px-3 py-2.5 cursor-pointer flex items-center gap-3 group">
              <input type="checkbox" name="services" value="{{ val }}" class="hidden peer">
              <div class="w-8 h-8 rounded-lg bg-green-500/10 flex items-center justify-center text-green-400 group-hover:bg-green-500/20 peer-checked:bg-green-500 peer-checked:text-white transition-all">
                <i class="fas {{ icon }} text-sm"></i>
              </div>
              <span class="text-sm text-gray-300 group-hover:text-white transition-colors">{{ label }}</span>
            </label>
            {% endfor %}
          </div>
        </div>
      </div>

      <!-- Advanced Options -->
      <details class="mb-8 group">
        <summary class="cursor-pointer text-sm font-semibold text-gray-400 hover:text-white transition-colors flex items-center gap-2">
          <i class="fas fa-chevron-right transition-transform group-open:rotate-90"></i>
          <i class="fas fa-sliders text-purple-400"></i> Advanced Options
        </summary>
        <div class="mt-4 grid md:grid-cols-2 gap-6 pl-6">
          <div>
            <label class="block text-sm font-medium mb-2 text-gray-300">
              <i class="fas fa-list text-blue-400 mr-2"></i>Custom Subdomain Words
            </label>
            <textarea name="extra_subdomains" rows="3" placeholder="admin&#10;portal&#10;staging"
                      class="w-full rounded-xl input-glass px-4 py-3 text-sm text-white resize-none"></textarea>
            <p class="text-xs text-gray-500 mt-1">One per line. Added to bruteforce wordlist.</p>
          </div>
          <div>
            <label class="block text-sm font-medium mb-2 text-gray-300">
              <i class="fas fa-folder-open text-yellow-400 mr-2"></i>Custom Exposure Paths
            </label>
            <textarea name="extra_exposures" rows="3" placeholder="/backup.tgz&#10;high::/admin/.env"
                      class="w-full rounded-xl input-glass px-4 py-3 text-sm text-white resize-none"></textarea>
            <p class="text-xs text-gray-500 mt-1">Prefix with <code class="text-red-400">high::</code>, <code class="text-yellow-400">medium::</code>, or <code class="text-blue-400">low::</code></p>
          </div>
          <div class="md:col-span-2">
            <label class="block text-sm font-medium mb-2 text-gray-300">
              <i class="fas fa-code text-green-400 mr-2"></i>Workflow Steps (JSON)
            </label>
            <textarea name="workflow_steps" rows="3" placeholder='[{"action":"click","selector":"#login"},{"action":"type","selector":"#user","value":"test"}]'
                      class="w-full rounded-xl input-glass px-4 py-3 text-sm text-white font-mono resize-none"></textarea>
            <p class="text-xs text-gray-500 mt-1">Playwright-style automation steps for the Workflow Runner module.</p>
          </div>
        </div>
      </details>

      <!-- Output Options & Submit -->
      <div class="flex flex-col md:flex-row items-start md:items-center justify-between gap-4 pt-6 border-t border-gray-700/50">
        <div class="flex flex-wrap items-center gap-4">
          <div class="flex items-center gap-3">
            <span class="text-sm text-gray-400"><i class="fas fa-file-export mr-1"></i>Output:</span>
            <label class="flex items-center gap-2 cursor-pointer">
              <input type="radio" name="view_mode" value="human" checked class="hidden peer">
              <span class="px-3 py-1.5 text-xs rounded-lg border border-gray-600 peer-checked:border-blue-500 peer-checked:bg-blue-500/20 peer-checked:text-blue-400 transition-all">
                <i class="fas fa-user mr-1"></i>Human
              </span>
            </label>
            <label class="flex items-center gap-2 cursor-pointer">
              <input type="radio" name="view_mode" value="json" class="hidden peer">
              <span class="px-3 py-1.5 text-xs rounded-lg border border-gray-600 peer-checked:border-green-500 peer-checked:bg-green-500/20 peer-checked:text-green-400 transition-all">
                <i class="fas fa-code mr-1"></i>JSON
              </span>
            </label>
          </div>
          <div class="flex items-center gap-2">
            <i class="fas fa-clock text-gray-500"></i>
            <input type="number" name="schedule_minutes" min="0" placeholder="0"
                   class="w-20 rounded-lg input-glass px-3 py-2 text-sm text-center" />
            <span class="text-xs text-gray-500">min interval</span>
          </div>
        </div>
        <button type="submit" class="btn-primary text-white font-bold px-8 py-3 rounded-xl flex items-center gap-3 text-base">
          <i class="fas fa-crosshairs"></i>
          <span>Start Hunt</span>
          <i class="fas fa-arrow-right"></i>
        </button>
      </div>
    </form>

    <!-- Footer -->
    <footer class="mt-8 text-center text-xs text-gray-600 fade-in stagger-3">
      <p>AEGIS v2.0 — Threat Hunter Swiss Army Knife</p>
      <p class="mt-1">For authorized security testing only. <a href="https://security-life.org" class="text-blue-500 hover:underline">security-life.org</a></p>
    </footer>
  </div>

  <script>
    const form = document.getElementById('scanForm');
    const overlay = document.getElementById('loadingOverlay');
    const loadingModules = document.getElementById('loadingModules');
    
    const moduleMessages = [
      'Initializing reconnaissance modules...',
      'Preparing threat intelligence feeds...',
      'Configuring subdomain enumeration...',
      'Setting up vulnerability scanners...',
      'Connecting to OSINT sources...',
      'Analyzing target infrastructure...',
      'Gathering security headers...',
      'Querying threat databases...',
      'Processing DNS records...',
      'Finalizing scan parameters...'
    ];
    
    form.addEventListener('submit', function() {
      overlay.style.display = 'flex';
      let msgIndex = 0;
      setInterval(() => {
        loadingModules.textContent = moduleMessages[msgIndex % moduleMessages.length];
        msgIndex++;
      }, 2000);
    });

    // Module card selection visual feedback
    document.querySelectorAll('.module-card input[type="checkbox"]').forEach(cb => {
      cb.addEventListener('change', function() {
        this.closest('.module-card').classList.toggle('selected', this.checked);
      });
    });

    // Presets with new modules
    const presets = {
      recon: ["crawler","tech","headers","sec_headers","dns","whois","archive","urlscan","github","code_scan","security_txt","robots_txt","securitytrails","signatures","cve_alerts","owasp_top10"],
      passive: ["crawler","tech","headers","sec_headers","tls","dns","whois","subdomains","security_txt","robots_txt","securitytrails","signatures","cve_alerts","virustotal","urlscan","otx","hibp","shodan","greynoise","abuseipdb","cloud_assets","owasp_top10"],
      semi: ["crawler","tech","headers","sec_headers","tls","dns","whois","subdomains","security_txt","robots_txt","securitytrails","signatures","cve_alerts","screenshot","virustotal","urlscan","otx","code_scan","hibp","shodan","greynoise","abuseipdb","exposure_checks","fuzzer","workflow","sandbox","owasp_top10"]
    };
    
    document.getElementById('presetSelect').addEventListener('change', (e) => {
      const vals = presets[e.target.value] || [];
      document.querySelectorAll('.module-card input[type="checkbox"]').forEach(cb => {
        cb.checked = false;
        cb.closest('.module-card').classList.remove('selected');
      });
      vals.forEach(v => {
        const cb = document.querySelector(`input[name="services"][value="${v}"]`);
        if (cb) {
          cb.checked = true;
          cb.closest('.module-card').classList.add('selected');
        }
      });
      if (e.target.value === 'semi') {
        document.querySelector('select[name="mode"]').value = 'semi';
      }
    });

    // Select All / Clear All
    document.getElementById('selectAll').addEventListener('click', () => {
      document.querySelectorAll('.module-card input[type="checkbox"]').forEach(cb => {
        cb.checked = true;
        cb.closest('.module-card').classList.add('selected');
      });
    });
    document.getElementById('clearAll').addEventListener('click', () => {
      document.querySelectorAll('.module-card input[type="checkbox"]').forEach(cb => {
        cb.checked = false;
        cb.closest('.module-card').classList.remove('selected');
      });
    });

    // Theme toggle
    const toggle = document.getElementById('themeToggle');
    if (toggle) {
      toggle.addEventListener('click', () => {
        document.documentElement.classList.toggle('invert');
        const icon = toggle.querySelector('i');
        icon.classList.toggle('fa-moon');
        icon.classList.toggle('fa-sun');
      });
    }

    // Keyboard shortcuts
    document.addEventListener('keydown', (e) => {
      if (e.ctrlKey || e.metaKey) {
        switch(e.key) {
          case 'Enter':
            e.preventDefault();
            form.submit();
            break;
          case 'a':
            if (e.target.tagName !== 'INPUT' && e.target.tagName !== 'TEXTAREA') {
              e.preventDefault();
              document.getElementById('selectAll').click();
            }
            break;
        }
      }
    });
  </script>
</body>
</html>
"""

RESULTS_HTML = r"""
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>AEGIS — Threat Hunt Results</title>
  <script src="https://cdn.tailwindcss.com"></script>
  <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css" rel="stylesheet">
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">
  <style>
    * { font-family: 'Inter', sans-serif; }
    
    /* Animated gradient background */
    .bg-animated {
      background: linear-gradient(-45deg, #0f0f23, #1a1a3e, #0d1b2a, #1b263b);
      background-size: 400% 400%;
      animation: gradientShift 15s ease infinite;
    }
    @keyframes gradientShift {
      0% { background-position: 0% 50%; }
      50% { background-position: 100% 50%; }
      100% { background-position: 0% 50%; }
    }
    
    /* Floating particles */
    .particles { position: fixed; top: 0; left: 0; width: 100%; height: 100%; pointer-events: none; overflow: hidden; z-index: 0; }
    .particle { position: absolute; width: 4px; height: 4px; background: rgba(96, 165, 250, 0.4); border-radius: 50%; animation: float 20s infinite; }
    @keyframes float { 0%, 100% { transform: translateY(100vh) rotate(0deg); opacity: 0; } 10% { opacity: 1; } 90% { opacity: 1; } 100% { transform: translateY(-10vh) rotate(720deg); opacity: 0; } }
    
    /* Glassmorphism cards */
    .glass-card {
      background: rgba(30, 41, 59, 0.7);
      backdrop-filter: blur(12px);
      -webkit-backdrop-filter: blur(12px);
      border: 1px solid rgba(148, 163, 184, 0.1);
      border-radius: 1rem;
      transition: all 0.3s ease;
    }
    .glass-card:hover {
      background: rgba(30, 41, 59, 0.85);
      border-color: rgba(96, 165, 250, 0.3);
      box-shadow: 0 8px 32px rgba(0, 0, 0, 0.3);
      transform: translateY(-2px);
    }
    
    /* Result cards */
    .result-card {
      background: rgba(30, 41, 59, 0.6);
      backdrop-filter: blur(10px);
      border: 1px solid rgba(148, 163, 184, 0.15);
      border-radius: 1rem;
      padding: 1.5rem;
      margin-bottom: 1rem;
      transition: all 0.3s ease;
    }
    .result-card:hover { border-color: rgba(96, 165, 250, 0.4); }
    .result-card[open] { border-color: rgba(96, 165, 250, 0.5); background: rgba(30, 41, 59, 0.8); }
    
    .result-title { color: #60a5fa; font-size: 1.1rem; font-weight: 600; display: flex; align-items: center; gap: 0.75rem; cursor: pointer; }
    .result-title:hover { color: #93c5fd; }
    .result-title i { font-size: 0.9rem; opacity: 0.7; }
    
    /* Summary stat cards */
    .stat-card {
      background: linear-gradient(135deg, rgba(30, 41, 59, 0.8) 0%, rgba(30, 41, 59, 0.4) 100%);
      backdrop-filter: blur(12px);
      border: 1px solid rgba(148, 163, 184, 0.15);
      border-radius: 1rem;
      padding: 1.25rem;
      position: relative;
      overflow: hidden;
    }
    .stat-card::before {
      content: '';
      position: absolute;
      top: 0; left: 0;
      width: 100%; height: 3px;
      background: linear-gradient(90deg, var(--accent-color, #3b82f6), transparent);
    }
    .stat-card .stat-icon { position: absolute; right: 1rem; top: 50%; transform: translateY(-50%); font-size: 2.5rem; opacity: 0.1; }
    
    /* Badges */
    .badge { display: inline-block; padding: 0.25rem 0.75rem; border-radius: 9999px; font-size: 0.7rem; font-weight: 600; text-transform: uppercase; letter-spacing: 0.05em; }
    .ok { background: linear-gradient(135deg, #10b981, #059669); color: white; box-shadow: 0 2px 8px rgba(16, 185, 129, 0.3); }
    .warn { background: linear-gradient(135deg, #f59e0b, #d97706); color: white; box-shadow: 0 2px 8px rgba(245, 158, 11, 0.3); }
    .bad { background: linear-gradient(135deg, #ef4444, #dc2626); color: white; box-shadow: 0 2px 8px rgba(239, 68, 68, 0.3); }
    .badge.sev-high { background: linear-gradient(135deg, #dc2626, #b91c1c); box-shadow: 0 2px 8px rgba(220, 38, 38, 0.4); }
    .badge.sev-medium { background: linear-gradient(135deg, #f97316, #ea580c); box-shadow: 0 2px 8px rgba(249, 115, 22, 0.3); }
    .badge.sev-low { background: linear-gradient(135deg, #0ea5e9, #0284c7); box-shadow: 0 2px 8px rgba(14, 165, 233, 0.3); }
    
    /* Tables */
    table { width: 100%; border-collapse: collapse; margin-top: 0.75rem; }
    th, td { padding: 0.75rem 1rem; text-align: left; border-bottom: 1px solid rgba(148, 163, 184, 0.1); }
    th { background: rgba(30, 41, 59, 0.5); color: #94a3b8; font-weight: 500; font-size: 0.8rem; text-transform: uppercase; letter-spacing: 0.05em; }
    tbody tr:hover { background: rgba(96, 165, 250, 0.05); }
    
    /* Risk score ring */
    .risk-ring { width: 100px; height: 100px; position: relative; }
    .risk-ring svg { transform: rotate(-90deg); }
    .risk-ring circle { fill: none; stroke-width: 8; stroke-linecap: round; }
    .risk-ring .bg { stroke: rgba(148, 163, 184, 0.2); }
    .risk-ring .progress { stroke: var(--ring-color, #3b82f6); transition: stroke-dashoffset 1s ease; }
    .risk-ring .value { position: absolute; top: 50%; left: 50%; transform: translate(-50%, -50%); font-size: 1.5rem; font-weight: 700; }
    
    /* Buttons */
    .btn { display: inline-flex; align-items: center; gap: 0.5rem; padding: 0.6rem 1.25rem; border-radius: 0.75rem; font-weight: 500; font-size: 0.85rem; transition: all 0.2s ease; }
    .btn-primary { background: linear-gradient(135deg, #3b82f6, #2563eb); color: white; }
    .btn-primary:hover { background: linear-gradient(135deg, #60a5fa, #3b82f6); transform: translateY(-1px); box-shadow: 0 4px 12px rgba(59, 130, 246, 0.4); }
    .btn-secondary { background: rgba(51, 65, 85, 0.7); color: #e2e8f0; border: 1px solid rgba(148, 163, 184, 0.2); }
    .btn-secondary:hover { background: rgba(71, 85, 105, 0.8); border-color: rgba(148, 163, 184, 0.4); }
    
    /* Details animation */
    details[open] summary ~ * { animation: slideDown 0.3s ease; }
    @keyframes slideDown { from { opacity: 0; transform: translateY(-10px); } to { opacity: 1; transform: translateY(0); } }
    details summary::-webkit-details-marker { display: none; }
    details summary::after { content: '\f078'; font-family: 'Font Awesome 6 Free'; font-weight: 900; margin-left: auto; font-size: 0.75rem; transition: transform 0.3s ease; }
    details[open] summary::after { transform: rotate(180deg); }
    
    /* Scrollbar */
    ::-webkit-scrollbar { width: 8px; height: 8px; }
    ::-webkit-scrollbar-track { background: rgba(30, 41, 59, 0.5); }
    ::-webkit-scrollbar-thumb { background: rgba(148, 163, 184, 0.3); border-radius: 4px; }
    ::-webkit-scrollbar-thumb:hover { background: rgba(148, 163, 184, 0.5); }
  </style>
</head>
<body class="bg-animated text-gray-200 min-h-screen">
  <!-- Floating Particles -->
  <div class="particles">
    <div class="particle" style="left: 10%; animation-delay: 0s;"></div>
    <div class="particle" style="left: 20%; animation-delay: 2s;"></div>
    <div class="particle" style="left: 40%; animation-delay: 4s;"></div>
    <div class="particle" style="left: 60%; animation-delay: 1s;"></div>
    <div class="particle" style="left: 80%; animation-delay: 3s;"></div>
    <div class="particle" style="left: 90%; animation-delay: 5s;"></div>
  </div>

  <div class="container mx-auto p-4 md:p-8 relative z-10">
    <!-- Header -->
    <div class="text-center mb-8">
      <div class="inline-flex items-center gap-3 mb-4">
        <div class="w-12 h-12 rounded-xl bg-gradient-to-br from-blue-500 to-purple-600 flex items-center justify-center">
          <i class="fas fa-shield-halved text-white text-xl"></i>
        </div>
        <h1 class="text-3xl md:text-4xl font-bold bg-gradient-to-r from-blue-400 to-purple-400 bg-clip-text text-transparent">
          Threat Hunt Results
        </h1>
      </div>
      <p class="text-gray-400">
        Analysis for: <a href="{{ url }}" class="text-blue-400 hover:text-blue-300 hover:underline transition-colors" target="_blank">{{ url }}</a>
      </p>
    </div>

    <!-- Summary Cards -->
    {% if results.get('_summary') %}
    <div class="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-4 mb-8">
      <div class="stat-card" style="--accent-color: #10b981;">
        <i class="fas fa-sitemap stat-icon text-green-400"></i>
        <div class="text-xs text-gray-400 mb-1">Subdomains</div>
        <div class="text-2xl font-bold text-green-400">{{ results['_summary']['subdomains'] }}</div>
      </div>
      <div class="stat-card" style="--accent-color: #f59e0b;">
        <i class="fas fa-shield-xmark stat-icon text-yellow-400"></i>
        <div class="text-xs text-gray-400 mb-1">Missing Headers</div>
        <div class="text-2xl font-bold text-yellow-400">{{ results['_summary']['missing_sec_headers'] }}</div>
      </div>
      <div class="stat-card" style="--accent-color: #ef4444;">
        <i class="fas fa-virus stat-icon text-red-400"></i>
        <div class="text-xs text-gray-400 mb-1">VT Malicious</div>
        <div class="text-2xl font-bold text-red-400">{{ results['_summary']['vt_malicious'] }}</div>
      </div>
      <div class="stat-card" style="--accent-color: #3b82f6;">
        <i class="fas fa-clock stat-icon text-blue-400"></i>
        <div class="text-xs text-gray-400 mb-1">Duration</div>
        <div class="text-2xl font-bold text-blue-400">{{ results.get('_meta', {}).get('total_seconds', '-') }}s</div>
      </div>
      <div class="stat-card col-span-2" style="--accent-color: {% if results['_summary']['risk_level'] == 'critical' %}#dc2626{% elif results['_summary']['risk_level'] == 'high' %}#f97316{% elif results['_summary']['risk_level'] == 'medium' %}#f59e0b{% else %}#10b981{% endif %};">
        <i class="fas fa-gauge-high stat-icon"></i>
        <div class="flex items-center justify-between">
          <div>
            <div class="text-xs text-gray-400 mb-1">Risk Score</div>
            <div class="text-3xl font-bold">{{ results['_summary']['risk_score'] }}</div>
          </div>
          <div class="text-right">
            <span class="badge {% if results['_summary']['risk_level'] == 'critical' %}bad{% elif results['_summary']['risk_level'] == 'high' %}sev-high{% elif results['_summary']['risk_level'] == 'medium' %}warn{% else %}ok{% endif %}">
              {{ results['_summary']['risk_level']|upper }}
            </span>
          </div>
        </div>
      </div>
    </div>
    {% endif %}

    <!-- Action Buttons -->
    <div class="glass-card p-4 mb-6">
      <div class="flex flex-wrap items-center justify-between gap-4">
        <div class="flex items-center gap-2">
          <button id="btnHuman" class="btn {% if view_mode == 'human' %}btn-primary{% else %}btn-secondary{% endif %}">
            <i class="fas fa-eye"></i> Human View
          </button>
          <button id="btnJSON" class="btn {% if view_mode == 'json' %}btn-primary{% else %}btn-secondary{% endif %}">
            <i class="fas fa-code"></i> JSON
          </button>
        </div>
        <div class="flex flex-wrap items-center gap-2">
          {% if scan_id %}
          <a href="/view/{{ scan_id }}" class="btn btn-secondary"><i class="fas fa-link"></i> Permalink</a>
          <a href="/graph/{{ scan_id }}" class="btn btn-secondary"><i class="fas fa-diagram-project"></i> Graph</a>
          {% endif %}
          <a href="/export/json" class="btn btn-secondary"><i class="fas fa-file-code"></i> JSON</a>
          <a href="/export/csv" class="btn btn-secondary"><i class="fas fa-file-csv"></i> CSV</a>
          {% if pdf_available %}
          <a href="/export/pdf" class="btn btn-primary"><i class="fas fa-file-pdf"></i> PDF</a>
          {% endif %}
        </div>
      </div>
    </div>

    <!-- Filter and Controls -->
    <div class="flex flex-wrap items-center gap-3 mb-6">
      <div class="flex-1 min-w-[200px]">
        <div class="relative">
          <i class="fas fa-search absolute left-4 top-1/2 -translate-y-1/2 text-gray-500"></i>
          <input id="resultFilter" type="text" placeholder="Filter results..."
                 class="w-full pl-11 pr-4 py-3 rounded-xl bg-slate-800/60 border border-slate-700/50 text-sm focus:outline-none focus:border-blue-500/50 focus:ring-2 focus:ring-blue-500/20 transition-all">
        </div>
      </div>
      <button id="btnExpandAll" class="btn btn-secondary"><i class="fas fa-expand"></i> Expand All</button>
      <button id="btnCollapseAll" class="btn btn-secondary"><i class="fas fa-compress"></i> Collapse All</button>
    </div>

    <!-- Module Timings (collapsible) -->
    {% if results.get('_meta', {}).get('module_times') %}
    <details class="result-card mb-6">
      <summary class="result-title"><i class="fas fa-stopwatch"></i> Module Timings</summary>
      <div class="mt-4">
        <div class="grid grid-cols-2 md:grid-cols-4 gap-2">
          {% for m, secs in results['_meta']['module_times'].items() %}
          <div class="flex justify-between items-center bg-slate-800/40 rounded-lg px-3 py-2">
            <span class="text-sm text-gray-300">{{ m.replace('_', ' ').title() }}</span>
            <span class="text-sm font-mono text-blue-400">{{ secs }}s</span>
          </div>
          {% endfor %}
        </div>
      </div>
    </details>
    {% endif %}

    <!-- Human View -->
    <div id="humanView" class="{% if view_mode != 'human' %}hidden{% endif %} space-y-6">
      {% for key, value in results.items() if value and not key.startswith('_') %}
      <div class="result-card">
        <h2 class="result-title">{{ key.replace('_', ' ')|title }}</h2>

        {% if value is mapping and value.get('error') %}
          <p class="text-red-400">Error: {{ value.error }}</p>

        {% elif key == 'crawler' %}
          <!-- Crawler Stats -->
          {% if value.get('stats') %}
          <div class="flex gap-4 mb-4 text-sm">
            <span class="text-gray-400">Pages Scanned: <span class="text-blue-400 font-semibold">{{ value.stats.pages_scanned }}</span></span>
            <span class="text-gray-400">Errors: <span class="text-red-400 font-semibold">{{ value.stats.errors }}</span></span>
          </div>
          {% endif %}
          
          <div class="grid md:grid-cols-2 gap-4">
            <!-- Pages Found -->
            <div class="bg-slate-800/40 rounded-lg p-3">
              <div class="flex justify-between items-center mb-2">
                <span class="text-sm font-medium text-gray-300"><i class="fas fa-file-lines mr-2 text-blue-400"></i>Pages Found</span>
                <span class="badge ok">{{ value.urls|length }}</span>
              </div>
              <details><summary class="text-blue-400 text-sm cursor-pointer">View pages</summary>
                <ul class="list-disc pl-5 mt-2 text-sm max-h-40 overflow-y-auto">{% for u in value.urls[:30] %}<li><a href="{{ u }}" target="_blank" class="hover:underline text-gray-300 truncate block">{{ u }}</a></li>{% endfor %}</ul>
              </details>
            </div>
            
            <!-- External Links -->
            <div class="bg-slate-800/40 rounded-lg p-3">
              <div class="flex justify-between items-center mb-2">
                <span class="text-sm font-medium text-gray-300"><i class="fas fa-external-link mr-2 text-purple-400"></i>External Links</span>
                <span class="badge warn">{{ value.external_links|length }}</span>
              </div>
              <details><summary class="text-blue-400 text-sm cursor-pointer">View links</summary>
                <ul class="list-disc pl-5 mt-2 text-sm max-h-40 overflow-y-auto">{% for l in value.external_links[:30] %}<li><a href="{{ l }}" target="_blank" class="hover:underline text-gray-300 truncate block">{{ l }}</a></li>{% endfor %}</ul>
              </details>
            </div>
            
            <!-- Emails -->
            <div class="bg-slate-800/40 rounded-lg p-3">
              <div class="flex justify-between items-center mb-2">
                <span class="text-sm font-medium text-gray-300"><i class="fas fa-envelope mr-2 text-green-400"></i>Emails Found</span>
                <span class="badge {% if value.emails|length > 0 %}ok{% else %}warn{% endif %}">{{ value.emails|length }}</span>
              </div>
              {% if value.emails %}<ul class="text-sm text-gray-300">{% for e in value.emails[:15] %}<li class="py-1">{{ e }}</li>{% endfor %}</ul>{% else %}<span class="text-gray-500 text-sm">None found</span>{% endif %}
            </div>
            
            <!-- Phone Numbers -->
            {% if value.get('phone_numbers') %}
            <div class="bg-slate-800/40 rounded-lg p-3">
              <div class="flex justify-between items-center mb-2">
                <span class="text-sm font-medium text-gray-300"><i class="fas fa-phone mr-2 text-yellow-400"></i>Phone Numbers</span>
                <span class="badge ok">{{ value.phone_numbers|length }}</span>
              </div>
              <ul class="text-sm text-gray-300">{% for p in value.phone_numbers[:10] %}<li class="py-1">{{ p }}</li>{% endfor %}</ul>
            </div>
            {% endif %}
            
            <!-- Forms -->
            {% if value.get('forms') %}
            <div class="bg-slate-800/40 rounded-lg p-3">
              <div class="flex justify-between items-center mb-2">
                <span class="text-sm font-medium text-gray-300"><i class="fas fa-rectangle-list mr-2 text-orange-400"></i>Forms Detected</span>
                <span class="badge warn">{{ value.forms|length }}</span>
              </div>
              <details><summary class="text-blue-400 text-sm cursor-pointer">View forms</summary>
                <div class="mt-2 space-y-2">
                  {% for f in value.forms[:10] %}
                  <div class="bg-slate-900/50 rounded p-2 text-xs">
                    <div><span class="badge {% if f.method == 'POST' %}warn{% else %}ok{% endif %}">{{ f.method }}</span> {{ f.action }}</div>
                    <div class="text-gray-500 mt-1">Inputs: {{ f.inputs|map(attribute='name')|list|join(', ') }}</div>
                  </div>
                  {% endfor %}
                </div>
              </details>
            </div>
            {% endif %}
            
            <!-- JavaScript Files -->
            {% if value.get('js_files') %}
            <div class="bg-slate-800/40 rounded-lg p-3">
              <div class="flex justify-between items-center mb-2">
                <span class="text-sm font-medium text-gray-300"><i class="fab fa-js mr-2 text-yellow-300"></i>JavaScript Files</span>
                <span class="badge ok">{{ value.js_files|length }}</span>
              </div>
              <details><summary class="text-blue-400 text-sm cursor-pointer">View files</summary>
                <ul class="list-disc pl-5 mt-2 text-sm max-h-40 overflow-y-auto">{% for js in value.js_files[:20] %}<li class="truncate"><a href="{{ js }}" target="_blank" class="hover:underline text-gray-300">{{ js }}</a></li>{% endfor %}</ul>
              </details>
            </div>
            {% endif %}
            
            <!-- API Endpoints -->
            {% if value.get('api_endpoints') %}
            <div class="bg-slate-800/40 rounded-lg p-3">
              <div class="flex justify-between items-center mb-2">
                <span class="text-sm font-medium text-gray-300"><i class="fas fa-code mr-2 text-cyan-400"></i>API Endpoints</span>
                <span class="badge sev-medium">{{ value.api_endpoints|length }}</span>
              </div>
              <details><summary class="text-blue-400 text-sm cursor-pointer">View endpoints</summary>
                <ul class="list-disc pl-5 mt-2 text-sm max-h-40 overflow-y-auto">{% for api in value.api_endpoints[:20] %}<li class="truncate text-gray-300">{{ api }}</li>{% endfor %}</ul>
              </details>
            </div>
            {% endif %}
            
            <!-- Social Media -->
            {% if value.get('social_media') %}
            <div class="bg-slate-800/40 rounded-lg p-3">
              <div class="flex justify-between items-center mb-2">
                <span class="text-sm font-medium text-gray-300"><i class="fas fa-share-nodes mr-2 text-pink-400"></i>Social Media</span>
                <span class="badge ok">{{ value.social_media|length }}</span>
              </div>
              <div class="flex flex-wrap gap-2">
                {% for sm in value.social_media[:10] %}
                <a href="{{ sm.url }}" target="_blank" class="text-xs bg-slate-700 px-2 py-1 rounded hover:bg-slate-600"><i class="fab fa-{{ sm.platform }} mr-1"></i>{{ sm.platform }}</a>
                {% endfor %}
              </div>
            </div>
            {% endif %}
            
            <!-- Suspicious Comments -->
            {% if value.get('comments') %}
            <div class="bg-slate-800/40 rounded-lg p-3 md:col-span-2">
              <div class="flex justify-between items-center mb-2">
                <span class="text-sm font-medium text-gray-300"><i class="fas fa-comment-dots mr-2 text-red-400"></i>Suspicious Comments</span>
                <span class="badge bad">{{ value.comments|length }}</span>
              </div>
              <div class="space-y-1">{% for c in value.comments[:5] %}<code class="block text-xs bg-slate-900/60 p-2 rounded text-red-300 overflow-x-auto">{{ c }}</code>{% endfor %}</div>
            </div>
            {% endif %}
          </div>


        {% elif key == 'http_headers' %}
          <table><thead><tr><th>Header</th><th>Value</th></tr></thead>
          <tbody>{% for k,v in value.items() %}<tr><td>{{ k }}</td><td>{{ v }}</td></tr>{% endfor %}</tbody></table>

        {% elif key == 'tech' and value.get('stack') %}
          <table><thead><tr><th>Technology</th></tr></thead>
          <tbody>{% for t in value.stack %}<tr><td>{{ t }}</td></tr>{% endfor %}</tbody></table>

        {% elif key == 'sec_headers' and value.get('rows') %}
          <table><thead><tr><th>Header</th><th>Status</th><th>Message</th></tr></thead>
          <tbody>{% for row in value.rows %}<tr><td>{{ row.header }}</td>
          <td><span class="badge {{ 'ok' if row.status == 'OK' else 'warn' if row.status == 'WARN' else 'bad' }}">{{ row.status }}</span></td>
          <td>{{ row.message }}</td></tr>{% endfor %}</tbody></table>

        {% elif key == 'tls' and value.get('subject') %}
          <table>
            <tr><th>Property</th><th>Value</th></tr>
            <tr><td>Subject</td><td>{{ value.subject.get('commonName', 'N/A') }}</td></tr>
            <tr><td>Issuer</td><td>{{ value.issuer.get('commonName', 'N/A') }}</td></tr>
            <tr><td>Valid From</td><td>{{ value.not_before }}</td></tr>
            <tr><td>Valid Until</td><td>{{ value.not_after }}</td></tr>
          </table>

        {% elif key == 'dns_records' %}
          <table><thead><tr><th>Type</th><th>Value</th></tr></thead>
          <tbody>
            {% for rtype, rvals in value.items() %}
              {% for rv in rvals %}<tr><td>{{ rtype }}</td><td><code>{{ rv }}</code></td></tr>{% endfor %}
            {% endfor %}
          </tbody></table>

        {% elif key == 'whois_lookup' %}
          <table><thead><tr><th>Property</th><th>Value</th></tr></thead>
          <tbody>
            {% for k, v in value.items() if k != 'error' and v %}
              <tr><td>{{ k|replace('_',' ')|title }}</td><td>{{ v }}</td></tr>
            {% endfor %}
          </tbody></table>

        {% elif key == 'subdomain_scan' and value.get('rows') %}
          <div class="mb-2">
            <a href="/export/subdomains.csv" class="bg-gray-700 hover:bg-gray-600 px-3 py-1 rounded text-sm">Export Subdomains CSV</a>
          </div>
          <table>
            <thead><tr><th>Subdomain</th><th>Source</th><th>A/AAAA</th><th>CNAME</th></tr></thead>
            <tbody>
              {% for r in value.rows[:500] %}
                <tr>
                  <td>{{ r.subdomain }}</td>
                  <td>{{ r.source }}</td>
                  <td>{{ (r.a_records or [])|join(', ') }}</td>
                  <td>{{ r.cname or '' }}</td>
                </tr>
              {% endfor %}
            </tbody>
          </table>

        {% elif key == 'subdomain_scan' and value.get('found') %}
          <div class="mb-2">
            <a href="/export/subdomains.csv" class="bg-gray-700 hover:bg-gray-600 px-3 py-1 rounded text-sm">Export Subdomains CSV</a>
          </div>
          <table><thead><tr><th>Found Subdomain</th></tr></thead>
          <tbody>{% for s in value.found %}<tr><td>{{ s }}</td></tr>{% endfor %}</tbody></table>

        {% elif key == 'securitytrails' %}
          <div class="grid md:grid-cols-2 gap-4">
            <div>
              <h3 class="text-sm font-semibold text-blue-300 mb-2">Current DNS</h3>
              {% set current = value.get('current') %}
              {% if current and not current.get('error') %}
                <pre class="bg-gray-800 border border-gray-700 rounded p-3 text-xs whitespace-pre-wrap">{{ current | tojson(indent=2) }}</pre>
              {% else %}
                <p class="text-sm text-gray-400">{{ current.get('error', 'No data') }}</p>
              {% endif %}
            </div>
            <div>
              <h3 class="text-sm font-semibold text-blue-300 mb-2">Passive DNS</h3>
              {% set history = value.get('history') %}
              {% if history and history is sequence %}
                <table>
                  <thead><tr><th>Hostname</th><th>IP</th><th>First Seen</th><th>Last Seen</th></tr></thead>
                  <tbody>
                    {% for rec in history[:10] %}
                      <tr>
                        <td>{{ rec.get('hostname', 'N/A') }}</td>
                        <td>{{ rec.get('value', 'N/A') }}</td>
                        <td>{{ rec.get('first_seen', '-') }}</td>
                        <td>{{ rec.get('last_seen', '-') }}</td>
                      </tr>
                    {% endfor %}
                  </tbody>
                </table>
              {% elif history and history.get('error') %}
                <p class="text-sm text-gray-400">{{ history.get('error') }}</p>
              {% else %}
                <p class="text-sm text-gray-400">No passive records returned.</p>
              {% endif %}
            </div>
          </div>

        {% elif key == 'security_txt' %}
          {% if value.get('found') and value.get('files') %}
            {% for file in value.files %}
              <p class="text-sm text-gray-400 mb-2">Discovered at <a href="{{ file.url }}" target="_blank" class="text-blue-400 hover:underline">{{ file.url }}</a> (HTTP {{ file.status }}){% if file.last_modified %} · updated {{ file.last_modified }}{% endif %}</p>
              <table>
                <thead><tr><th>Field</th><th>Value</th></tr></thead>
                <tbody>
                  {% for entry in file.entries %}
                    <tr><td>{{ entry.field }}</td><td>{{ entry.value }}</td></tr>
                  {% endfor %}
                </tbody>
              </table>
            {% endfor %}
          {% else %}
            <p class="text-gray-400 text-sm">{{ value.get('message', 'security.txt not discovered') }}</p>
          {% endif %}
          {% if value.get('errors') %}
            <details class="mt-3 text-sm text-gray-400">
              <summary class="cursor-pointer text-blue-400">Fetch errors</summary>
              <ul class="list-disc pl-5 mt-2 space-y-1">
                {% for err in value.errors %}
                  <li>{{ err.path }} → {{ err.error }}</li>
                {% endfor %}
              </ul>
            </details>
          {% endif %}

        {% elif key == 'robots_txt' %}
          <p class="text-sm text-gray-400 mb-2">Fetched from <a href="{{ value.get('url') }}" target="_blank" class="text-blue-400 hover:underline">{{ value.get('url') }}</a> (HTTP {{ value.get('status', '-') }}){% if value.get('last_modified') %} · updated {{ value.get('last_modified') }}{% endif %}</p>
          {% if value.get('rules') %}
            <table>
              <thead><tr><th>Directive</th><th>Path</th></tr></thead>
              <tbody>
                {% for rule in value.rules[:200] %}
                  <tr><td>{{ rule.directive }}</td><td><code>{{ rule.path }}</code></td></tr>
                {% endfor %}
              </tbody>
            </table>
          {% else %}
            <p class="text-gray-400 text-sm">No Allow/Disallow directives parsed.</p>
          {% endif %}
          {% if value.get('suspicious') %}
            <div class="mt-4">
              <h3 class="text-sm font-semibold text-red-300 mb-2">Potentially sensitive entries</h3>
              <table>
                <thead><tr><th>Directive</th><th>Path</th><th>Keyword</th></tr></thead>
                <tbody>
                  {% for rule in value.suspicious %}
                    <tr>
                      <td>{{ rule.directive }}</td>
                      <td>{{ rule.path }}</td>
                      <td><span class="badge bad">{{ rule.keyword }}</span></td>
                    </tr>
                  {% endfor %}
                </tbody>
              </table>
            </div>
          {% endif %}

        {% elif key == 'signature_hits' %}
          {% if value.get('rows') %}
            <table>
              <thead><tr><th>Signature</th><th>Severity</th></tr></thead>
              <tbody>
                {% for hit in value.rows %}
                  <tr>
                    <td>{{ hit.name }}</td>
                    <td><span class="badge {% if hit.severity == 'high' %}bad{% elif hit.severity == 'medium' %}warn{% else %}ok{% endif %}">{{ hit.severity|capitalize }}</span></td>
                  </tr>
                {% endfor %}
              </tbody>
            </table>
          {% else %}
            <p class="text-sm text-gray-400">No signatures matched.</p>
          {% endif %}

        {% elif key == 'cve_alerts' %}
          {% if value.get('rows') %}
            <table>
              <thead><tr><th>Tech</th><th>CVE</th><th>CVSS</th><th>Summary</th></tr></thead>
              <tbody>
                {% for alert in value.rows %}
                  <tr>
                    <td>{{ alert.tech }}</td>
                    <td>{{ alert.id }}</td>
                    <td>{{ alert.cvss or '-' }}</td>
                    <td>{{ alert.summary }}</td>
                  </tr>
                {% endfor %}
              </tbody>
            </table>
          {% else %}
            <p class="text-sm text-gray-400">No recent CVEs found for detected tech stack.</p>
          {% endif %}

        {% elif key == 'cloud_assets' %}
          {% if value.get('error') %}
            <p class="text-red-400 text-sm">{{ value.error }}</p>
          {% else %}
            <div>
              <h3 class="text-sm font-semibold mb-2">S3 Buckets</h3>
              {% if value.get('s3') %}
                <ul class="list-disc pl-5 text-sm space-y-1">
                  {% for bucket in value.s3 %}
                    <li>{{ bucket.name }} <span class="text-xs text-gray-400">{{ bucket.created }}</span></li>
                  {% endfor %}
                </ul>
              {% else %}
                <p class="text-sm text-gray-400">{{ value.get('message', 'No buckets matched domain keyword.') }}</p>
              {% endif %}
            </div>
          {% endif %}

        {% elif key == 'code_scan' %}
          {% if value.get('rows') %}
            <table>
              <thead><tr><th>Repository</th><th>File</th><th>Findings</th></tr></thead>
              <tbody>
                {% for row in value.rows %}
                  <tr>
                    <td>{{ row.repo }}</td>
                    <td><a href="{{ row.file }}" target="_blank" class="text-blue-400 hover:underline">View file</a></td>
                    <td>{{ row.findings|join(', ') }}</td>
                  </tr>
                {% endfor %}
              </tbody>
            </table>
          {% else %}
            <p class="text-sm text-gray-400">{{ value.get('message', 'No risky patterns detected in sampled files.') }}</p>
          {% endif %}

        {% elif key == 'fuzzer' %}
          {% if value.get('baseline') %}
            <p class="text-xs text-gray-400 mb-2">Baseline: status {{ value.baseline.status or 'N/A' }}, length {{ value.baseline.length or '-' }} bytes</p>
          {% endif %}
          <table>
            <thead><tr><th>Payload</th><th>Method</th><th>Status</th><th>Length</th><th>Severity</th><th>Redirected</th><th>Details</th></tr></thead>
            <tbody>
              {% for row in value.get('rows', []) %}
                <tr>
                  <td>{{ row.name }}</td>
                  <td>{{ row.method }}</td>
                  <td>{{ row.status or row.error }}</td>
                  <td>{{ row.length or '-' }}</td>
                  <td>
                    <span class="badge {% if row.severity == 'high' %}sev-high{% elif row.severity == 'medium' %}sev-medium{% else %}sev-low{% endif %}">
                      {{ row.severity|capitalize }}
                    </span>
                  </td>
                  <td>{{ row.redirected }}</td>
                  <td class="text-xs text-gray-400">
                    {% if row.description %}<div>{{ row.description }}</div>{% endif %}
                    {% if row.params %}<div>Params: {{ row.params }}</div>{% endif %}
                    {% if row.notes %}<div>Notes: {{ row.notes|join('; ') }}</div>{% endif %}
                    {% if row.error %}<div class="text-red-400">Error: {{ row.error }}</div>{% endif %}
                  </td>
                </tr>
              {% endfor %}
            </tbody>
          </table>

        {% elif key == 'workflow' %}
          {% if value.get('error') %}
            <p class="text-red-400 text-sm">{{ value.error }}</p>
          {% else %}
            <div class="space-y-2">
              <h3 class="text-sm font-semibold text-blue-300">Logs</h3>
              <ul class="list-disc pl-5 text-sm text-gray-300">
                {% for log in value.get('logs', []) %}
                  <li>{{ log }}</li>
                {% endfor %}
              </ul>
              {% if value.get('snapshot') %}
                <details>
                  <summary class="text-blue-400 cursor-pointer">HTML Snapshot</summary>
                  <pre class="bg-gray-800 border border-gray-700 rounded p-3 text-xs overflow-x-auto">{{ value.snapshot[:5000] }}{% if value.snapshot|length > 5000 %}...{% endif %}</pre>
                </details>
              {% endif %}
            </div>
          {% endif %}

        {% elif key == 'sandbox_report' %}
          {% if value.get('error') %}
            <p class="text-red-400 text-sm">{{ value.error }}</p>
          {% else %}
            <pre class="bg-gray-800 border border-gray-700 rounded p-3 text-xs whitespace-pre-wrap">{{ value | tojson(indent=2) }}</pre>
          {% endif %}

        {% elif key == 'owasp_top10' %}
          <table>
            <thead><tr><th>Category</th><th>Status</th><th>Evidence</th></tr></thead>
            <tbody>
              {% for row in value.get('rows', []) %}
                <tr>
                  <td>{{ row.category }}</td>
                  <td>
                    {% set badge_class = 'ok' %}
                    {% if row.status == 'fail' %}
                      {% set badge_class = 'bad' %}
                    {% elif row.status == 'warn' %}
                      {% set badge_class = 'warn' %}
                    {% elif row.status == 'unknown' %}
                      {% set badge_class = 'warn' %}
                    {% endif %}
                    <span class="badge {{ badge_class }}">
                      {{ row.status|upper }}
                    </span>
                  </td>
                  <td>{{ row.evidence }}</td>
                </tr>
              {% endfor %}
            </tbody>
          </table>

        {% elif key == 'virustotal' and value.get('data', {}).get('attributes') %}
          {% set stats = value.get('data', {}).get('attributes', {}).get('last_analysis_stats', {}) %}
          <table>
            <tr><th>Malicious</th><th>Suspicious</th><th>Harmless</th></tr>
            <tr><td><span class="badge bad">{{ stats.get('malicious', 0) }}</span></td>
                <td><span class="badge warn">{{ stats.get('suspicious', 0) }}</span></td>
                <td><span class="badge ok">{{ stats.get('harmless', 0) }}</span></td></tr>
          </table>

        {% elif key == 'urlscan' and value.get('results') %}
          <table><thead><tr><th>Domain</th><th>Scan Time</th><th>Link</th></tr></thead>
          <tbody>
            {% for r in value.results[:5] %}
              <tr>
                <td>{{ r.get('task', {}).get('domain', 'N/A') }}</td>
                <td>{{ r.get('task', {}).get('time', '') | replace('T',' ') | replace('Z','') }}</td>
                <td><a href="{{ r.get('result', '#') }}" target="_blank" class="text-blue-400 hover:underline">View Scan</a></td>
              </tr>
            {% endfor %}
          </tbody></table>

        {% elif key == 'otx' and value.get('general') %}
          <table>
            <tr><th>Property</th><th>Value</th></tr>
            <tr><td>Pulse Count</td><td>{{ value.get('general', {}).get('pulse_info', {}).get('count', 'N/A') }}</td></tr>
            {% set validation_list = value.get('validation', []) %}
            {% set validation_msg = 'N/A' %}
            {% if validation_list and validation_list[0] is mapping %}
              {% set validation_msg = validation_list[0].get('message', 'N/A') %}
            {% endif %}
            <tr><td>Validation</td><td>{{ validation_msg }}</td></tr>
          </table>

        {% elif key == 'github' and value.get('items') %}
          <table><thead><tr><th>Repository</th><th>Path</th><th>Link</th></tr></thead>
          <tbody>
            {% for item in value.get('items', [])[:5] %}
              <tr>
                <td>{{ item.get('repository', {}).get('full_name', 'N/A') }}</td>
                <td>{{ item.get('path', 'N/A') }}</td>
                <td><a href="{{ item.get('html_url', '#') }}" target="_blank" class="text-blue-400 hover:underline">View Code</a></td>
              </tr>
            {% endfor %}
          </tbody></table>

        {% elif key == 'archive_org' and value is sequence and value|length > 1 %}
          <table><thead><tr><th>Timestamp</th><th>Original URL</th><th>MIME</th><th>Status</th><th>Link</th></tr></thead>
          <tbody>
            {% for row in value[1:11] %}
              <tr>
                <td>{{ row[1] }}</td>
                <td>{{ row[2] }}</td>
                <td>{{ row[3] }}</td>
                <td>{{ row[4] }}</td>
                <td><a target="_blank" class="text-blue-400 hover:underline" href="https://web.archive.org/web/{{ row[1] }}/{{ row[2] }}">Open</a></td>
              </tr>
            {% endfor %}
          </tbody></table>

        {% elif key == 'shodan' and value.get('data') %}
          <table><thead><tr><th>IP</th><th>Org</th><th>Open Ports</th><th>Hostnames</th><th>Tags</th></tr></thead>
          <tbody>
            <tr>
              <td>{{ value.get('ip_str', 'N/A') }}</td>
              <td>{{ value.get('org', 'N/A') }}</td>
              <td>{{ value.get('ports', [])|join(', ') }}</td>
              <td>{{ value.get('hostnames', [])|join(', ') }}</td>
              <td>{{ value.get('tags', [])|join(', ') }}</td>
            </tr>
          </tbody></table>

        {% elif key == 'greynoise' and (value.get('ip') or value.get('classification')) %}
          <table>
            <tr><th>IP</th><td>{{ value.get('ip', 'N/A') }}</td></tr>
            <tr><th>Classification</th><td>{{ value.get('classification', 'unknown') }}</td></tr>
            <tr><th>Name</th><td>{{ value.get('name', 'N/A') }}</td></tr>
            <tr><th>Last Seen</th><td>{{ value.get('last_seen', 'N/A') }}</td></tr>
          </table>

        {% elif key == 'abuseipdb' and value.get('data') %}
          {% set d = value.get('data', {}) %}
          <table>
            <tr><th>IP</th><td>{{ d.get('ipAddress', 'N/A') }}</td></tr>
            <tr><th>Total Reports</th><td>{{ d.get('totalReports', 0) }}</td></tr>
            <tr><th>Abuse Confidence</th><td>{{ d.get('abuseConfidenceScore', 0) }}%</td></tr>
            <tr><th>Last Reported</th><td>{{ d.get('lastReportedAt', 'N/A') }}</td></tr>
            <tr><th>Country</th><td>{{ d.get('countryCode', 'N/A') }}</td></tr>
            <tr><th>Usage Type</th><td>{{ d.get('usageType', 'N/A') }}</td></tr>
            <tr><th>ISP</th><td>{{ d.get('isp', 'N/A') }}</td></tr>
          </table>

        {% elif key == 'screenshot' %}
          {% if value.get('data_uri') %}
            <img src="{{ value.data_uri }}" alt="Screenshot" class="w-full border border-gray-700 rounded-lg" />
          {% else %}
            <p class="text-sm text-gray-400">{{ value.get('error', 'Screenshot capture unavailable.') }}</p>
          {% endif %}

        {% elif key == 'exposure_checks' and value.get('rows') %}
          <table>
            <thead><tr><th>Path</th><th>Severity</th><th>Status</th><th>Length</th><th>Details</th></tr></thead>
            <tbody>
              {% for row in value.rows %}
                <tr>
                  <td><a href="{{ row.url }}" target="_blank" class="text-blue-400 hover:underline">{{ row.path }}</a></td>
                  <td>
                    <span class="badge {% if row.severity == 'high' %}sev-high{% elif row.severity == 'medium' %}sev-medium{% else %}sev-low{% endif %}">
                      {{ row.severity|capitalize }}
                    </span>
                  </td>
                  <td>{{ row.status }}</td>
                  <td>{{ row.length or '-' }}</td>
                  <td>
                    <div>{{ row.description }}</div>
                    {% if row.content_type %}<div class="text-xs text-gray-400">Type: {{ row.content_type }}</div>{% endif %}
                    {% if row.error %}<div class="text-xs text-red-400">Error: {{ row.error }}</div>{% endif %}
                  </td>
                </tr>
              {% endfor %}
            </tbody>
          </table>

        {% elif key == 'hibp' and value.get('rows') %}
          <table>
            <thead><tr><th>Email</th><th>Status</th><th>Breaches</th></tr></thead>
            <tbody>
              {% for row in value.rows %}
                <tr>
                  <td>{{ row.email }}</td>
                  <td>
                    {% if row.error %}
                      <span class="badge bad">Error</span>
                    {% elif row.breached %}
                      <span class="badge bad">Breached</span>
                    {% else %}
                      <span class="badge ok">Clear</span>
                    {% endif %}
                  </td>
                  <td>
                    {% if row.error %}
                      <span class="text-red-400 text-sm">{{ row.error }}</span>
                    {% elif row.breaches %}
                      {{ row.breaches|join(', ') }}
                    {% else %}
                      <span class="text-gray-400 text-sm">No hits</span>
                    {% endif %}
                  </td>
                </tr>
              {% endfor %}
            </tbody>
          </table>

        {% elif key == 'waf_detect' %}
          {% if value.get('error') %}
            <p class="text-red-400 text-sm">{{ value.error }}</p>
          {% else %}
            <table>
              <tr><th>WAF/CDN Detected</th><td>
                {% if value.get('detected') %}
                  {% for waf in value.detected %}<span class="badge warn mr-1">{{ waf }}</span>{% endfor %}
                {% else %}<span class="badge ok">None Detected</span>{% endif %}
              </td></tr>
              <tr><th>Confidence</th><td>{{ value.get('confidence', 'N/A') }}</td></tr>
              <tr><th>Protected</th><td>{{ 'Yes' if value.get('likely_protected') else 'No' }}</td></tr>
            </table>
            {% if value.get('headers_evidence') %}
              <div class="mt-2"><p class="text-xs text-gray-400 mb-1">Header Evidence:</p>
                <ul class="text-xs text-gray-300 list-disc pl-5">
                  {% for h in value.headers_evidence %}<li>{{ h }}</li>{% endfor %}
                </ul>
              </div>
            {% endif %}
          {% endif %}

        {% elif key == 'email_security' %}
          {% if value.get('error') %}
            <p class="text-red-400 text-sm">{{ value.error }}</p>
          {% else %}
            <div class="flex items-center gap-4 mb-3">
              <div class="text-3xl font-bold {% if value.get('grade') == 'A' %}text-green-400{% elif value.get('grade') == 'B' %}text-blue-400{% elif value.get('grade') == 'C' %}text-yellow-400{% else %}text-red-400{% endif %}">
                Grade: {{ value.get('grade', 'N/A') }}
              </div>
              <div class="text-sm text-gray-400">Score: {{ value.get('score', 0) }}/100</div>
            </div>
            <table>
              <tr><th>SPF</th><td>
                {% if value.get('spf', {}).get('found') %}<span class="badge ok">Found</span> <span class="text-xs ml-2">{{ value.spf.get('policy', '') }}</span>
                {% else %}<span class="badge bad">Missing</span>{% endif %}
              </td></tr>
              <tr><th>DMARC</th><td>
                {% if value.get('dmarc', {}).get('found') %}<span class="badge ok">Found</span> <span class="text-xs ml-2">Policy: {{ value.dmarc.get('policy', 'none') }}</span>
                {% else %}<span class="badge bad">Missing</span>{% endif %}
              </td></tr>
              <tr><th>DKIM</th><td>
                {% if value.get('dkim', {}).get('found') %}<span class="badge ok">Found</span> <span class="text-xs ml-2">{{ value.dkim.get('selectors', [])|length }} selector(s)</span>
                {% else %}<span class="badge warn">Not Found</span>{% endif %}
              </td></tr>
            </table>
            {% if value.get('recommendations') %}
              <div class="mt-2 text-sm text-yellow-300"><i class="fas fa-exclamation-triangle mr-1"></i>Recommendations:
                <ul class="list-disc pl-5">{% for r in value.recommendations %}<li>{{ r }}</li>{% endfor %}</ul>
              </div>
            {% endif %}
          {% endif %}

        {% elif key == 'port_scan' %}
          {% if value.get('error') %}
            <p class="text-red-400 text-sm">{{ value.error }}</p>
          {% else %}
            <p class="text-sm text-gray-400 mb-2">Target IP: {{ value.get('target_ip', 'N/A') }} | Open Ports: {{ value.get('open_count', 0) }}</p>
            {% if value.get('risk_ports') %}
              <div class="mb-2 text-yellow-300 text-sm"><i class="fas fa-exclamation-triangle mr-1"></i>Risk Ports Found: {{ value.risk_ports|length }}</div>
            {% endif %}
            <table>
              <thead><tr><th>Port</th><th>State</th><th>Service</th></tr></thead>
              <tbody>
                {% for p in value.get('open_ports', []) %}
                  <tr>
                    <td>{{ p.port }}</td>
                    <td><span class="badge {% if p.port in [21,22,23,3389,445,5900] %}warn{% else %}ok{% endif %}">{{ p.state }}</span></td>
                    <td>{{ p.service }}</td>
                  </tr>
                {% endfor %}
              </tbody>
            </table>
          {% endif %}

        {% elif key == 'asn_lookup' %}
          {% if value.get('error') %}
            <p class="text-red-400 text-sm">{{ value.error }}</p>
          {% else %}
            <table>
              <tr><th>IP Address</th><td>{{ value.get('ip', 'N/A') }}</td></tr>
              <tr><th>ASN</th><td>{{ value.get('asn', 'N/A') }}</td></tr>
              <tr><th>Prefix (CIDR)</th><td>{{ value.get('prefix', 'N/A') }}</td></tr>
              <tr><th>Country</th><td>{{ value.get('country', 'N/A') }}</td></tr>
              <tr><th>Organization</th><td>{{ value.get('org_name', 'N/A') }}</td></tr>
            </table>
          {% endif %}

        {% elif key == 'favicon_hash' %}
          {% if value.get('found') %}
            <table>
              <tr><th>Favicon URL</th><td><a href="{{ value.get('url', '#') }}" target="_blank" class="text-blue-400 hover:underline">{{ value.get('url', 'N/A') }}</a></td></tr>
              <tr><th>Size</th><td>{{ value.get('size_bytes', 0) }} bytes</td></tr>
              <tr><th>MD5 Hash</th><td class="font-mono text-xs">{{ value.get('md5', 'N/A') }}</td></tr>
              <tr><th>MMH3 Hash</th><td class="font-mono text-xs">{{ value.get('mmh3_hash', 'N/A') }}</td></tr>
              {% if value.get('shodan_query') %}
                <tr><th>Shodan Query</th><td><code class="text-xs bg-gray-700 px-2 py-1 rounded">{{ value.shodan_query }}</code></td></tr>
              {% endif %}
            </table>
          {% else %}
            <p class="text-gray-400 text-sm">No favicon found.</p>
          {% endif %}

        {% elif key == 'ssl_tls' %}
          {% if value.get('error') %}
            <p class="text-red-400 text-sm">{{ value.error }}</p>
          {% else %}
            <div class="flex items-center gap-4 mb-4">
              <div class="text-4xl font-bold {% if value.get('grade') == 'A' %}text-green-400{% elif value.get('grade') == 'B' %}text-blue-400{% elif value.get('grade') == 'C' %}text-yellow-400{% else %}text-red-400{% endif %}">
                {{ value.get('grade', 'F') }}
              </div>
              <div>
                <div class="text-sm text-gray-400">SSL/TLS Score: {{ value.get('score', 0) }}/100</div>
                <div class="text-sm text-gray-300">Protocol: {{ value.get('protocol', 'Unknown') }}</div>
              </div>
            </div>
            <table>
              <tr><th>Cipher Suite</th><td class="font-mono text-xs">{{ value.get('cipher_suite', 'N/A') }}</td></tr>
              <tr><th>Certificate Subject</th><td>{{ value.get('certificate', {}).get('subject', {}).get('commonName', 'N/A') }}</td></tr>
              <tr><th>Issuer</th><td>{{ value.get('certificate', {}).get('issuer', {}).get('organizationName', 'N/A') }}</td></tr>
              <tr><th>Valid Until</th><td>{{ value.get('certificate', {}).get('not_after', 'N/A') }}</td></tr>
              <tr><th>Days Until Expiry</th><td>{{ value.get('certificate', {}).get('days_until_expiry', 'N/A') }}</td></tr>
            </table>
            {% if value.get('issues') %}
            <div class="mt-3 text-sm text-yellow-300"><i class="fas fa-exclamation-triangle mr-1"></i>Issues:
              <ul class="list-disc pl-5">{% for i in value.issues %}<li>{{ i }}</li>{% endfor %}</ul>
            </div>
            {% endif %}
          {% endif %}

        {% elif key == 'subdomain_takeover' %}
          {% if value.get('vulnerable') %}
            <div class="mb-3 text-red-400"><i class="fas fa-skull-crossbones mr-2"></i>VULNERABLE: {{ value.vulnerable|length }} takeover(s) possible!</div>
            <table>
              <thead><tr><th>Subdomain</th><th>CNAME</th><th>Service</th><th>Fingerprint</th></tr></thead>
              <tbody>{% for v in value.vulnerable %}
                <tr>
                  <td>{{ v.subdomain }}</td>
                  <td class="font-mono text-xs">{{ v.cname }}</td>
                  <td><span class="badge bad">{{ v.service }}</span></td>
                  <td class="text-xs">{{ v.fingerprint }}</td>
                </tr>
              {% endfor %}</tbody>
            </table>
          {% else %}
            <p class="text-green-400 text-sm"><i class="fas fa-check mr-1"></i>No subdomain takeover vulnerabilities detected.</p>
            {% if value.get('cname_records') %}<p class="text-xs text-gray-400 mt-2">CNAME records checked: {{ value.cname_records|join(', ') }}</p>{% endif %}
          {% endif %}

        {% elif key == 'http_methods' %}
          <div class="grid md:grid-cols-2 gap-4">
            <div class="bg-slate-800/40 rounded-lg p-3">
              <div class="text-sm font-medium text-gray-300 mb-2">Allowed Methods</div>
              <div class="flex flex-wrap gap-2">
                {% for m in value.get('allowed', []) %}<span class="badge ok">{{ m }}</span>{% endfor %}
              </div>
            </div>
            {% if value.get('dangerous') %}
            <div class="bg-slate-800/40 rounded-lg p-3">
              <div class="text-sm font-medium text-red-400 mb-2"><i class="fas fa-exclamation-triangle mr-1"></i>Dangerous Methods</div>
              {% for d in value.dangerous %}
                <div class="flex items-center gap-2 mb-1">
                  <span class="badge bad">{{ d.method }}</span>
                  <span class="text-xs text-gray-400">Status: {{ d.status }}</span>
                </div>
              {% endfor %}
            </div>
            {% endif %}
          </div>

        {% elif key == 'cors' %}
          {% if value.get('vulnerable') %}
            <div class="mb-3 text-red-400"><i class="fas fa-link-slash mr-2"></i>CORS Misconfiguration Detected!</div>
            <ul class="list-disc pl-5 text-sm text-red-300">{% for i in value.get('issues', []) %}<li>{{ i }}</li>{% endfor %}</ul>
            {% if value.get('headers') %}
            <table class="mt-3">
              {% for k, v in value.headers.items() %}<tr><th>{{ k }}</th><td class="font-mono text-xs">{{ v }}</td></tr>{% endfor %}
            </table>
            {% endif %}
          {% else %}
            <p class="text-green-400 text-sm"><i class="fas fa-check mr-1"></i>No CORS misconfigurations detected.</p>
          {% endif %}

        {% elif key == 'cookie_audit' %}
          <div class="flex items-center gap-4 mb-4">
            <div class="text-2xl font-bold {% if value.get('score', 0) >= 80 %}text-green-400{% elif value.get('score', 0) >= 50 %}text-yellow-400{% else %}text-red-400{% endif %}">
              {{ value.get('score', 0) }}/100
            </div>
            <span class="text-sm text-gray-400">Cookie Security Score</span>
          </div>
          {% if value.get('cookies') %}
          <table>
            <thead><tr><th>Cookie</th><th>Secure</th><th>HttpOnly</th><th>SameSite</th><th>Issues</th></tr></thead>
            <tbody>{% for c in value.cookies %}
              <tr>
                <td class="font-mono text-xs">{{ c.name }}</td>
                <td><span class="badge {% if c.secure %}ok{% else %}bad{% endif %}">{{ 'Yes' if c.secure else 'No' }}</span></td>
                <td><span class="badge {% if c.httponly %}ok{% else %}bad{% endif %}">{{ 'Yes' if c.httponly else 'No' }}</span></td>
                <td>{{ c.samesite or 'None' }}</td>
                <td class="text-xs text-red-300">{{ c.issues|join(', ') }}</td>
              </tr>
            {% endfor %}</tbody>
          </table>
          {% else %}<p class="text-gray-400 text-sm">No cookies found.</p>{% endif %}

        {% elif key == 'js_secrets' %}
          <p class="text-sm text-gray-400 mb-3">JS files scanned: {{ value.get('js_files_scanned', 0) }}</p>
          {% if value.get('secrets_found') %}
            <div class="text-red-400 mb-2"><i class="fas fa-key mr-1"></i>{{ value.secrets_found|length }} secrets found!</div>
            <table>
              <thead><tr><th>Type</th><th>Value</th><th>Severity</th></tr></thead>
              <tbody>{% for s in value.secrets_found %}
                <tr>
                  <td>{{ s.type }}</td>
                  <td class="font-mono text-xs max-w-xs truncate">{{ s.value }}</td>
                  <td><span class="badge {% if s.severity == 'critical' %}bad{% else %}sev-high{% endif %}">{{ s.severity }}</span></td>
                </tr>
              {% endfor %}</tbody>
            </table>
          {% else %}
            <p class="text-green-400 text-sm"><i class="fas fa-check mr-1"></i>No exposed secrets detected.</p>
          {% endif %}

        {% elif key == 'mitre_attack' %}
          {% if value.get('findings') %}
            <div class="text-sm text-gray-400 mb-3">{{ value.count }} findings mapped to MITRE ATT&CK</div>
            <table>
              <thead><tr><th>Technique</th><th>Tactic</th><th>Name</th><th>Evidence</th></tr></thead>
              <tbody>{% for f in value.findings %}
                <tr>
                  <td><span class="badge warn">{{ f.technique }}</span></td>
                  <td>{{ f.tactic }}</td>
                  <td>{{ f.name }}</td>
                  <td class="text-xs text-gray-400">{{ f.evidence }}</td>
                </tr>
              {% endfor %}</tbody>
            </table>
          {% else %}
            <p class="text-green-400 text-sm"><i class="fas fa-check mr-1"></i>No findings mapped to MITRE ATT&CK techniques.</p>
          {% endif %}

        {% else %}
          <p class="text-gray-400 text-sm">No structured data available.</p>
        {% endif %}
      </div>
      {% endfor %}
    </div>

    <!-- JSON View -->
    <div id="jsonView" class="{% if view_mode != 'json' %}hidden{% endif %}">
      <pre class="bg-gray-800 border border-gray-700 rounded-lg p-4 overflow-x-auto text-sm whitespace-pre-wrap">{{ results | tojson(indent=2) }}</pre>
    </div>

    <div class="text-center mt-8 flex items-center justify-center gap-4">
      <a href="/export/report" class="inline-block bg-gray-700 hover:bg-gray-600 px-6 py-3 rounded-full font-bold text-white"><i class="fas fa-file-alt mr-2"></i>Export Report</a>
      <a href="/" class="inline-block bg-blue-600 hover:bg-blue-500 px-6 py-3 rounded-full font-bold text-white"><i class="fas fa-arrow-left mr-2"></i>New Hunt</a>
    </div>
  </div>

  <script>
    const humanBtn = document.getElementById('btnHuman');
    const jsonBtn = document.getElementById('btnJSON');
    const humanView = document.getElementById('humanView');
    const jsonView = document.getElementById('jsonView');
    humanBtn.addEventListener('click', () => {
      humanView.classList.remove('hidden');
      jsonView.classList.add('hidden');
      humanBtn.classList.add('bg-blue-600','text-white');
      jsonBtn.classList.remove('bg-blue-600','text-white');
    });
    jsonBtn.addEventListener('click', () => {
      jsonView.classList.remove('hidden');
      humanView.classList.add('hidden');
      jsonBtn.classList.add('bg-blue-600','text-white');
      humanBtn.classList.remove('bg-blue-600','text-white');
    });

    // Filter + expand/collapse
    const filterInput = document.getElementById('resultFilter');
    const cards = () => Array.from(document.querySelectorAll('.result-card'));
    if (filterInput) {
      filterInput.addEventListener('input', () => {
        const q = filterInput.value.toLowerCase();
        cards().forEach(c => {
          const text = c.innerText.toLowerCase();
          c.style.display = text.includes(q) ? '' : 'none';
        });
      });
    }
    const btnExpandAll = document.getElementById('btnExpandAll');
    const btnCollapseAll = document.getElementById('btnCollapseAll');
    if (btnExpandAll) btnExpandAll.addEventListener('click', () => document.querySelectorAll('details').forEach(d => d.open = true));
    if (btnCollapseAll) btnCollapseAll.addEventListener('click', () => document.querySelectorAll('details').forEach(d => d.open = false));
  </script>
</body>
</html>
"""

HISTORY_HTML = r"""
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>AEGIS — Scan History</title>
  <script src="https://cdn.tailwindcss.com"></script>
  <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css" rel="stylesheet">
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">
  <style>
    * { font-family: 'Inter', sans-serif; }
    .bg-animated { background: linear-gradient(-45deg, #0f0f23, #1a1a3e, #0d1b2a, #1b263b); background-size: 400% 400%; animation: gradientShift 15s ease infinite; }
    @keyframes gradientShift { 0% { background-position: 0% 50%; } 50% { background-position: 100% 50%; } 100% { background-position: 0% 50%; } }
    .glass-card { background: rgba(30, 41, 59, 0.7); backdrop-filter: blur(12px); border: 1px solid rgba(148, 163, 184, 0.1); border-radius: 1rem; transition: all 0.3s ease; }
    .glass-card:hover { background: rgba(30, 41, 59, 0.85); border-color: rgba(96, 165, 250, 0.3); box-shadow: 0 8px 32px rgba(0, 0, 0, 0.3); transform: translateY(-2px); }
    .scan-row { background: rgba(30, 41, 59, 0.5); border: 1px solid rgba(148, 163, 184, 0.1); border-radius: 0.75rem; transition: all 0.2s ease; }
    .scan-row:hover { border-color: rgba(96, 165, 250, 0.4); background: rgba(30, 41, 59, 0.7); }
    .btn { display: inline-flex; align-items: center; gap: 0.5rem; padding: 0.6rem 1.25rem; border-radius: 0.75rem; font-weight: 500; font-size: 0.85rem; transition: all 0.2s ease; }
    .btn-primary { background: linear-gradient(135deg, #3b82f6, #2563eb); color: white; }
    .btn-primary:hover { background: linear-gradient(135deg, #60a5fa, #3b82f6); transform: translateY(-1px); box-shadow: 0 4px 12px rgba(59, 130, 246, 0.4); }
    .stat-card { background: linear-gradient(135deg, rgba(30, 41, 59, 0.8) 0%, rgba(30, 41, 59, 0.4) 100%); border: 1px solid rgba(148, 163, 184, 0.15); border-radius: 1rem; padding: 1.25rem; position: relative; overflow: hidden; }
    .stat-card::before { content: ''; position: absolute; top: 0; left: 0; width: 100%; height: 3px; background: linear-gradient(90deg, var(--accent-color, #3b82f6), transparent); }
  </style>
</head>
<body class="bg-animated text-gray-200 min-h-screen">
  <div class="container mx-auto p-4 md:p-8">
    <!-- Header -->
    <div class="flex flex-wrap items-center justify-between gap-4 mb-8">
      <div class="flex items-center gap-4">
        <div class="w-12 h-12 rounded-xl bg-gradient-to-br from-blue-500 to-purple-600 flex items-center justify-center">
          <i class="fas fa-clock-rotate-left text-white text-xl"></i>
        </div>
        <div>
          <h1 class="text-3xl font-bold bg-gradient-to-r from-blue-400 to-purple-400 bg-clip-text text-transparent">Scan History</h1>
          <p class="text-gray-400 text-sm">Browse and compare previous threat hunts</p>
        </div>
      </div>
      <div class="flex gap-3">
        <a href="/scheduled" class="btn" style="background: rgba(51, 65, 85, 0.7); border: 1px solid rgba(148, 163, 184, 0.2);"><i class="fas fa-calendar"></i> Scheduled</a>
        <a href="/" class="btn btn-primary"><i class="fas fa-plus"></i> New Scan</a>
      </div>
    </div>

    <!-- Stats -->
    <div class="grid grid-cols-2 md:grid-cols-4 gap-4 mb-8">
      <div class="stat-card" style="--accent-color: #3b82f6;">
        <div class="text-xs text-gray-400 mb-1">Total Scans</div>
        <div class="text-2xl font-bold text-blue-400">{{ items|length }}</div>
      </div>
      <div class="stat-card" style="--accent-color: #10b981;">
        <div class="text-xs text-gray-400 mb-1">This Week</div>
        <div class="text-2xl font-bold text-green-400">{{ items[:7]|length }}</div>
      </div>
      <div class="stat-card" style="--accent-color: #f59e0b;">
        <div class="text-xs text-gray-400 mb-1">Unique Targets</div>
        <div class="text-2xl font-bold text-yellow-400">{{ items|map(attribute='url')|list|unique|list|length if items else 0 }}</div>
      </div>
      <div class="stat-card" style="--accent-color: #8b5cf6;">
        <div class="text-xs text-gray-400 mb-1">Latest Scan</div>
        <div class="text-sm font-bold text-purple-400 truncate">{{ items[0]['scan_date'][:10] if items else 'None' }}</div>
      </div>
    </div>

    <!-- Search -->
    <div class="glass-card p-4 mb-6">
      <div class="flex flex-wrap gap-4 items-center">
        <div class="flex-1 min-w-[250px]">
          <div class="relative">
            <i class="fas fa-search absolute left-4 top-1/2 -translate-y-1/2 text-gray-500"></i>
            <input id="histFilter" type="text" placeholder="Search by URL, date, or ID..."
                   class="w-full pl-11 pr-4 py-3 rounded-xl bg-slate-800/60 border border-slate-700/50 text-sm focus:outline-none focus:border-blue-500/50 focus:ring-2 focus:ring-blue-500/20 transition-all">
          </div>
        </div>
        <div class="text-sm text-gray-400">
          <span id="resultCount">{{ items|length }}</span> scans found
        </div>
      </div>
    </div>

    <!-- Scan List -->
    <div id="scanList" class="space-y-3">
      {% for it in items %}
      <div class="scan-row p-4 flex flex-wrap items-center justify-between gap-4" data-search="{{ it['url'] }} {{ it['scan_date'] }} {{ it['id'] }}">
        <div class="flex items-center gap-4">
          <div class="w-10 h-10 rounded-lg bg-blue-500/20 flex items-center justify-center text-blue-400">
            <i class="fas fa-globe"></i>
          </div>
          <div>
            <div class="font-medium text-white truncate max-w-[400px]">{{ it['url'] }}</div>
            <div class="text-xs text-gray-400 flex items-center gap-3 mt-1">
              <span><i class="fas fa-hashtag mr-1"></i>{{ it['id'] }}</span>
              <span><i class="fas fa-calendar mr-1"></i>{{ it['scan_date'] }}</span>
            </div>
          </div>
        </div>
        <div class="flex gap-2">
          <a href="/view/{{ it['id'] }}" class="btn btn-primary text-sm py-2"><i class="fas fa-eye"></i> View</a>
          <a href="/graph/{{ it['id'] }}" class="btn text-sm py-2" style="background: rgba(51, 65, 85, 0.7); border: 1px solid rgba(148, 163, 184, 0.2);"><i class="fas fa-diagram-project"></i></a>
        </div>
      </div>
      {% endfor %}
      {% if not items %}
      <div class="glass-card p-12 text-center">
        <i class="fas fa-inbox text-4xl text-gray-600 mb-4"></i>
        <p class="text-gray-400">No scans yet. Start your first threat hunt!</p>
        <a href="/" class="btn btn-primary mt-4"><i class="fas fa-rocket"></i> Start Scanning</a>
      </div>
      {% endif %}
    </div>
  </div>

  <script>
    const input = document.getElementById('histFilter');
    const rows = Array.from(document.querySelectorAll('.scan-row'));
    const countEl = document.getElementById('resultCount');
    input.addEventListener('input', () => {
      const q = input.value.toLowerCase();
      let visible = 0;
      rows.forEach(r => {
        const match = r.dataset.search.toLowerCase().includes(q);
        r.style.display = match ? '' : 'none';
        if (match) visible++;
      });
      countEl.textContent = visible;
    });
  </script>
</body>
</html>
"""


GRAPH_HTML = r"""
<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>Relationship Graph</title>
  <script type="text/javascript" src="https://unpkg.com/vis-network@9.1.2/dist/vis-network.min.js"></script>
  <link rel="stylesheet" href="https://unpkg.com/vis-network@9.1.2/dist/vis-network.min.css">
  <style>
    body { background:#0f172a; color:#e2e8f0; font-family:system-ui, sans-serif; }
    #network { width: 100%; height: 85vh; border: 1px solid #1e293b; border-radius: 0.5rem; background:#0f172a; }
    .panel { max-width: 1200px; margin: 2rem auto; }
    a { color:#60a5fa; }
  </style>
</head>
<body>
  <div class="panel">
    <h1>Graph for scan {{ scan_id }}</h1>
    <p>Nodes sized by type; drag to explore. <a href="/">Back</a></p>
    <div id="network"></div>
  </div>
  <script>
    const nodes = new vis.DataSet({{ nodes | tojson }});
    const edges = new vis.DataSet({{ edges | tojson }});
    new vis.Network(document.getElementById('network'), { nodes, edges }, {
      nodes: { font: { color: '#e2e8f0' }, borderWidth: 1 },
      edges: { color: '#64748b' },
      physics: { stabilization: true }
    });
  </script>
</body>
</html>
"""

REPORT_HTML = r"""
<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>AEGIS Scan Report</title>
  <style>
    body { font-family: "Segoe UI", Arial, sans-serif; margin: 0; padding: 0; background:#0f172a; color:#e2e8f0; }
    .wrapper { max-width: 960px; margin: 0 auto; padding: 40px 30px; }
    h1, h2, h3 { color:#60a5fa; margin-bottom: 10px; }
    .cards { display:flex; flex-wrap:wrap; gap:16px; margin-bottom:24px; }
    .card { flex:1 1 200px; background:#1f2937; border:1px solid #334155; border-radius:8px; padding:16px; }
    .card .label { font-size:12px; text-transform:uppercase; letter-spacing:1px; color:#94a3b8; }
    .card .value { font-size:24px; font-weight:bold; margin-top:8px; }
    table { width:100%; border-collapse:collapse; margin-bottom:24px; }
    th, td { padding:10px 12px; border:1px solid #334155; text-align:left; font-size:14px; }
    th { background:#1e293b; color:#e2e8f0; }
    .badge { display:inline-block; padding:2px 10px; border-radius:999px; font-size:12px; font-weight:600; color:#0f172a; }
    .badge.ok { background:#22c55e; }
    .badge.warn { background:#f97316; }
    .badge.bad { background:#ef4444; }
    .section { margin-bottom:32px; }
    .meta { font-size:14px; color:#94a3b8; margin-bottom:24px; }
  </style>
</head>
<body>
  <div class="wrapper">
    <h1>AEGIS Scan Report</h1>
    <div class="meta">
      Target: <strong>{{ url }}</strong><br>
      Generated: {{ generated }}<br>
      Risk Level: {{ summary.get('risk_level', 'n/a') }} (Score: {{ summary.get('risk_score', 0) }})
    </div>

    <div class="cards">
      <div class="card">
        <div class="label">Duration (s)</div>
        <div class="value">{{ meta.get('total_seconds', '-') }}</div>
      </div>
      <div class="card">
        <div class="label">Subdomains</div>
        <div class="value">{{ summary.get('subdomains', 0) }}</div>
      </div>
      <div class="card">
        <div class="label">Missing Sec Headers</div>
        <div class="value">{{ summary.get('missing_sec_headers', 0) }}</div>
      </div>
      <div class="card">
        <div class="label">VT Malicious</div>
        <div class="value">{{ summary.get('vt_malicious', 0) }}</div>
      </div>
    </div>

    {% if owasp %}
    <div class="section">
      <h2>OWASP Top 10 Snapshot</h2>
      <table>
        <thead><tr><th>Category</th><th>Status</th><th>Evidence</th></tr></thead>
        <tbody>
          {% for row in owasp %}
          <tr>
            <td>{{ row.category }}</td>
            <td>
              {% set badge = 'ok' %}
              {% if row.status == 'fail' %}{% set badge = 'bad' %}{% elif row.status in ['warn','unknown'] %}{% set badge = 'warn' %}{% endif %}
              <span class="badge {{ badge }}">{{ row.status|upper }}</span>
            </td>
            <td>{{ row.evidence }}</td>
          </tr>
          {% endfor %}
        </tbody>
      </table>
    </div>
    {% endif %}

    {% if exposures %}
    <div class="section">
      <h2>Exposed Paths</h2>
      <table>
        <thead><tr><th>Path</th><th>Status</th><th>Severity</th><th>Description</th></tr></thead>
        <tbody>
          {% for row in exposures %}
          <tr>
            <td>{{ row.path }}</td>
            <td>{{ row.status }}</td>
            <td>{{ row.severity|capitalize }}</td>
            <td>{{ row.description }}</td>
          </tr>
          {% endfor %}
        </tbody>
      </table>
    </div>
    {% endif %}

    {% if fuzzer %}
    <div class="section">
      <h2>Fuzzer Highlights</h2>
      <table>
        <thead><tr><th>Payload</th><th>Method</th><th>Status</th><th>Severity</th><th>Notes</th></tr></thead>
        <tbody>
          {% for row in fuzzer %}
          <tr>
            <td>{{ row.name }}</td>
            <td>{{ row.method }}</td>
            <td>{{ row.status or row.error }}</td>
            <td>{{ row.severity|capitalize }}</td>
            <td>{{ (row.notes or [])|join('; ') }}</td>
          </tr>
          {% endfor %}
        </tbody>
      </table>
    </div>
    {% endif %}

    {% if subdomains %}
    <div class="section">
      <h2>Sample Subdomains</h2>
      <table>
        <thead><tr><th>Subdomain</th><th>Source</th><th>Resolved IPs</th></tr></thead>
        <tbody>
          {% for row in subdomains %}
          <tr>
            <td>{{ row.subdomain }}</td>
            <td>{{ row.source }}</td>
            <td>{{ (row.a_records or [])|join(', ') }}</td>
          </tr>
          {% endfor %}
        </tbody>
      </table>
    </div>
    {% endif %}

    {% if signatures %}
    <div class="section">
      <h2>Detected Signatures</h2>
      <ul>
        {% for sig in signatures %}
          <li>{{ sig.name }} ({{ sig.severity }})</li>
        {% endfor %}
      </ul>
    </div>
    {% endif %}

    <div class="section">
      <h2>Module Timings</h2>
      <table>
        <thead><tr><th>Module</th><th>Seconds</th></tr></thead>
        <tbody>
          {% for name, secs in meta.get('module_times', {}).items() %}
          <tr><td>{{ name }}</td><td>{{ secs }}</td></tr>
          {% endfor %}
        </tbody>
      </table>
    </div>
  </div>
</body>
</html>
"""

SCHEDULED_HTML = r"""
<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>Scheduled Scans</title>
  <link href="https://cdn.jsdelivr.net/npm/tailwindcss@2.2.19/dist/tailwind.min.css" rel="stylesheet">
</head>
<body class="bg-gray-900 text-gray-100">
  <div class="max-w-5xl mx-auto py-10">
    <div class="flex items-center justify-between mb-6">
      <h1 class="text-3xl font-semibold text-blue-400">Scheduled Scans</h1>
      <a href="/" class="bg-gray-700 hover:bg-gray-600 px-4 py-2 rounded">Back</a>
    </div>
    <div class="bg-gray-800 border border-gray-700 rounded-lg overflow-hidden">
      <table class="min-w-full text-sm">
        <thead class="bg-gray-700">
          <tr>
            <th class="px-3 py-2 text-left">ID</th>
            <th class="px-3 py-2 text-left">URL</th>
            <th class="px-3 py-2 text-left">Modules</th>
            <th class="px-3 py-2 text-left">Interval (min)</th>
            <th class="px-3 py-2 text-left">Next Run</th>
            <th class="px-3 py-2 text-left">Last Run</th>
          </tr>
        </thead>
        <tbody>
        {% for row in items %}
          <tr class="border-t border-gray-700">
            <td class="px-3 py-2">{{ row.id }}</td>
            <td class="px-3 py-2">{{ row.url }}</td>
            <td class="px-3 py-2 text-xs">{{ row.services }}</td>
            <td class="px-3 py-2">{{ row.interval_minutes }}</td>
            <td class="px-3 py-2">{{ row.next_run }}</td>
            <td class="px-3 py-2">{{ row.last_run or '-' }}</td>
          </tr>
        {% endfor %}
        </tbody>
      </table>
      {% if not items %}
        <p class="p-4 text-sm text-gray-400">No schedules defined yet.</p>
      {% endif %}
    </div>
  </div>
</body>
</html>
"""

# ---------------- Utilities ----------------
def url_normalize(u: str) -> str:
    u = u.strip()
    if not u.startswith(('http://', 'https://')):
        u = "http://" + u
    return u

def get_domain(u: str) -> str:
    try:
        return urlparse(u).hostname or ""
    except Exception:
        return ""

def http_get(u: str):
    try:
        r = SESSION.get(u, timeout=DEFAULT_TIMEOUT, allow_redirects=True)
        r.raise_for_status()
        return r
    except requests.RequestException as e:
        # response-like object with 'error'
        return type('obj', (object,), {'status_code': 0, 'text': '', 'headers': {}, 'url': u, 'error': str(e)})

def parse_multiline_values(raw: str):
    if not raw:
        return []
    values = []
    for chunk in raw.replace(",", "\n").splitlines():
        val = chunk.strip()
        if val:
            values.append(val)
    return values

# ---------------- Subdomain Scanner ----------------
def _crtsh_subdomains(domain: str):
    """Passive OSINT from Certificate Transparency (crt.sh)."""
    names = set()
    try:
        r = SESSION.get(
            "https://crt.sh/",
            params={"q": f"%.{domain}", "output": "json"},
            timeout=DEFAULT_TIMEOUT,
        )
        if r.status_code != 200:
            return names
        data = r.json()
        for entry in data:
            raw = entry.get("name_value", "") or ""
            for line in raw.split("\n"):
                name = line.strip().lower()
                if not name or name.startswith("*."):
                    continue
                if name.endswith("." + domain) or name == domain:
                    names.add(name)
    except Exception:
        pass
    return names

def _resolve_records(host: str):
    """Resolve A/AAAA and CNAME with short timeouts."""
    res = {"A": [], "AAAA": [], "CNAME": None}
    try:
        answers = dns.resolver.resolve(host, "A", lifetime=3)
        res["A"] = [a.to_text() for a in answers]
    except Exception:
        pass
    try:
        answers = dns.resolver.resolve(host, "AAAA", lifetime=3)
        res["AAAA"] = [a.to_text() for a in answers]
    except Exception:
        pass
    try:
        answers = dns.resolver.resolve(host, "CNAME", lifetime=3)
        for a in answers:
            try:
                res["CNAME"] = a.target.to_unicode().rstrip(".")
            except Exception:
                res["CNAME"] = str(a.target).rstrip(".")
            break
    except Exception:
        pass
    return res

_BRUTE_WORDS = [
    "www","mail","ftp","webmail","smtp","pop","imap","api","dev","test","staging",
    "cdn","assets","static","portal","admin","vpn","sso","blog","shop","mx","gw",
    "ns1","ns2","m","beta","qa","help","support","status","git","repo","office",
]

def _bruteforce_subdomains(domain: str, extra_words=None, max_workers=20):
    words = list(dict.fromkeys((extra_words or []) + _BRUTE_WORDS))
    candidates = [f"{w}.{domain}" for w in words]
    found = {}

    def probe(host):
        rec = _resolve_records(host)
        if rec["A"] or rec["AAAA"] or rec["CNAME"]:
            return host, rec
        return None

    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        futures = {ex.submit(probe, h): h for h in candidates}
        for fut in as_completed(futures):
            out = fut.result()
            if out:
                host, rec = out
                found[host] = rec
    return found

def subdomain_scan(domain: str, mode: str = "defensive", extra_words=None):
    """
    Returns:
      {
        "rows": [{"subdomain": str, "source": "crt.sh|bruteforce", "a_records": [..], "cname": str|None}],
        "found": [list]  # simple view
      }
    """
    rows = []
    found_set = set()

    crt_names = _crtsh_subdomains(domain)
    for name in crt_names:
        rec = _resolve_records(name)
        rows.append({
            "subdomain": name,
            "source": "crt.sh",
            "a_records": rec["A"] + rec["AAAA"],
            "cname": rec["CNAME"],
        })
        found_set.add(name)

    should_bruteforce = mode == "semi" or extra_words
    if should_bruteforce:
        brute = _bruteforce_subdomains(domain, extra_words=extra_words)
        for name, rec in brute.items():
            if name not in found_set:
                rows.append({
                    "subdomain": name,
                    "source": "bruteforce",
                    "a_records": rec["A"] + rec["AAAA"],
                    "cname": rec["CNAME"],
                })
                found_set.add(name)

    rows.sort(key=lambda r: r["subdomain"])
    return {"rows": rows, "found": sorted(found_set)}

# ---------------- Other Modules ----------------
def crawl_website(start_url, max_depth=2, max_pages=50):
    """Enhanced crawler with concurrent execution and extended data extraction"""
    visited = set()
    to_visit = [(url_normalize(start_url), 0)]
    base_netloc = urlparse(start_url).netloc
    
    crawled = {
        'urls': [],
        'emails': [],
        'external_links': [],
        'forms': [],
        'js_files': [],
        'social_media': [],
        'phone_numbers': [],
        'api_endpoints': [],
        'comments': [],
        'images': [],
        'stats': {'pages_scanned': 0, 'errors': 0}
    }
    
    # Regex patterns
    email_rx = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
    phone_rx = re.compile(r"(?:\+\d{1,3}[-.\s]?)?\(?\d{2,4}\)?[-.\s]?\d{3,4}[-.\s]?\d{3,4}")
    api_rx = re.compile(r"(?:/api/[^\s\"'<>]+|\.json(?:\?[^\s\"'<>]*)?)", re.I)
    comment_rx = re.compile(r"<!--(.*?)-->", re.S)
    social_patterns = {
        'twitter': re.compile(r"(?:twitter\.com|x\.com)/[A-Za-z0-9_]+", re.I),
        'facebook': re.compile(r"facebook\.com/[A-Za-z0-9_.]+", re.I),
        'linkedin': re.compile(r"linkedin\.com/(?:in|company)/[A-Za-z0-9_-]+", re.I),
        'github': re.compile(r"github\.com/[A-Za-z0-9_-]+", re.I),
        'instagram': re.compile(r"instagram\.com/[A-Za-z0-9_.]+", re.I),
    }
    
    def process_page(url, depth):
        """Process a single page and extract data"""
        result = {'url': url, 'depth': depth, 'links': [], 'data': {}}
        try:
            r = http_get(url)
            if hasattr(r, 'error'):
                return None
            
            html_text = r.text
            soup = BeautifulSoup(html_text, 'html.parser')
            
            # Extract emails
            for m in email_rx.findall(html_text):
                if m not in crawled['emails'] and not m.endswith(('.png', '.jpg', '.gif')):
                    crawled['emails'].append(m)
            
            # Extract phone numbers
            for m in phone_rx.findall(html_text):
                clean = re.sub(r'[^\d+]', '', m)
                if len(clean) >= 10 and clean not in crawled['phone_numbers']:
                    crawled['phone_numbers'].append(m.strip())
            
            # Extract API endpoints
            for m in api_rx.findall(html_text):
                endpoint = urljoin(url, m)
                if endpoint not in crawled['api_endpoints']:
                    crawled['api_endpoints'].append(endpoint)
            
            # Extract social media links
            for platform, pattern in social_patterns.items():
                for match in pattern.findall(html_text):
                    full_url = f"https://{match}"
                    entry = {'platform': platform, 'url': full_url}
                    if entry not in crawled['social_media']:
                        crawled['social_media'].append(entry)
            
            # Extract HTML comments
            for comment in comment_rx.findall(html_text):
                comment = comment.strip()
                if len(comment) > 10 and len(comment) < 500:
                    if any(kw in comment.lower() for kw in ['todo', 'fixme', 'bug', 'hack', 'password', 'secret', 'key', 'token', 'debug']):
                        if comment not in crawled['comments']:
                            crawled['comments'].append(comment[:200])
            
            # Extract forms
            for form in soup.find_all('form'):
                form_data = {
                    'action': urljoin(url, form.get('action', '')),
                    'method': form.get('method', 'GET').upper(),
                    'inputs': []
                }
                for inp in form.find_all(['input', 'textarea', 'select']):
                    inp_name = inp.get('name', '')
                    inp_type = inp.get('type', 'text')
                    if inp_name:
                        form_data['inputs'].append({'name': inp_name, 'type': inp_type})
                if form_data['action'] and form_data not in crawled['forms']:
                    crawled['forms'].append(form_data)
            
            # Extract JavaScript files
            for script in soup.find_all('script', src=True):
                js_url = urljoin(url, script['src'])
                if js_url not in crawled['js_files'] and base_netloc in js_url:
                    crawled['js_files'].append(js_url)
            
            # Extract links
            for a in soup.find_all('a', href=True):
                href = a['href'].strip()
                if href.startswith(('#', 'javascript:', 'mailto:', 'tel:')):
                    continue
                absolute = urljoin(url, href)
                netloc = urlparse(absolute).netloc
                
                if netloc == base_netloc:
                    if absolute not in visited and absolute not in [v[0] for v in to_visit]:
                        result['links'].append((absolute, depth + 1))
                elif netloc and absolute not in crawled['external_links']:
                    crawled['external_links'].append(absolute)
            
            return result
            
        except Exception as e:
            crawled['stats']['errors'] += 1
            return None
    
    # Concurrent crawling
    with ThreadPoolExecutor(max_workers=8) as executor:
        while to_visit and len(crawled['urls']) < max_pages:
            # Get batch of URLs to process
            batch = []
            while to_visit and len(batch) < 8:
                url, depth = to_visit.pop(0)
                if url not in visited and depth <= max_depth:
                    visited.add(url)
                    batch.append((url, depth))
            
            if not batch:
                break
            
            # Process batch concurrently
            futures = {executor.submit(process_page, url, depth): (url, depth) for url, depth in batch}
            for future in as_completed(futures, timeout=30):
                try:
                    result = future.result()
                    if result:
                        crawled['urls'].append(result['url'])
                        crawled['stats']['pages_scanned'] += 1
                        # Add new links to queue
                        for link_url, link_depth in result.get('links', []):
                            if link_url not in visited:
                                to_visit.append((link_url, link_depth))
                except Exception:
                    crawled['stats']['errors'] += 1
    
    # Limit results to prevent massive output
    crawled['external_links'] = crawled['external_links'][:100]
    crawled['js_files'] = crawled['js_files'][:50]
    crawled['forms'] = crawled['forms'][:30]
    crawled['comments'] = crawled['comments'][:20]
    crawled['social_media'] = crawled['social_media'][:20]
    crawled['api_endpoints'] = crawled['api_endpoints'][:50]
    
    return crawled

def get_whois_info(domain):
    try:
        w = whois.whois(domain)
        return {k: str(v) for k, v in w.items()}
    except Exception as e:
        return {"error": str(e)}

def get_dns_records(domain):
    records = {}
    for rtype in ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA']:
        try:
            answers = dns.resolver.resolve(domain, rtype)
            records[rtype] = [r.to_text() for r in answers]
        except dns.resolver.NoAnswer:
            records[rtype] = []
        except Exception as e:
            records[rtype] = [str(e)]
    return records

def get_http_headers(url):
    try:
        r = SESSION.get(url, timeout=DEFAULT_TIMEOUT)
        return dict(r.headers)
    except Exception as e:
        return {"error": str(e)}

def fingerprint(headers: dict, html_text: str):
    stack = set()
    if "Server" in headers: stack.add(f"Server: {headers['Server']}")
    if "X-Powered-By" in headers: stack.add(f"X-Powered-By: {headers['X-Powered-By']}")
    signatures = {
        "WordPress": re.compile(r"/wp-content/|wp-includes", re.I),
        "React": re.compile(r"data-reactroot", re.I),
    }
    for name, rx in signatures.items():
        if rx.search(html_text):
            stack.add(name)
    return {"stack": sorted(list(stack))}

def security_headers_report(headers: dict):
    rows = []
    sec_headers = {
        "Strict-Transport-Security": "OK",
        "Content-Security-Policy": "OK",
        "X-Frame-Options": "OK",
        "X-Content-Type-Options": "OK",
        "Referrer-Policy": "OK",
        "Permissions-Policy": "OK"
    }
    for header, status in sec_headers.items():
        if header not in headers:
            rows.append({"header": header, "status": "WARN", "message": "Missing"})
        else:
            rows.append({"header": header, "status": status, "message": headers[header]})
    return {"rows": rows}

def tls_info(domain: str, port: int = 443):
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((domain, port), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
        return {
            "subject": dict(x[0] for x in cert['subject']),
            "issuer": dict(x[0] for x in cert['issuer']),
            "not_before": cert['notBefore'],
            "not_after": cert['notAfter']
        }
    except Exception as e:
        return {"error": str(e)}

def vt_url_lookup(u: str):
    if not VT_API_KEY: return {"error": "VT_API_KEY not set."}
    url_id = base64.urlsafe_b64encode(u.encode()).decode().strip("=")
    url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
    try:
        r = SESSION.get(url, headers={"x-apikey": VT_API_KEY})
        return r.json()
    except Exception as e:
        return {"error": str(e)}

def otx_domain_general(domain: str):
    if not OTX_API_KEY: return {"error": "OTX_API_KEY not set."}
    url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/general"
    try:
        r = SESSION.get(url, headers={"X-OTX-API-KEY": OTX_API_KEY})
        return r.json()
    except Exception as e:
        return {"error": str(e)}

def urlscan_search_domain(domain: str):
    try:
        r = SESSION.get(f"https://urlscan.io/api/v1/search/?q=domain:{domain}")
        return r.json()
    except Exception as e:
        return {"error": str(e)}

def archive_cdx(u: str):
    dom = get_domain(u)
    url = f"http://web.archive.org/cdx/search/cdx?url={dom}/*&output=json&limit=10"
    try:
        r = SESSION.get(url, timeout=DEFAULT_TIMEOUT)
        r.raise_for_status()
        return r.json()
    except Exception as e:
        return {"error": str(e)}

def github_code_search(query: str):
    headers = {"Accept": "application/vnd.github+json"}
    if GITHUB_TOKEN:
        headers["Authorization"] = f"Bearer {GITHUB_TOKEN}"
    url = f"https://api.github.com/search/code?q={query}"
    try:
        r = SESSION.get(url, headers=headers)
        return r.json()
    except Exception as e:
        return {"error": str(e)}

def securitytrails_lookup(domain: str):
    if not SECURITYTRAILS_API_KEY:
        return {"error": "SECURITYTRAILS_API_KEY not set."}
    headers = {"APIKEY": SECURITYTRAILS_API_KEY}
    base = f"https://api.securitytrails.com/v1/domain/{domain}"
    history_url = f"https://api.securitytrails.com/v1/history/{domain}/dns/a"
    result = {}
    try:
        resp = SESSION.get(base, headers=headers, timeout=DEFAULT_TIMEOUT)
        result["current"] = resp.json() if resp.ok else {"error": resp.text}
    except Exception as exc:
        result["current"] = {"error": str(exc)}
    try:
        hist_resp = SESSION.get(history_url, headers=headers, timeout=DEFAULT_TIMEOUT)
        if hist_resp.ok:
            payload = hist_resp.json()
            result["history"] = payload.get("records", [])[:25]
        else:
            result["history"] = {"error": hist_resp.text}
    except Exception as exc:
        result["history"] = {"error": str(exc)}
    return result

def shodan_lookup(domain: str):
    if not SHODAN_API_KEY: return {"error": "SHODAN_API_KEY not set."}
    try:
        ip = socket.gethostbyname(domain)
        r = SESSION.get(f"https://api.shodan.io/shodan/host/{ip}?key={SHODAN_API_KEY}")
        return r.json()
    except Exception as e:
        return {"error": str(e)}

def greynoise_lookup(ip: str):
    if not GREYNOISE_API_KEY: return {"error": "GREYNOISE_API_KEY not set."}
    try:
        r = SESSION.get(f"https://api.greynoise.io/v3/community/{ip}", headers={"key": GREYNOISE_API_KEY})
        return r.json()
    except Exception as e:
        return {"error": str(e)}

def abuseipdb_lookup(ip: str):
    if not ABUSEIPDB_API_KEY: return {"error": "ABUSEIPDB_API_KEY not set."}
    try:
        r = SESSION.get(
            "https://api.abuseipdb.com/api/v2/check",
            params={"ipAddress": ip},
            headers={"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"}
        )
        return r.json()
    except Exception as e:
        return {"error": str(e)}

# ---------------- NEW RECONNAISSANCE MODULES ----------------

# WAF Detection signatures
WAF_SIGNATURES = {
    "Cloudflare": ["cf-ray", "cf-cache-status", "__cfduid", "cloudflare"],
    "AWS WAF": ["x-amzn-requestid", "x-amz-cf-id", "awselb"],
    "Akamai": ["akamai-origin-hop", "x-akamai-transformed"],
    "Imperva/Incapsula": ["x-iinfo", "incap_ses", "visid_incap"],
    "Sucuri": ["x-sucuri-id", "x-sucuri-cache"],
    "ModSecurity": ["mod_security", "modsecurity"],
    "F5 BIG-IP": ["x-wa-info", "bigipserver"],
    "Barracuda": ["barra_counter_session"],
    "Fortinet FortiWeb": ["fortiwafsid"],
    "DDoS-Guard": ["ddos-guard"],
}

def detect_waf(url: str):
    """Detect WAF/CDN using response headers and behavior analysis"""
    detected = []
    headers_found = []
    try:
        resp = SESSION.get(url, timeout=DEFAULT_TIMEOUT, allow_redirects=True)
        response_headers = {k.lower(): v for k, v in resp.headers.items()}
        cookies = resp.cookies.get_dict()
        
        for waf_name, signatures in WAF_SIGNATURES.items():
            for sig in signatures:
                sig_lower = sig.lower()
                for header_name, header_value in response_headers.items():
                    if sig_lower in header_name or sig_lower in header_value.lower():
                        if waf_name not in detected:
                            detected.append(waf_name)
                            headers_found.append(f"{header_name}: {header_value[:50]}")
                for cookie_name in cookies:
                    if sig_lower in cookie_name.lower():
                        if waf_name not in detected:
                            detected.append(waf_name)
        
        server = response_headers.get("server", "").lower()
        if "cloudflare" in server and "Cloudflare" not in detected:
            detected.append("Cloudflare")
        elif "akamai" in server and "Akamai" not in detected:
            detected.append("Akamai")
        
        return {
            "detected": detected,
            "headers_evidence": headers_found[:10],
            "likely_protected": len(detected) > 0,
            "confidence": "high" if detected else "low",
        }
    except Exception as e:
        return {"error": str(e)}

def email_security_check(domain: str):
    """Check SPF, DKIM, DMARC email security records"""
    results = {"spf": None, "dkim": None, "dmarc": None, "score": 0, "recommendations": []}
    
    try:
        # SPF Check
        try:
            spf_answers = dns.resolver.resolve(domain, 'TXT')
            for rdata in spf_answers:
                txt = rdata.to_text().strip('"')
                if txt.startswith('v=spf1'):
                    results["spf"] = {"record": txt, "found": True}
                    if "-all" in txt:
                        results["spf"]["policy"] = "strict"
                        results["score"] += 30
                    elif "~all" in txt:
                        results["spf"]["policy"] = "softfail"
                        results["score"] += 20
                    break
            if not results["spf"]:
                results["spf"] = {"found": False}
                results["recommendations"].append("Implement SPF record")
        except Exception:
            results["spf"] = {"found": False}
        
        # DMARC Check
        try:
            dmarc_answers = dns.resolver.resolve(f"_dmarc.{domain}", 'TXT')
            for rdata in dmarc_answers:
                txt = rdata.to_text().strip('"')
                if 'v=DMARC1' in txt:
                    policy = "none"
                    if "p=reject" in txt:
                        policy = "reject"
                        results["score"] += 40
                    elif "p=quarantine" in txt:
                        policy = "quarantine"
                        results["score"] += 30
                    results["dmarc"] = {"record": txt, "found": True, "policy": policy}
                    break
            if not results["dmarc"]:
                results["dmarc"] = {"found": False}
                results["recommendations"].append("Implement DMARC record")
        except Exception:
            results["dmarc"] = {"found": False}
        
        # DKIM Check
        dkim_selectors = ["default", "google", "selector1", "selector2", "k1"]
        dkim_found = []
        for selector in dkim_selectors:
            try:
                dkim_answers = dns.resolver.resolve(f"{selector}._domainkey.{domain}", 'TXT')
                for rdata in dkim_answers:
                    txt = rdata.to_text().strip('"')
                    if 'v=DKIM1' in txt or 'k=' in txt:
                        dkim_found.append({"selector": selector, "record": txt[:80]})
                        results["score"] += 15
            except Exception:
                pass
        results["dkim"] = {"found": bool(dkim_found), "selectors": dkim_found}
        
        # Grade
        if results["score"] >= 80:
            results["grade"] = "A"
        elif results["score"] >= 60:
            results["grade"] = "B"
        elif results["score"] >= 40:
            results["grade"] = "C"
        else:
            results["grade"] = "F"
        
        return results
    except Exception as e:
        return {"error": str(e)}

def port_scan(domain: str):
    """Quick port scan with service identification"""
    TOP_PORTS = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 993, 995, 3306, 3389, 5432, 5900, 8080, 8443]
    
    try:
        target_ip = socket.gethostbyname(domain)
    except socket.gaierror as e:
        return {"error": f"Could not resolve: {e}"}
    
    open_ports = []
    service_map = {21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 80: "HTTP",
                   110: "POP3", 143: "IMAP", 443: "HTTPS", 445: "SMB", 993: "IMAPS",
                   995: "POP3S", 3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL",
                   5900: "VNC", 8080: "HTTP-Proxy", 8443: "HTTPS-Alt"}
    
    def scan_port(port):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1.5)
            if sock.connect_ex((target_ip, port)) == 0:
                return {"port": port, "state": "open", "service": service_map.get(port, "Unknown")}
            sock.close()
        except Exception:
            pass
        return None
    
    with ThreadPoolExecutor(max_workers=20) as executor:
        futures = [executor.submit(scan_port, port) for port in TOP_PORTS]
        for future in as_completed(futures, timeout=30):
            result = future.result()
            if result:
                open_ports.append(result)
    
    open_ports.sort(key=lambda x: x["port"])
    return {
        "target_ip": target_ip,
        "open_count": len(open_ports),
        "open_ports": open_ports,
        "risk_ports": [p for p in open_ports if p["port"] in [21, 22, 23, 3389, 445, 5900]],
    }

def asn_lookup(ip: str):
    """Get ASN and organization info"""
    try:
        reversed_ip = ".".join(reversed(ip.split(".")))
        asn_query = f"{reversed_ip}.origin.asn.cymru.com"
        result = {"ip": ip, "asn": None, "prefix": None, "country": None, "org_name": None}
        
        try:
            answers = dns.resolver.resolve(asn_query, 'TXT')
            for rdata in answers:
                txt = rdata.to_text().strip('"')
                parts = [p.strip() for p in txt.split('|')]
                if len(parts) >= 3:
                    result["asn"] = parts[0]
                    result["prefix"] = parts[1]
                    result["country"] = parts[2]
        except Exception:
            pass
        
        if result["asn"]:
            try:
                answers = dns.resolver.resolve(f"AS{result['asn']}.asn.cymru.com", 'TXT')
                for rdata in answers:
                    txt = rdata.to_text().strip('"')
                    parts = [p.strip() for p in txt.split('|')]
                    if len(parts) >= 5:
                        result["org_name"] = parts[4]
            except Exception:
                pass
        
        return result
    except Exception as e:
        return {"error": str(e)}

def favicon_hash(url: str):
    """Calculate favicon hash for Shodan matching"""
    import hashlib
    
    for path in ["/favicon.ico", "/favicon.png"]:
        try:
            resp = SESSION.get(urljoin(url, path), timeout=10)
            if resp.status_code == 200 and len(resp.content) > 0:
                b64_content = base64.b64encode(resp.content).decode()
                md5_hash = hashlib.md5(resp.content).hexdigest()
                try:
                    import mmh3
                    mmh3_hash = mmh3.hash(b64_content)
                except ImportError:
                    mmh3_hash = "mmh3 not installed"
                return {
                    "found": True, "url": urljoin(url, path),
                    "size_bytes": len(resp.content), "md5": md5_hash,
                    "mmh3_hash": mmh3_hash,
                    "shodan_query": f"http.favicon.hash:{mmh3_hash}" if isinstance(mmh3_hash, int) else None,
                }
        except Exception:
            continue
    return {"found": False}

# ---------------- ADVANCED RECON MODULES ----------------

def ssl_tls_analysis(domain: str):
    """Deep SSL/TLS analysis with cipher grading"""
    WEAK_CIPHERS = ['RC4', 'DES', 'NULL', 'EXPORT', 'MD5', 'anon']
    GOOD_PROTOCOLS = ['TLSv1.2', 'TLSv1.3']
    
    result = {
        "grade": "F", "score": 0, "issues": [], "certificate": {},
        "protocol": None, "cipher_suite": None, "key_exchange": None
    }
    
    try:
        context = ssl.create_default_context()
        # Enforce modern TLS (TLS 1.2+) for the analysis connection
        try:
            # Preferred on Python 3.7+
            context.minimum_version = ssl.TLSVersion.TLSv1_2
        except (AttributeError, ValueError):
            # Fallback for older Python/OpenSSL: explicitly disable TLS 1.0 and 1.1
            if hasattr(ssl, "OP_NO_TLSv1") and hasattr(ssl, "OP_NO_TLSv1_1"):
                context.options |= ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1
        with socket.create_connection((domain, 443), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                result["protocol"] = ssock.version()
                result["cipher_suite"] = ssock.cipher()[0]
                
                cert = ssock.getpeercert()
                result["certificate"] = {
                    "subject": dict(x[0] for x in cert.get('subject', [])),
                    "issuer": dict(x[0] for x in cert.get('issuer', [])),
                    "not_before": cert.get('notBefore'),
                    "not_after": cert.get('notAfter'),
                    "san": [x[1] for x in cert.get('subjectAltName', [])],
                }
                
                # Score calculation
                score = 0
                if result["protocol"] in GOOD_PROTOCOLS:
                    score += 40
                elif result["protocol"] == "TLSv1.1":
                    score += 20
                    result["issues"].append("TLS 1.1 deprecated - upgrade to 1.2+")
                elif result["protocol"] == "TLSv1":
                    result["issues"].append("TLS 1.0 deprecated - security risk")
                
                # Cipher check
                cipher = result["cipher_suite"]
                if any(weak in cipher for weak in WEAK_CIPHERS):
                    result["issues"].append(f"Weak cipher: {cipher}")
                else:
                    score += 30
                
                # Certificate validity
                from datetime import datetime
                try:
                    not_after = datetime.strptime(cert.get('notAfter', ''), '%b %d %H:%M:%S %Y %Z')
                    days_left = (not_after - datetime.utcnow()).days
                    result["certificate"]["days_until_expiry"] = days_left
                    if days_left < 0:
                        result["issues"].append("Certificate EXPIRED")
                    elif days_left < 30:
                        result["issues"].append(f"Certificate expires in {days_left} days")
                        score += 10
                    else:
                        score += 30
                except:
                    pass
                
                result["score"] = score
                if score >= 90: result["grade"] = "A"
                elif score >= 70: result["grade"] = "B"
                elif score >= 50: result["grade"] = "C"
                elif score >= 30: result["grade"] = "D"
                
    except Exception as e:
        result["error"] = str(e)
    
    return result

def subdomain_takeover_check(domain: str):
    """Check for subdomain takeover vulnerabilities"""
    TAKEOVER_FINGERPRINTS = {
        "github.io": ["There isn't a GitHub Pages site here"],
        "herokuapp.com": ["No such app", "no-such-app"],
        "s3.amazonaws.com": ["NoSuchBucket", "The specified bucket does not exist"],
        "cloudfront.net": ["Bad Request", "ERROR: The request could not be satisfied"],
        "azure": ["404 Web Site not found"],
        "zendesk.com": ["Help Center Closed"],
        "shopify.com": ["Sorry, this shop is currently unavailable"],
        "tumblr.com": ["There's nothing here"],
        "wordpress.com": ["Do you want to register"],
        "ghost.io": ["The thing you were looking for is no longer here"],
    }
    
    result = {"vulnerable": [], "checked": [], "cname_records": []}
    
    try:
        # Get CNAME records
        try:
            answers = dns.resolver.resolve(domain, 'CNAME')
            for rdata in answers:
                result["cname_records"].append(rdata.target.to_text())
        except:
            pass
        
        for cname in result["cname_records"]:
            result["checked"].append(cname)
            for service, fingerprints in TAKEOVER_FINGERPRINTS.items():
                if service in cname.lower():
                    try:
                        resp = SESSION.get(f"http://{domain}", timeout=10, allow_redirects=True)
                        for fp in fingerprints:
                            if fp.lower() in resp.text.lower():
                                result["vulnerable"].append({
                                    "subdomain": domain,
                                    "cname": cname,
                                    "service": service,
                                    "fingerprint": fp
                                })
                    except:
                        pass
    except Exception as e:
        result["error"] = str(e)
    
    return result

def http_method_enum(url: str):
    """Enumerate allowed HTTP methods"""
    METHODS = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS', 'HEAD', 'TRACE']
    DANGEROUS = ['PUT', 'DELETE', 'TRACE']
    
    result = {"allowed": [], "dangerous": [], "options_header": None}
    
    try:
        # Try OPTIONS first
        try:
            resp = SESSION.options(url, timeout=10)
            allow = resp.headers.get('Allow', '')
            result["options_header"] = allow
            if allow:
                result["allowed"] = [m.strip() for m in allow.split(',')]
        except:
            pass
        
        # Test each method
        for method in METHODS:
            try:
                resp = SESSION.request(method, url, timeout=5)
                if resp.status_code not in [405, 501]:
                    if method not in result["allowed"]:
                        result["allowed"].append(method)
                    if method in DANGEROUS:
                        result["dangerous"].append({
                            "method": method,
                            "status": resp.status_code,
                            "risk": "high" if method in ['PUT', 'DELETE'] else "medium"
                        })
            except:
                pass
    except Exception as e:
        result["error"] = str(e)
    
    return result

def cors_check(url: str):
    """Check for CORS misconfigurations"""
    TEST_ORIGINS = ["https://evil.com", "null", "https://attacker.com"]
    result = {"vulnerable": False, "issues": [], "headers": {}}
    
    try:
        for origin in TEST_ORIGINS:
            resp = SESSION.get(url, headers={"Origin": origin}, timeout=10)
            acao = resp.headers.get("Access-Control-Allow-Origin", "")
            acac = resp.headers.get("Access-Control-Allow-Credentials", "")
            
            if acao:
                result["headers"]["Access-Control-Allow-Origin"] = acao
                result["headers"]["Access-Control-Allow-Credentials"] = acac
                
                if acao == "*":
                    result["issues"].append("Wildcard ACAO - allows any origin")
                    result["vulnerable"] = True
                elif acao == origin:
                    result["issues"].append(f"Reflects arbitrary origin: {origin}")
                    result["vulnerable"] = True
                    if acac.lower() == "true":
                        result["issues"].append("CRITICAL: Credentials allowed with reflected origin")
                elif acao == "null":
                    result["issues"].append("Allows 'null' origin - sandbox bypass possible")
                    result["vulnerable"] = True
                break
    except Exception as e:
        result["error"] = str(e)
    
    return result

def cookie_security_audit(url: str):
    """Audit cookie security attributes"""
    result = {"cookies": [], "issues": [], "score": 100}
    
    try:
        resp = SESSION.get(url, timeout=10)
        for cookie in resp.cookies:
            cookie_info = {
                "name": cookie.name,
                "secure": cookie.secure,
                "httponly": cookie.has_nonstandard_attr('HttpOnly') or 'httponly' in str(cookie).lower(),
                "samesite": None,
                "issues": []
            }
            
            # Check SameSite
            cookie_str = str(cookie).lower()
            if 'samesite=strict' in cookie_str:
                cookie_info["samesite"] = "Strict"
            elif 'samesite=lax' in cookie_str:
                cookie_info["samesite"] = "Lax"
            elif 'samesite=none' in cookie_str:
                cookie_info["samesite"] = "None"
            
            # Score issues
            if not cookie_info["secure"]:
                cookie_info["issues"].append("Missing Secure flag")
                result["score"] -= 15
            if not cookie_info["httponly"]:
                cookie_info["issues"].append("Missing HttpOnly flag")
                result["score"] -= 10
            if cookie_info["samesite"] is None:
                cookie_info["issues"].append("Missing SameSite attribute")
                result["score"] -= 5
            
            result["cookies"].append(cookie_info)
            result["issues"].extend([f"{cookie.name}: {i}" for i in cookie_info["issues"]])
        
        result["score"] = max(0, result["score"])
    except Exception as e:
        result["error"] = str(e)
    
    return result

def js_secret_scan(url: str):
    """Extract secrets from JavaScript files"""
    SECRET_PATTERNS = {
        "AWS Key": re.compile(r'AKIA[0-9A-Z]{16}'),
        "Google API": re.compile(r'AIza[0-9A-Za-z\-_]{35}'),
        "Slack Token": re.compile(r'xox[baprs]-[0-9A-Za-z\-]{10,}'),
        "GitHub Token": re.compile(r'gh[pousr]_[A-Za-z0-9_]{36,}'),
        "JWT": re.compile(r'eyJ[A-Za-z0-9\-_]+\.eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+'),
        "Private Key": re.compile(r'-----BEGIN (?:RSA |EC )?PRIVATE KEY-----'),
        "API Key": re.compile(r'(?:api[_-]?key|apikey)["\s:=]+["\']?([A-Za-z0-9\-_]{16,})["\']?', re.I),
        "Password": re.compile(r'(?:password|passwd|pwd)["\s:=]+["\']([^"\']{4,})["\']', re.I),
        "Bearer Token": re.compile(r'Bearer\s+[A-Za-z0-9\-_\.]+'),
    }
    
    result = {"secrets_found": [], "js_files_scanned": 0}
    
    try:
        resp = SESSION.get(url, timeout=10)
        soup = BeautifulSoup(resp.text, 'html.parser')
        
        js_content = [resp.text]  # Also scan HTML
        
        for script in soup.find_all('script', src=True):
            try:
                js_url = urljoin(url, script['src'])
                js_resp = SESSION.get(js_url, timeout=5)
                js_content.append(js_resp.text)
                result["js_files_scanned"] += 1
            except:
                pass
        
        for content in js_content:
            for secret_type, pattern in SECRET_PATTERNS.items():
                matches = pattern.findall(content)
                for match in matches[:3]:  # Limit per type
                    match_str = match if isinstance(match, str) else match[0]
                    if len(match_str) > 8:  # Filter short matches
                        result["secrets_found"].append({
                            "type": secret_type,
                            "value": match_str[:50] + "..." if len(match_str) > 50 else match_str,
                            "severity": "critical" if secret_type in ["AWS Key", "Private Key", "GitHub Token"] else "high"
                        })
        
        # Deduplicate
        seen = set()
        result["secrets_found"] = [s for s in result["secrets_found"] if not (s["value"] in seen or seen.add(s["value"]))]
        
    except Exception as e:
        result["error"] = str(e)
    
    return result

# MITRE ATT&CK Mapping for findings
MITRE_MAPPING = {
    "missing_security_headers": {"tactic": "Initial Access", "technique": "T1190", "name": "Exploit Public-Facing Application"},
    "weak_tls": {"tactic": "Collection", "technique": "T1557", "name": "Adversary-in-the-Middle"},
    "exposed_credentials": {"tactic": "Credential Access", "technique": "T1552", "name": "Unsecured Credentials"},
    "subdomain_takeover": {"tactic": "Resource Development", "technique": "T1584.001", "name": "Compromise Infrastructure: Domains"},
    "cors_misconfiguration": {"tactic": "Initial Access", "technique": "T1189", "name": "Drive-by Compromise"},
    "dangerous_http_methods": {"tactic": "Persistence", "technique": "T1505", "name": "Server Software Component"},
    "exposed_admin": {"tactic": "Initial Access", "technique": "T1190", "name": "Exploit Public-Facing Application"},
    "javascript_secrets": {"tactic": "Credential Access", "technique": "T1552.001", "name": "Credentials In Files"},
}

def apply_mitre_mapping(results: dict):
    """Apply MITRE ATT&CK mapping to scan results"""
    mitre_findings = []
    
    # Check security headers
    if results.get("sec_headers", {}).get("rows"):
        missing = [r for r in results["sec_headers"]["rows"] if r.get("status") == "WARN"]
        if missing:
            mitre_findings.append({**MITRE_MAPPING["missing_security_headers"], "evidence": f"{len(missing)} missing security headers"})
    
    # Check TLS
    if results.get("ssl_tls", {}).get("grade") in ["D", "F"]:
        mitre_findings.append({**MITRE_MAPPING["weak_tls"], "evidence": f"TLS Grade: {results['ssl_tls']['grade']}"})
    
    # Check JS secrets
    if results.get("js_secrets", {}).get("secrets_found"):
        mitre_findings.append({**MITRE_MAPPING["javascript_secrets"], "evidence": f"{len(results['js_secrets']['secrets_found'])} secrets found"})
    
    # Check subdomain takeover
    if results.get("subdomain_takeover", {}).get("vulnerable"):
        mitre_findings.append({**MITRE_MAPPING["subdomain_takeover"], "evidence": "Subdomain takeover possible"})
    
    # Check CORS
    if results.get("cors", {}).get("vulnerable"):
        mitre_findings.append({**MITRE_MAPPING["cors_misconfiguration"], "evidence": results["cors"].get("issues", ["CORS issue"])[0]})
    
    # Check HTTP methods
    if results.get("http_methods", {}).get("dangerous"):
        mitre_findings.append({**MITRE_MAPPING["dangerous_http_methods"], "evidence": f"Dangerous methods: {[d['method'] for d in results['http_methods']['dangerous']]}"})
    
    return {"findings": mitre_findings, "count": len(mitre_findings)}

SECURITY_TXT_PATHS = [
    "/.well-known/security.txt",
    "/security.txt",
]

SENSITIVE_ROBOTS_KEYWORDS = [
    "admin",
    "backup",
    "config",
    "secret",
    "internal",
    "staging",
    "dev",
    "test",
    "beta",
    "private",
    "tmp",
    "hidden",
]

EXPOSURE_PATHS = [
    {"path": "/.git/config", "severity": "high", "description": "Git repository configuration"},
    {"path": "/.env", "severity": "high", "description": "Environment variables"},
    {"path": "/server-status", "severity": "medium", "description": "Apache status handler"},
    {"path": "/phpinfo.php", "severity": "medium", "description": "PHP configuration dump"},
    {"path": "/.svn/entries", "severity": "medium", "description": "SVN metadata"},
    {"path": "/backup.zip", "severity": "high", "description": "Backup archive"},
    {"path": "/db.sql", "severity": "high", "description": "Database dump"},
    {"path": "/config.old", "severity": "medium", "description": "Legacy configuration file"},
    {"path": "/.idea/workspace.xml", "severity": "low", "description": "IDE project metadata"},
    {"path": "/.DS_Store", "severity": "low", "description": "Directory index leak"},
    {"path": "/aws.yml", "severity": "medium", "description": "Cloud configuration"},
    {"path": "/storage.tar.gz", "severity": "high", "description": "Archive of application data"},
]

SIGNATURE_PATTERNS = [
    {"name": "Magecart Skimmer", "pattern": re.compile(r"skimmer|magecart", re.I), "severity": "high"},
    {"name": "Crypto Miner", "pattern": re.compile(r"CoinHive|cryptonight", re.I), "severity": "medium"},
    {"name": "Phishing Kit", "pattern": re.compile(r"login\.php\?auth|otp-bypass", re.I), "severity": "high"},
]

FUZZ_PAYLOADS = [
    {"name": "debug_flag", "method": "GET", "params": {"debug": "1"}, "description": "Attempt to enable verbose/debug output"},
    {"name": "verbose_mode", "method": "GET", "params": {"verbose": "true"}, "description": "Toggle verbose flag"},
    {"name": "path_traversal", "method": "GET", "params": {"file": "../../../../etc/passwd"}, "description": "Probe file traversal"},
    {"name": "sql_injection_id", "method": "GET", "params": {"id": "1' OR '1'='1"}, "description": "Classic SQLi id param"},
    {"name": "sqli_search", "method": "GET", "params": {"search": "\" OR \"1\"=\"1"}, "description": "Quote-based SQLi"},
    {"name": "json_admin", "method": "POST", "json": {"role": "admin", "debug": True}, "description": "POST JSON privilege escalation"},
    {"name": "form_override", "method": "POST", "data": {"is_admin": "true", "price": "0"}, "description": "Form tampering"},
    {"name": "header_origin", "method": "GET", "params": {}, "headers": {"X-Forwarded-For": "127.0.0.1", "Origin": "https://evil.tld"}, "description": "Header manipulation"},
    {"name": "template_injection", "method": "GET", "params": {"msg": "{{7*7}}"}, "description": "SSTI probe"},
    {"name": "command_injection", "method": "GET", "params": {"cmd": "1; cat /etc/passwd"}, "description": "Command injection test"},
]

FUZZ_ALERT_TERMS = [
    "exception",
    "stack trace",
    "sql syntax",
    "mysql",
    "postgres",
    "syntax error",
    "warning",
    "fatal",
    "undefined",
    "traceback",
    "internal server error",
]

CVE_TECH_MAPPING = {
    "apache": ("apache", "http_server"),
    "nginx": ("nginx", "nginx"),
    "wordpress": ("wordpress", "wordpress"),
    "react": ("facebook", "react"),
    "django": ("djangoproject", "django"),
    "express": ("nodejs", "express"),
}

CODE_SCAN_PATTERNS = [
    ("Hardcoded password", re.compile(r"password\s*=\s*['\"]", re.I)),
    ("API key literal", re.compile(r"api_key\s*=\s*['\"]", re.I)),
    ("Suspicious eval", re.compile(r"eval\(", re.I)),
    ("AWS Secret", re.compile(r"(?i)aws_secret_access_key")),
]

def fetch_security_txt(base_url: str):
    files = []
    errors = []
    for path in SECURITY_TXT_PATHS:
        url = urljoin(base_url, path)
        try:
            resp = SESSION.get(url, timeout=DEFAULT_TIMEOUT, allow_redirects=True)
        except requests.RequestException as exc:
            errors.append({"path": path, "url": url, "error": str(exc)})
            continue
        if resp.status_code >= 400 or not resp.text.strip():
            continue
        entries = []
        for raw_line in resp.text.splitlines():
            line = raw_line.strip()
            if not line or line.startswith("#") or ":" not in line:
                continue
            key, value = line.split(":", 1)
            entries.append({"field": key.strip(), "value": value.strip()})
        if entries:
            files.append({
                "path": path,
                "url": url,
                "status": resp.status_code,
                "entries": entries,
                "size": len(resp.text),
                "last_modified": resp.headers.get("Last-Modified"),
            })
    result = {"found": bool(files), "files": files}
    if not files:
        result["message"] = "security.txt not found"
    if errors:
        result["errors"] = errors
    return result

def robots_txt_report(base_url: str):
    url = urljoin(base_url, "/robots.txt")
    try:
        resp = SESSION.get(url, timeout=DEFAULT_TIMEOUT, allow_redirects=True)
    except requests.RequestException as exc:
        return {"error": str(exc)}
    if resp.status_code >= 400:
        return {"error": f"robots.txt returned status {resp.status_code}"}
    rules = []
    suspicious = []
    for raw_line in resp.text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or ":" not in line:
            continue
        directive, value = line.split(":", 1)
        directive = directive.strip()
        value = value.strip()
        directive_norm = directive.lower()
        if directive_norm in ("allow", "disallow"):
            rule = {"directive": directive.capitalize(), "path": value}
            rules.append(rule)
            lowered = value.lower()
            for keyword in SENSITIVE_ROBOTS_KEYWORDS:
                if keyword in lowered:
                    suspicious.append({**rule, "keyword": keyword})
                    break
    return {
        "url": url,
        "status": resp.status_code,
        "rules": rules,
        "suspicious": suspicious,
        "last_modified": resp.headers.get("Last-Modified"),
    }

def exposure_checks(base_url: str, extra_paths=None):
    rows = []
    targets = list(EXPOSURE_PATHS)
    for raw in extra_paths or []:
        value = raw.strip()
        if not value:
            continue
        severity = "medium"
        desc = "Custom path"
        path = value
        if "::" in value:
            prefix, remainder = value.split("::", 1)
            severity = prefix.lower() or severity
            path = remainder.strip() or path
        if not path.startswith("/"):
            path = "/" + path.lstrip("/")
        targets.append({"path": path, "severity": severity, "description": desc})
    for entry in targets:
        path = entry["path"]
        severity = entry.get("severity", "medium")
        description = entry.get("description", "Custom path")
        url = urljoin(base_url, path)
        status = "Error"
        length = None
        content_type = None
        error = None
        try:
            resp = SESSION.head(url, timeout=5, allow_redirects=True)
            status = resp.status_code
            length = resp.headers.get("Content-Length")
            content_type = resp.headers.get("Content-Type")
            if status in (403, 405):
                resp = SESSION.get(url, timeout=5, allow_redirects=True)
                status = resp.status_code
                length = resp.headers.get("Content-Length") or len(resp.content)
                content_type = resp.headers.get("Content-Type")
        except requests.RequestException as exc:
            error = str(exc)
        rows.append({
            "path": path,
            "url": url,
            "status": status,
            "length": length,
            "severity": severity,
            "description": description,
            "content_type": content_type,
            "error": error,
        })
    return {"rows": rows}

JS_SECRET_PATTERNS = [("AWS Access Key", re.compile(r"AKIA[0-9A-Z]{16}"))]
def js_secrets_from_page(url: str):
    rows = []
    try:
        r = http_get(url)
        if hasattr(r, 'error'):
            return {"rows": []}
        soup = BeautifulSoup(r.text, "html.parser")
        for script in soup.find_all("script", src=True):
            script_url = urljoin(url, script['src'])
            script_r = http_get(script_url)
            if hasattr(script_r, 'error'):
                continue
            for name, pattern in JS_SECRET_PATTERNS:
                for match in pattern.finditer(script_r.text):
                    rows.append({"file": script_url, "type": name, "value": match.group(0)})
    except Exception:
        pass
    return {"rows": rows}

def hibp_lookup(emails):
    if not HIBP_API_KEY:
        return {"error": "HIBP_API_KEY not set."}
    headers = {
        "hibp-api-key": HIBP_API_KEY,
        "user-agent": USER_AGENT,
    }
    checked = []
    rows = []
    for idx, email in enumerate(emails or []):
        email_norm = email.strip()
        if not email_norm or email_norm in checked:
            continue
        url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{email_norm}"
        try:
            resp = SESSION.get(url, headers=headers, params={"truncateResponse": "true"}, timeout=DEFAULT_TIMEOUT)
            if resp.status_code == 404:
                rows.append({"email": email_norm, "breached": False, "breaches": []})
            elif resp.ok:
                breaches = resp.json()
                rows.append({"email": email_norm, "breached": True, "breaches": [b.get("Name") for b in breaches]})
            else:
                rows.append({"email": email_norm, "error": f"{resp.status_code}: {resp.text}"})
        except Exception as exc:
            rows.append({"email": email_norm, "error": str(exc)})
        checked.append(email_norm)
        if idx != len(emails) - 1:
            time.sleep(1.6)
    return {"rows": rows}

async def _screenshot_async(url: str):
    browser = await launch(headless=True, args=["--no-sandbox", "--disable-gpu"])
    page = await browser.newPage()
    await page.setViewport({"width": 1280, "height": 720})
    await page.goto(url, timeout=SCREENSHOT_TIMEOUT * 1000, waitUntil="networkidle2")
    data = await page.screenshot(fullPage=True)
    await browser.close()
    return base64.b64encode(data).decode()

def capture_screenshot(url: str):
    if launch is None:
        return {"error": "pyppeteer is not installed"}
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        encoded = loop.run_until_complete(_screenshot_async(url))
        return {"data_uri": f"data:image/png;base64,{encoded}"}
    except Exception as exc:
        return {"error": str(exc)}
    finally:
        loop.close()

def signature_scan(html_text: str):
    rows = []
    if not html_text:
        return {"rows": rows}
    for sig in SIGNATURE_PATTERNS:
        if sig["pattern"].search(html_text):
            rows.append({"name": sig["name"], "severity": sig["severity"]})
    return {"rows": rows}

def parameter_fuzzer(url: str):
    rows = []
    baseline = {}
    try:
        base_resp = SESSION.get(url, timeout=DEFAULT_TIMEOUT, allow_redirects=True)
        baseline = {
            "status": base_resp.status_code,
            "length": int(base_resp.headers.get("Content-Length") or len(base_resp.content)),
        }
    except requests.RequestException:
        baseline = {}

    for payload in FUZZ_PAYLOADS:
        method = (payload.get("method") or "GET").upper()
        headers = payload.get("headers") or {}
        req_kwargs = {
            "timeout": DEFAULT_TIMEOUT,
            "allow_redirects": True,
            "headers": headers if headers else None,
        }
        if method == "GET":
            req_kwargs["params"] = payload.get("params")
        else:
            req_kwargs["params"] = payload.get("params")
            if payload.get("json") is not None:
                req_kwargs["json"] = payload.get("json")
            if payload.get("data") is not None:
                req_kwargs["data"] = payload.get("data")
        req_kwargs = {k: v for k, v in req_kwargs.items() if v is not None}

        try:
            resp = SESSION.request(method, url, **req_kwargs)
            try:
                body = resp.text
            except Exception:
                body = resp.content.decode("latin-1", errors="ignore")
            length = int(resp.headers.get("Content-Length") or len(body))
            keywords = []
            low_body = body.lower()
            for term in FUZZ_ALERT_TERMS:
                if term in low_body:
                    keywords.append(term)
            reflected = False
            candidate_values = []
            for source in ("params", "data", "json"):
                values = payload.get(source)
                if isinstance(values, dict):
                    candidate_values.extend([str(v) for v in values.values() if isinstance(v, (str, int, float))])
            for value in candidate_values:
                val = str(value).strip()
                if val and val.lower() in low_body:
                    reflected = True
                    break
            severity = "info"
            notes = []
            if resp.status_code >= 500:
                severity = "high"
                notes.append("Server error response")
            elif resp.status_code >= 400:
                severity = "medium"
                notes.append("Client error response")

            if baseline:
                delta = abs(length - baseline.get("length", length))
                threshold = max(200, baseline.get("length", 1) * 0.3)
                if delta > threshold:
                    severity = "medium" if severity == "info" else severity
                    notes.append(f"Response size deviates by {delta} bytes")

            if keywords:
                severity = "high" if severity != "high" else severity
                notes.append(f"Keywords: {', '.join(keywords[:5])}")

            if reflected:
                severity = "high"
                notes.append("Payload reflected in response body")

            rows.append({
                "name": payload["name"],
                "method": method,
                "params": payload.get("params") or payload.get("data") or payload.get("json"),
                "status": resp.status_code,
                "length": length,
                "redirected": bool(resp.history),
                "severity": severity,
                "notes": notes,
                "keywords": keywords,
                "reflected": reflected,
                "description": payload.get("description"),
            })
        except requests.RequestException as exc:
            rows.append({
                "name": payload["name"],
                "method": method,
                "params": payload.get("params") or payload.get("data") or payload.get("json"),
                "error": str(exc),
                "severity": "info",
                "notes": [],
                "keywords": [],
                "reflected": False,
                "description": payload.get("description"),
            })
    return {"rows": rows, "baseline": baseline}

def cloud_asset_inventory(domain: str):
    if not domain:
        return {"error": "Domain required"}
    if boto3 is None:
        return {"error": "boto3 is not installed"}
    session = boto3.session.Session(region_name=AWS_REGION)
    findings = {"s3": []}
    try:
        s3 = session.client("s3")
        buckets = s3.list_buckets().get("Buckets", [])
        for bucket in buckets:
            name = bucket.get("Name", "")
            if domain.split(".")[0] in name:
                findings["s3"].append({"name": name, "created": str(bucket.get("CreationDate"))})
    except Exception as exc:
        return {"error": str(exc)}
    if not findings["s3"]:
        findings["message"] = "No S3 buckets matched the domain keyword."
    return findings

def code_static_analysis(github_results):
    items = (github_results or {}).get("items", [])
    if not items:
        return {"rows": [], "message": "No GitHub code to analyze."}
    rows = []
    headers = {"Accept": "application/vnd.github+json"}
    if GITHUB_TOKEN:
        headers["Authorization"] = f"Bearer {GITHUB_TOKEN}"
    for item in items[:3]:
        meta_url = item.get("url")
        if not meta_url:
            continue
        try:
            meta_resp = SESSION.get(meta_url, headers=headers, timeout=DEFAULT_TIMEOUT)
            if not meta_resp.ok:
                continue
            meta = meta_resp.json()
            download_url = meta.get("download_url")
            if not download_url:
                continue
            content_resp = SESSION.get(download_url, timeout=DEFAULT_TIMEOUT)
            if not content_resp.ok:
                continue
            text = content_resp.text
            findings = []
            for name, pattern in CODE_SCAN_PATTERNS:
                if pattern.search(text):
                    findings.append(name)
            if findings:
                rows.append({
                    "file": item.get("html_url"),
                    "repo": item.get("repository", {}).get("full_name"),
                    "findings": findings,
                })
        except requests.RequestException:
            continue
    return {"rows": rows}

def cve_lookup_from_stack(stack_entries):
    alerts = []
    queried = set()
    for entry in stack_entries or []:
        if not isinstance(entry, str):
            continue
        lowered = entry.lower()
        for keyword, (vendor, product) in CVE_TECH_MAPPING.items():
            if keyword in lowered:
                if keyword in queried:
                    continue
                try:
                    resp = SESSION.get(f"https://cve.circl.lu/api/search/{vendor}/{product}", timeout=DEFAULT_TIMEOUT)
                    if resp.ok:
                        payload = resp.json()
                        if isinstance(payload, dict):
                            if isinstance(payload.get("data"), list):
                                entries = payload["data"]
                            elif isinstance(payload.get("results"), list):
                                entries = payload["results"]
                            else:
                                entries = list(payload.values()) if all(isinstance(v, dict) for v in payload.values()) else [payload]
                        else:
                            entries = payload or []
                        for item in (entries or [])[:3]:
                            if not isinstance(item, dict):
                                continue
                            alerts.append({
                                "tech": keyword,
                                "id": item.get("id"),
                                "summary": item.get("summary", "")[:200],
                                "cvss": item.get("cvss"),
                            })
                        queried.add(keyword)
                except requests.RequestException:
                    continue
    return {"rows": alerts}

def owasp_top10_audit(results, scheme="http"):
    findings = []
    exposure_mod = results.get("exposure_checks")
    exposures = exposure_mod.get("rows", []) if isinstance(exposure_mod, dict) else None
    sec_headers_mod = results.get("sec_headers")
    sec_headers = sec_headers_mod.get("rows", []) if isinstance(sec_headers_mod, dict) else None
    fuzzer_mod = results.get("fuzzer")
    fuzzer = fuzzer_mod.get("rows", []) if isinstance(fuzzer_mod, dict) else None
    cves_mod = results.get("cve_alerts")
    cves = cves_mod.get("rows", []) if isinstance(cves_mod, dict) else None
    tls = results.get("tls")
    security_txt = results.get("security_txt")

    def add(category, status, evidence):
        findings.append({
            "category": category,
            "status": status,
            "evidence": evidence,
        })

    # A01: Broken Access Control
    if exposures is None:
        add("A01: Broken Access Control", "unknown", "Exposure module not executed")
    else:
        exposed = [
            row for row in exposures
            if isinstance(row.get("status"), int) and 200 <= row["status"] < 400 and row.get("severity") in ("high", "medium")
        ]
        if exposed:
            add("A01: Broken Access Control", "fail", f"{len(exposed)} sensitive paths accessible (e.g., {exposed[0]['path']})")
        else:
            add("A01: Broken Access Control", "ok", "No sensitive paths responded successfully")

    # A02: Cryptographic Failures
    if scheme != "https":
        add("A02: Cryptographic Failures", "fail", "Site served over non-HTTPS scheme")
    elif not tls:
        add("A02: Cryptographic Failures", "unknown", "TLS module not executed")
    elif tls.get("error"):
        add("A02: Cryptographic Failures", "warn", f"TLS error: {tls['error']}")
    else:
        add("A02: Cryptographic Failures", "ok", "HTTPS enforced and TLS handshake succeeded")

    # A03: Injection
    if fuzzer is None:
        add("A03: Injection", "unknown", "Fuzzer module not executed")
    else:
        injection_hits = [row for row in fuzzer if row.get("severity") == "high"]
        if injection_hits:
            add("A03: Injection", "fail", f"High-risk fuzzer payload detected ({injection_hits[0]['name']})")
        else:
            add("A03: Injection", "ok", "No high-risk payload reflections detected")

    # A05: Security Misconfiguration (using OWASP 2021 numbering where A05)
    if sec_headers is None:
        add("A05: Security Misconfiguration", "unknown", "Security headers module not executed")
    else:
        missing_headers = [row for row in sec_headers if row.get("status") != "OK"]
        if missing_headers:
            add("A05: Security Misconfiguration", "warn", f"{len(missing_headers)} missing security headers")
        else:
            add("A05: Security Misconfiguration", "ok", "Core security headers present")

    # A06: Vulnerable and Outdated Components
    if cves is None:
        add("A06: Vulnerable Components", "unknown", "CVE lookup module not executed")
    elif cves:
        add("A06: Vulnerable Components", "warn", f"{len(cves)} known CVEs related to stack (e.g., {cves[0]['id']})")
    else:
        add("A06: Vulnerable Components", "ok", "No CVE alerts for detected technologies")

    # A07: Identification and Authentication Failures (heuristic using exposures to auth endpoints)
    if exposures is None:
        add("A07: Identification & Auth Failures", "unknown", "Exposure module not executed")
    else:
        auth_exposures = [
            row for row in exposures
            if isinstance(row.get("path"), str) and ("login" in row["path"].lower() or "auth" in row["path"].lower())
        ]
        if auth_exposures:
            add("A07: Identification & Auth Failures", "warn", f"Potential auth endpoint exposed ({auth_exposures[0]['path']})")
        else:
            add("A07: Identification & Auth Failures", "ok", "No obvious authentication endpoints exposed")

    # A09: Security Logging and Monitoring Failures (heuristic)
    if security_txt is None:
        add("A09: Security Logging & Monitoring", "unknown", "security.txt module not executed")
    elif not security_txt.get("found"):
        add("A09: Security Logging & Monitoring", "warn", "security.txt not discovered (limited contact info)")
    else:
        add("A09: Security Logging & Monitoring", "ok", "security.txt present")

    return {"rows": findings}

def extract_relationships(results):
    nodes = {}
    edges = []
    def add_node(identifier, label, group):
        if identifier in nodes:
            return
        nodes[identifier] = {"id": identifier, "label": label, "group": group}

    subdomains = results.get("subdomain_scan", {}).get("rows", [])
    for row in subdomains:
        sub = row.get("subdomain")
        if not sub:
            continue
        add_node(sub, sub, "subdomain")
        for addr in row.get("a_records", []):
            add_node(addr, addr, "ip")
            edges.append({"from": sub, "to": addr})
    emails = results.get("crawler", {}).get("emails", [])
    for email in emails:
        add_node(email, email, "email")
        if results.get("_meta", {}).get("base_domain"):
            edges.append({"from": results["_meta"]["base_domain"], "to": email})
    links = results.get("crawler", {}).get("external_links", [])
    for link in links[:200]:
        add_node(link, link, "link")
        if results.get("_meta", {}).get("base_domain"):
            edges.append({"from": results["_meta"]["base_domain"], "to": link})
    base = results.get("_meta", {}).get("base_domain")
    if base:
        add_node(base, base, "domain")
    return list(nodes.values()), edges

def submit_to_sandbox(content, url):
    if not MALWARE_SANDBOX_URL or not content:
        return {"error": "Sandbox not configured or no payload."}
    try:
        resp = SESSION.post(
            MALWARE_SANDBOX_URL,
            headers={"Authorization": f"Bearer {MALWARE_SANDBOX_KEY}"} if MALWARE_SANDBOX_KEY else None,
            json={"url": url, "content": content[:500000]},
            timeout=DEFAULT_TIMEOUT,
        )
        if resp.ok:
            return resp.json()
        return {"error": f"{resp.status_code}: {resp.text}"}
    except requests.RequestException as exc:
        return {"error": str(exc)}

def run_workflow(url, steps):
    if not steps:
        return {"logs": ["No steps provided."], "status": "skipped"}
    if sync_playwright is None:
        return {"error": "playwright is not installed"}
    logs = []
    steps = steps[:WORKFLOW_MAX_STEPS]
    def log(msg):
        logs.append(msg)
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            page = browser.new_page()
            page.goto(url, timeout=DEFAULT_TIMEOUT * 1000)
            log(f"Goto {url}")
            for step in steps:
                action = (step.get("action") or "").lower()
                if action == "goto":
                    target = step.get("url", url)
                    page.goto(target, timeout=DEFAULT_TIMEOUT * 1000)
                    log(f"Goto {target}")
                elif action == "click":
                    selector = step.get("selector")
                    if selector:
                        page.click(selector, timeout=DEFAULT_TIMEOUT * 1000)
                        log(f"Click {selector}")
                elif action == "type":
                    selector = step.get("selector")
                    value = step.get("value", "")
                    if selector:
                        page.fill(selector, value)
                        log(f"Type into {selector}")
                elif action == "wait":
                    delay = int(step.get("ms", 1000))
                    page.wait_for_timeout(delay)
                    log(f"Wait {delay}ms")
            snapshot = page.content()
            browser.close()
        return {"logs": logs, "snapshot": snapshot}
    except Exception as exc:
        return {"error": str(exc), "logs": logs}

# ---------------- Summary & Orchestrator ----------------
def build_summary(results):
    s = {
        "subdomains": len(results.get("subdomain_scan", {}).get("rows", [])) or len(results.get("subdomain_scan", {}).get("found", [])),
        "missing_sec_headers": 0,
        "vt_malicious": 0,
        "risk_score": 0,
        "risk_level": "low",
    }
    sh = results.get("sec_headers", {})
    for r in sh.get("rows", []):
        if r.get("status") != "OK":
            s["missing_sec_headers"] += 1
    vt = results.get("virustotal", {})
    stats = (vt.get("data", {}) or {}).get("attributes", {}).get("last_analysis_stats", {})
    try:
        s["vt_malicious"] = int(stats.get("malicious", 0) or 0)
    except Exception:
        s["vt_malicious"] = 0
    score = 0
    score += s["missing_sec_headers"] * 2
    score += min(50, s["vt_malicious"] * 5)
    exposures = results.get("exposure_checks", {}).get("rows", [])
    severity_weight = {"high": 15, "medium": 7, "low": 3, "custom": 5}
    for row in exposures:
        status = row.get("status")
        if isinstance(status, int) and 200 <= status < 400:
            score += severity_weight.get(row.get("severity"), 5)
    robots = results.get("robots_txt", {}).get("suspicious") or []
    score += len(robots) * 2
    signatures = results.get("signature_hits", {}).get("rows", [])
    score += len(signatures) * 5
    cve_hits = results.get("cve_alerts", {}).get("rows", [])
    score += len(cve_hits) * 3
    owasp = results.get("owasp_top10", {}).get("rows", [])
    for item in owasp:
        if item.get("status") == "fail":
            score += 8
        elif item.get("status") == "warn":
            score += 4
    hibp = results.get("hibp", {}).get("rows", [])
    for entry in hibp:
        if entry.get("breached"):
            score += 10 + len(entry.get("breaches") or []) * 2
    s["risk_score"] = score
    if score >= 60:
        s["risk_level"] = "high"
    elif score >= 30:
        s["risk_level"] = "medium"
    return s

def maybe_send_notification(url, summary, results):
    if not SLACK_WEBHOOK_URL:
        return
    score = summary.get("risk_score", 0)
    if score < ALERT_THRESHOLD:
        return
    payload = {
        "text": f"AEGIS alert ({summary.get('risk_level')}) for {url}",
        "attachments": [
            {
                "color": "#dc2626" if summary.get("risk_level") == "high" else "#f59e0b",
                "fields": [
                    {"title": "Risk Score", "value": str(score), "short": True},
                    {"title": "VT Malicious", "value": str(summary.get("vt_malicious", 0)), "short": True},
                    {"title": "Missing Sec Headers", "value": str(summary.get("missing_sec_headers", 0)), "short": True},
                ]
            }
        ]
    }
    try:
        requests.post(SLACK_WEBHOOK_URL, json=payload, timeout=5)
    except requests.RequestException:
        pass

def summarize_changes(old_results, new_results):
    diffs = {}
    old_sd = set((old_results or {}).get("subdomain_scan", {}).get("found", []))
    new_sd = set(new_results.get("subdomain_scan", {}).get("found", []))
    added_sd = sorted(new_sd - old_sd)
    if added_sd:
        diffs["subdomains_added"] = added_sd

    def successful_exposures(res):
        rows = (res or {}).get("exposure_checks", {}).get("rows", [])
        paths = set()
        for row in rows:
            status = row.get("status")
            if isinstance(status, int) and 200 <= status < 400:
                paths.add(row.get("path"))
        return paths

    new_exposures = successful_exposures(new_results) - successful_exposures(old_results or {})
    if new_exposures:
        diffs["new_exposures"] = sorted(new_exposures)
    return diffs

def notify_diff(url, diff):
    if not SLACK_WEBHOOK_URL or not diff:
        return
    fields = []
    if diff.get("subdomains_added"):
        fields.append({"title": "New Subdomains", "value": "\n".join(diff["subdomains_added"][:5]), "short": False})
    if diff.get("new_exposures"):
        fields.append({"title": "New Exposures", "value": "\n".join(diff["new_exposures"][:5]), "short": False})
    payload = {
        "text": f"AEGIS scheduled diff for {url}",
        "attachments": [{"color": "#2563eb", "fields": fields}]
    }
    try:
        requests.post(SLACK_WEBHOOK_URL, json=payload, timeout=5)
    except requests.RequestException:
        pass

def schedule_recurring_scan(url, services, mode, extras, minutes):
    if minutes <= 0:
        return
    db = get_db()
    next_run = (datetime.utcnow() + timedelta(minutes=minutes)).isoformat()
    db.execute(
        """
        INSERT INTO scheduled_scans (url, services, mode, extras, interval_minutes, next_run)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (
            url,
            json.dumps(services),
            mode,
            json.dumps(extras or {}),
            minutes,
            next_run,
        ),
    )
    db.commit()

def process_schedules():
    if app.config.get("_processing_schedule"):
        return
    db = get_db()
    now = datetime.utcnow().isoformat()
    try:
        row = db.execute(
            "SELECT * FROM scheduled_scans WHERE next_run <= ? ORDER BY next_run ASC LIMIT 1",
            (now,),
        ).fetchone()
    except sqlite3.OperationalError:
        return
    if not row:
        return
    app.config["_processing_schedule"] = True
    try:
        services = json.loads(row["services"])
        extras = json.loads(row["extras"] or "{}")
        old_results = json.loads(row["last_results"]) if row["last_results"] else {}
        results, url_norm = run_scan(
            row["url"],
            services,
            row["mode"],
            extras.get("subdomains"),
            extras.get("exposures"),
            extras.get("workflow"),
            scheduled_run=True,
        )
        next_run = (datetime.utcnow() + timedelta(minutes=row["interval_minutes"])).isoformat()
        db.execute(
            "UPDATE scheduled_scans SET next_run=?, last_run=?, last_results=? WHERE id=?",
            (next_run, datetime.utcnow().isoformat(), json.dumps(results), row["id"]),
        )
        db.commit()
        diff = summarize_changes(old_results, results)
        notify_diff(url_norm, diff)
    finally:
        app.config["_processing_schedule"] = False

@app.before_request
def _schedule_tick():
    process_schedules()

def compute_anomalies(url, summary):
    db = get_db()
    rows = db.execute(
        "SELECT results FROM scans WHERE url=? ORDER BY id DESC LIMIT 10",
        (url,),
    ).fetchall()
    if not rows:
        return {"message": "Baseline unavailable."}
    metrics = {"missing_sec_headers": [], "vt_malicious": [], "risk_score": []}
    for row in rows:
        try:
            data = json.loads(row["results"])
            summ = data.get("_summary", {})
            for key in metrics:
                if key in summ:
                    metrics[key].append(float(summ.get(key, 0)))
        except Exception:
            continue
    anomalies = {}
    for key, values in metrics.items():
        if not values:
            continue
        avg = sum(values) / len(values)
        diff = summary.get(key, 0) - avg
        if abs(diff) >= max(1, avg * 0.5):
            anomalies[key] = {"average": round(avg, 2), "current": summary.get(key, 0), "delta": round(diff, 2)}
    return anomalies or {"message": "No significant deviations."}

def maybe_create_ticket(url, summary, results):
    if not TICKET_WEBHOOK_URL:
        return
    if summary.get("risk_score", 0) < AUTO_TICKET_THRESHOLD:
        return
    exposures = results.get("exposure_checks", {}).get("rows", [])
    high_exposures = [r for r in exposures if r.get("severity") == "high" and isinstance(r.get("status"), int) and r["status"] < 400]
    payload = {
        "summary": f"AEGIS alert for {url} (risk {summary.get('risk_score')})",
        "details": {
            "missing_sec_headers": summary.get("missing_sec_headers"),
            "vt_malicious": summary.get("vt_malicious"),
            "high_exposures": high_exposures[:5],
            "timestamp": datetime.utcnow().isoformat()
        }
    }
    try:
        requests.post(TICKET_WEBHOOK_URL, json=payload, timeout=5)
    except requests.RequestException:
        pass

def run_scan(url_to_scan, selected_services, mode, extra_subdomain_words=None, extra_exposure_paths=None, workflow_steps=None, scheduled_run=False):
    url_norm = url_normalize(url_to_scan)
    parsed_url = urlparse(url_norm)
    domain = parsed_url.hostname or get_domain(url_norm)
    results = {}
    module_times = {}
    t0 = time.perf_counter()

    workflow_steps = workflow_steps or []
    def run_mod(name, cond, func, *args, **kwargs):
        if not cond:
            return
        start = time.perf_counter()
        try:
            out = func(*args, **kwargs)
        finally:
            module_times[name] = round(time.perf_counter() - start, 3)
        results[name] = out

    # Base response for fingerprinting
    base_resp = http_get(url_norm)
    headers = base_resp.headers if not hasattr(base_resp, 'error') else {}
    html_text = base_resp.text if not hasattr(base_resp, 'error') else ""

    run_mod("crawler",      "crawler" in selected_services, crawl_website, url_norm)
    run_mod("http_headers", "headers" in selected_services, get_http_headers, url_norm)
    run_mod("tech",         "tech" in selected_services, fingerprint, headers, html_text)
    run_mod("signature_hits", "signatures" in selected_services, signature_scan, html_text)
    run_mod("cve_alerts",   "cve_alerts" in selected_services and results.get("tech"), cve_lookup_from_stack, results.get("tech", {}).get("stack"))
    run_mod("sec_headers",  "sec_headers" in selected_services, security_headers_report, headers)
    run_mod("tls",          "tls" in selected_services and domain, tls_info, domain)
    run_mod("whois_lookup", "whois" in selected_services and domain, get_whois_info, domain)
    run_mod("dns_records",  "dns" in selected_services and domain, get_dns_records, domain)
    run_mod("subdomain_scan", "subdomains" in selected_services and domain, subdomain_scan, domain, mode, extra_subdomain_words or [])
    run_mod("securitytrails", "securitytrails" in selected_services and domain, securitytrails_lookup, domain)
    run_mod("cloud_assets", "cloud_assets" in selected_services and domain, cloud_asset_inventory, domain)
    run_mod("virustotal",   "virustotal" in selected_services, vt_url_lookup, url_norm)
    run_mod("urlscan",      "urlscan" in selected_services and domain, urlscan_search_domain, domain)
    run_mod("archive_org",  "archive" in selected_services, archive_cdx, url_norm)
    run_mod("security_txt", "security_txt" in selected_services, fetch_security_txt, url_norm)
    run_mod("robots_txt",   "robots_txt" in selected_services, robots_txt_report, url_norm)
    run_mod("otx",          "otx" in selected_services and domain, otx_domain_general, domain)
    run_mod("github",       "github" in selected_services and domain, github_code_search, domain)
    run_mod("code_scan",    "code_scan" in selected_services and results.get("github"), code_static_analysis, results.get("github"))

    ip = ""
    if domain:
        try:
            ip = socket.gethostbyname(domain)
        except socket.gaierror:
            ip = ""

    run_mod("shodan",     "shodan" in selected_services and domain, shodan_lookup, domain)
    run_mod("greynoise",  "greynoise" in selected_services and ip, greynoise_lookup, ip)
    run_mod("abuseipdb",  "abuseipdb" in selected_services and ip, abuseipdb_lookup, ip)
    
    # New reconnaissance modules
    run_mod("waf_detect", "waf_detect" in selected_services, detect_waf, url_norm)
    run_mod("email_security", "email_security" in selected_services and domain, email_security_check, domain)
    run_mod("port_scan", "port_scan" in selected_services and domain, port_scan, domain)
    run_mod("asn_lookup", "asn_lookup" in selected_services and ip, asn_lookup, ip)
    run_mod("favicon_hash", "favicon_hash" in selected_services, favicon_hash, url_norm)
    
    # Advanced reconnaissance modules
    run_mod("ssl_tls", "ssl_tls" in selected_services and domain, ssl_tls_analysis, domain)
    run_mod("subdomain_takeover", "subdomain_takeover" in selected_services and domain, subdomain_takeover_check, domain)
    run_mod("http_methods", "http_methods" in selected_services, http_method_enum, url_norm)
    run_mod("cors", "cors" in selected_services, cors_check, url_norm)
    run_mod("cookie_audit", "cookie_audit" in selected_services, cookie_security_audit, url_norm)
    run_mod("js_secrets", "js_secrets" in selected_services, js_secret_scan, url_norm)
    
    run_mod("workflow",    "workflow" in selected_services and workflow_steps, run_workflow, url_norm, workflow_steps or [])
    run_mod("screenshot",  "screenshot" in selected_services, capture_screenshot, url_norm)
    run_mod("sandbox_report", "sandbox" in selected_services and html_text, submit_to_sandbox, html_text, url_norm)
    run_mod("fuzzer",      "fuzzer" in selected_services, parameter_fuzzer, url_norm)

    crawler_emails = results.get("crawler", {}).get("emails", [])
    run_mod("hibp", "hibp" in selected_services and crawler_emails, hibp_lookup, crawler_emails)

    should_run_exposure = ("exposure_checks" in selected_services) or mode == "semi"
    if should_run_exposure:
        run_mod("exposure_checks", True, exposure_checks, url_norm, extra_exposure_paths or [])
    if mode == "semi":
        run_mod("js_secrets", True, js_secrets_from_page, url_norm)

    current_scheme = parsed_url.scheme or "http"
    run_mod("owasp_top10", "owasp_top10" in selected_services, owasp_top10_audit, results, current_scheme)

    summary = build_summary(results)
    try:
        summary["anomalies"] = compute_anomalies(url_norm, summary)
    except Exception:
        summary["anomalies"] = {"message": "Baseline unavailable."}
    
    # Apply MITRE ATT&CK mapping
    results["mitre_attack"] = apply_mitre_mapping(results)
    
    results["_summary"] = summary
    results["_meta"] = {
        "total_seconds": round(time.perf_counter() - t0, 3),
        "module_times": {k: v for k, v in module_times.items() if v},
        "scheduled_run": scheduled_run,
        "base_domain": domain,
        "scheme": parsed_url.scheme or "http",
    }
    maybe_send_notification(url_norm, summary, results)
    maybe_create_ticket(url_norm, summary, results)
    return results, url_norm

# ---------------- Routes ----------------
@app.route("/", methods=["GET"])
def index():
    return render_template_string(INDEX_HTML)

@app.route("/scan", methods=["POST"])
def scan():
    url_to_scan = request.form["url"]
    selected = request.form.getlist("services")
    view_mode = request.form.get("view_mode", "human")
    mode = request.form.get("mode", "defensive")
    extra_subdomains = parse_multiline_values(request.form.get("extra_subdomains", ""))
    extra_exposures = parse_multiline_values(request.form.get("extra_exposures", ""))
    workflow_raw = request.form.get("workflow_steps", "").strip()
    workflow_steps = []
    if workflow_raw:
        try:
            data = json.loads(workflow_raw)
            if isinstance(data, list):
                workflow_steps = data
        except json.JSONDecodeError:
            workflow_steps = []
    schedule_minutes = 0
    try:
        schedule_minutes = int(request.form.get("schedule_minutes", "0") or 0)
    except ValueError:
        schedule_minutes = 0

    results, url_norm = run_scan(url_to_scan, selected, mode, extra_subdomains, extra_exposures, workflow_steps)

    if schedule_minutes > 0:
        schedule_recurring_scan(
            url_norm,
            selected,
            mode,
            {"subdomains": extra_subdomains, "exposures": extra_exposures, "workflow": workflow_steps},
            schedule_minutes,
        )

    # Persist & capture ID
    db = get_db()
    cur = db.execute(
        'INSERT INTO scans (url, results, scan_date) VALUES (?, ?, ?)',
        (url_norm, json.dumps(results), datetime.now().isoformat())
    )
    db.commit()
    scan_id = cur.lastrowid

    # Cache latest for exports
    app.config["LATEST_RESULTS"] = results
    app.config["LATEST_URL"] = url_norm
    app.config["LATEST_SCAN_ID"] = scan_id

    return render_template_string(
        RESULTS_HTML,
        results=results,
        url=url_norm,
        view_mode=view_mode,
        mode=mode,
        pdf_available=(HTML is not None),
        scan_id=scan_id
    )

@app.route("/history")
def history():
    db = get_db()
    rows = db.execute("SELECT id, url, scan_date FROM scans ORDER BY id DESC LIMIT 100").fetchall()
    return render_template_string(HISTORY_HTML, items=rows)

@app.route("/scheduled")
def scheduled():
    db = get_db()
    rows = db.execute(
        "SELECT id, url, services, interval_minutes, next_run, last_run FROM scheduled_scans ORDER BY next_run ASC"
    ).fetchall()
    items = []
    for row in rows:
        try:
            services = ", ".join(json.loads(row["services"]))
        except Exception:
            services = row["services"]
        items.append({
            "id": row["id"],
            "url": row["url"],
            "services": services,
            "interval_minutes": row["interval_minutes"],
            "next_run": row["next_run"],
            "last_run": row["last_run"],
        })
    return render_template_string(SCHEDULED_HTML, items=items)

@app.route("/view/<int:scan_id>")
def view_scan(scan_id):
    db = get_db()
    row = db.execute("SELECT id, url, results, scan_date FROM scans WHERE id=?", (scan_id,)).fetchone()
    if not row:
        return "Not found", 404
    results = json.loads(row["results"])
    # also set LATEST so exports work after viewing history
    app.config["LATEST_RESULTS"] = results
    app.config["LATEST_URL"] = row["url"]
    app.config["LATEST_SCAN_ID"] = row["id"]
    return render_template_string(
        RESULTS_HTML,
        results=results,
        url=row["url"],
        view_mode="human",
        mode="defensive",
        pdf_available=(HTML is not None),
        scan_id=row["id"]
    )

@app.route("/graph/<int:scan_id>")
def graph(scan_id):
    db = get_db()
    row = db.execute("SELECT results FROM scans WHERE id=?", (scan_id,)).fetchone()
    if not row:
        return "Not found", 404
    results = json.loads(row["results"])
    nodes, edges = extract_relationships(results)
    return render_template_string(GRAPH_HTML, nodes=nodes, edges=edges, scan_id=scan_id)

def flatten_results_for_csv(results):
    rows = []
    for key, value in results.items():
        if key.startswith("_"):
            continue
        if isinstance(value, dict) and 'rows' in value:
            for row in value['rows']:
                rows.append({'module': key, 'data': json.dumps(row, ensure_ascii=False)})
        elif isinstance(value, dict):
            rows.append({'module': key, 'data': json.dumps(value, ensure_ascii=False)})
        elif isinstance(value, list):
            for item in value:
                rows.append({'module': key, 'data': str(item)})
        else:
            rows.append({'module': key, 'data': str(value)})
    return rows

@app.route("/export/csv")
def export_csv():
    results = app.config.get("LATEST_RESULTS", {})
    if not results:
        return "No data to export", 404

    rows = flatten_results_for_csv(results)
    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=['module', 'data'])
    writer.writeheader()
    writer.writerows(rows)

    response = make_response(output.getvalue())
    response.headers["Content-Disposition"] = "attachment; filename=export.csv"
    response.headers["Content-type"] = "text/csv"
    return response

@app.route("/export/json")
def export_json():
    results = app.config.get("LATEST_RESULTS", {})
    if not results:
        return "No data to export", 404
    return Response(
        json.dumps(results, indent=2),
        mimetype='application/json',
        headers={'Content-Disposition':'attachment; filename=export.json'}
    )

@app.route("/export/pdf")
def export_pdf():
    if HTML is None:
        return "PDF export functionality is not available. Please install weasyprint.", 500
    results = app.config.get("LATEST_RESULTS", {})
    if not results:
        return "No data to export", 404
    url_norm = app.config.get("LATEST_URL", "N/A")
    rendered_html = render_template_string(
        RESULTS_HTML,
        results=results,
        url=url_norm,
        view_mode='human',
        pdf_available=False,
        scan_id=app.config.get("LATEST_SCAN_ID")
    )
    pdf = HTML(string=rendered_html).write_pdf()
    response = make_response(pdf)
    response.headers['Content-Type'] = 'application/pdf'
    response.headers['Content-Disposition'] = 'attachment; filename=report.pdf'
    return response

@app.route("/export/subdomains.csv")
def export_subdomains_csv():
    results = app.config.get("LATEST_RESULTS", {})
    sd = results.get("subdomain_scan", {})
    rows = sd.get("rows") or [{"subdomain": x} for x in sd.get("found", [])]
    if not rows:
        return "No subdomains", 404
    out = io.StringIO()
    cols = sorted({k for r in rows for k in r.keys()})
    writer = csv.DictWriter(out, fieldnames=cols)
    writer.writeheader()
    for r in rows:
        normalized = {}
        for k in cols:
            val = r.get(k)
            if isinstance(val, list):
                normalized[k] = ",".join(val)
            else:
                normalized[k] = val
        writer.writerow(normalized)
    resp = make_response(out.getvalue())
    resp.headers["Content-Disposition"] = "attachment; filename=subdomains.csv"
    resp.headers["Content-Type"] = "text/csv"
    return resp

@app.route("/export/report")
def export_report():
    results = app.config.get("LATEST_RESULTS", {})
    if not results:
        return "No data to export", 404
    url_val = app.config.get("LATEST_URL", "N/A")
    summary = results.get("_summary", {})
    meta = results.get("_meta", {})
    owasp = results.get("owasp_top10", {}).get("rows", [])
    exposures = results.get("exposure_checks", {}).get("rows", [])
    fuzzer = results.get("fuzzer", {}).get("rows", [])
    subdomains = results.get("subdomain_scan", {}).get("rows", [])[:15]
    signatures = results.get("signature_hits", {}).get("rows", [])
    report_html = render_template_string(
        REPORT_HTML,
        url=url_val,
        summary=summary,
        meta=meta,
        owasp=owasp,
        exposures=exposures,
        fuzzer=fuzzer,
        subdomains=subdomains,
        signatures=signatures,
        generated=datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC")
    )
    report_format = request.args.get("format", "pdf").lower()
    if report_format == "html" or HTML is None:
        resp = make_response(report_html)
        resp.headers["Content-Type"] = "text/html"
        resp.headers["Content-Disposition"] = "attachment; filename=report.html"
        return resp
    pdf = HTML(string=report_html).write_pdf()
    response = make_response(pdf)
    response.headers['Content-Type'] = 'application/pdf'
    response.headers['Content-Disposition'] = 'attachment; filename=report.pdf'
    return response

# ---------------- Main ----------------
if __name__ == "__main__":
    with app.app_context():
        init_db()
    # Bind to localhost to avoid Windows firewall prompt for public networks
    app.run(host="127.0.0.1", port=8080, debug=True)
