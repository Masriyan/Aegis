#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
AEGIS v4.0 — Enterprise Threat Hunter & Attack Surface Management Platform

================================================================================
                    AUTOMATED ENRICHMENT & GLOBAL INTELLIGENCE SCANNER
================================================================================

Enhanced Features (v4.0 - Innovative Analysis):
- 🔬 Entropy-based Secret Scanner (no API needed)
- 📝 Recon Wordlist Generator (local processing)
- 🔐 Password Policy Detector (form analysis)
- 📈 Technology Timeline (Archive.org integration)
- 📊 Scan Diff Analyzer (change detection)
- 🗺️ Attack Surface Mapper (visual graph)
- 📋 Report Narrative Generator (management-friendly)
- ⏰ Delta Alert System (baseline monitoring)

Enhanced Features (v3.0):
- 🤖 AI-Powered Threat Analysis Engine
- 🔐 Advanced Vulnerability Correlation (CVE/EPSS/KEV)
- 🌐 Extended OSINT (20+ intelligence sources)
- ⚔️ Active Security Testing Suite (authorized mode)
- 📊 Continuous Attack Surface Monitoring
- 📈 Interactive Visualization Dashboard
- 🔗 Integration Hub (REST API, SIEM, webhooks)
- 🎯 Multi-Target Campaign Scanning

Core Features:
- Passive & semi-offensive modules (opt-in)
- Subdomain enumeration (CT logs + bruteforce)
- Presets picker (Recon / Passive / Semi-offensive)
- Results filter + expand/collapse all
- History & permalinks (/history, /view/<id>)
- AI-enhanced risk scoring with MITRE ATT&CK mapping
- Export: CSV/JSON/PDF/STIX/Splunk/Elastic

IMPORTANT: For educational and authorized testing only.



================================================================================
"""

import asyncio
import base64
import csv
import hashlib
import io
import json
import logging
import os
import random
import re
import socket
import ssl
import sqlite3
import statistics
import string
import time
import threading
import traceback
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta
from functools import wraps
from typing import Dict, List, Optional, Tuple, Any
from urllib.parse import urljoin, urlparse, quote, parse_qs

import requests
from bs4 import BeautifulSoup
from flask import Flask, render_template_string, request, Response, g, make_response, jsonify

# Optional .env support
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

# Optional PDF support
try:
    from weasyprint import HTML as WeasyHTML
except ImportError:
    WeasyHTML = None

# Optional AI libraries
try:
    import openai
    OPENAI_AVAILABLE = True
except ImportError:
    openai = None
    OPENAI_AVAILABLE = False

try:
    import anthropic
    ANTHROPIC_AVAILABLE = True
except ImportError:
    anthropic = None
    ANTHROPIC_AVAILABLE = False

# Optional ML libraries
try:
    from sklearn.ensemble import IsolationForest
    from sklearn.preprocessing import StandardScaler
    import numpy as np
    ML_AVAILABLE = True
except ImportError:
    IsolationForest = None
    StandardScaler = None
    np = None
    ML_AVAILABLE = False

# Optional visualization
try:
    import plotly.express as px
    import plotly.graph_objects as go
    PLOTLY_AVAILABLE = True
except ImportError:
    px = None
    go = None
    PLOTLY_AVAILABLE = False

try:
    import networkx as nx
    NETWORKX_AVAILABLE = True
except ImportError:
    nx = None
    NETWORKX_AVAILABLE = False

# Optional async HTTP
try:
    import httpx
    HTTPX_AVAILABLE = True
except ImportError:
    httpx = None
    HTTPX_AVAILABLE = False

try:
    import aiohttp
    AIOHTTP_AVAILABLE = True
except ImportError:
    aiohttp = None
    AIOHTTP_AVAILABLE = False

# Optional Censys
try:
    from censys.search import CensysHosts
    CENSYS_AVAILABLE = True
except ImportError:
    CensysHosts = None
    CENSYS_AVAILABLE = False

# Optional background scheduling
try:
    from apscheduler.schedulers.background import BackgroundScheduler
    SCHEDULER_AVAILABLE = True
except ImportError:
    BackgroundScheduler = None
    SCHEDULER_AVAILABLE = False

# Optional data processing
try:
    import pandas as pd
    PANDAS_AVAILABLE = True
except ImportError:
    pd = None
    PANDAS_AVAILABLE = False

import dns.resolver
import whois

# v6.1.0 Enhancement Modules
try:
    from aegis_enhancements import run_enhanced_modules
    ENHANCEMENTS_AVAILABLE = True
except ImportError:
    run_enhanced_modules = None
    ENHANCEMENTS_AVAILABLE = False

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger('AEGIS')

# ---------------- Config ----------------
HERE = os.path.dirname(os.path.abspath(__file__))
DATABASE = os.path.join(HERE, 'aegis.db')  # Windows-safe path
DEFAULT_TIMEOUT = 15
USER_AGENT = "Mozilla/5.0 (AegisSparks/6.0; +https://security-life.org)"
SESSION = requests.Session()
SESSION.headers.update({"User-Agent": USER_AGENT})
AEGIS_VERSION = "6.1.0"

# API keys (optional) - Core
VT_API_KEY = os.getenv("VT_API_KEY", "")
OTX_API_KEY = os.getenv("OTX_API_KEY", "")
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN", "")
SHODAN_API_KEY = os.getenv("SHODAN_API_KEY", "")
GREYNOISE_API_KEY = os.getenv("GREYNOISE_API_KEY", "")
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY", "")
SECURITYTRAILS_API_KEY = os.getenv("SECURITYTRAILS_API_KEY", "")
HIBP_API_KEY = os.getenv("HIBP_API_KEY", "")

# Extended OSINT API Keys
HUNTER_API_KEY = os.getenv("HUNTER_API_KEY", "")
CENSYS_API_ID = os.getenv("CENSYS_API_ID", "")
CENSYS_API_SECRET = os.getenv("CENSYS_API_SECRET", "")
LEAKCHECK_API_KEY = os.getenv("LEAKCHECK_API_KEY", "")
FOFA_API_KEY = os.getenv("FOFA_API_KEY", "")
FOFA_EMAIL = os.getenv("FOFA_EMAIL", "")
DEHASHED_API_KEY = os.getenv("DEHASHED_API_KEY", "")
DEHASHED_EMAIL = os.getenv("DEHASHED_EMAIL", "")
FULLHUNT_API_KEY = os.getenv("FULLHUNT_API_KEY", "")
ZOOMEYE_API_KEY = os.getenv("ZOOMEYE_API_KEY", "")
BINARYEDGE_API_KEY = os.getenv("BINARYEDGE_API_KEY", "")
INTELX_API_KEY = os.getenv("INTELX_API_KEY", "")
BUILTWITH_API_KEY = os.getenv("BUILTWITH_API_KEY", "")
WHOISXML_API_KEY = os.getenv("WHOISXML_API_KEY", "")

# AI API Keys
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "")
ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY", "")
AI_MODEL = os.getenv("AI_MODEL", "gpt-4-turbo-preview")
AI_ENABLED = os.getenv("AI_ENABLED", "true").lower() == "true"

# Notifications
SLACK_WEBHOOK_URL = os.getenv("SLACK_WEBHOOK_URL", "")
DISCORD_WEBHOOK_URL = os.getenv("DISCORD_WEBHOOK_URL", "")
TEAMS_WEBHOOK_URL = os.getenv("TEAMS_WEBHOOK_URL", "")
TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "")
TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID", "")

# Thresholds
ALERT_THRESHOLD = int(os.getenv("ALERT_THRESHOLD", "60"))
SCREENSHOT_TIMEOUT = int(os.getenv("SCREENSHOT_TIMEOUT", "20"))
AUTO_TICKET_THRESHOLD = int(os.getenv("AUTO_TICKET_THRESHOLD", "70"))
WORKFLOW_MAX_STEPS = int(os.getenv("WORKFLOW_MAX_STEPS", "15"))
MAX_CONCURRENT_SCANS = int(os.getenv("MAX_CONCURRENT_SCANS", "5"))

# Cloud & Sandbox
AWS_REGION = os.getenv("AWS_REGION", "us-east-1")
MALWARE_SANDBOX_URL = os.getenv("MALWARE_SANDBOX_URL", "")
MALWARE_SANDBOX_KEY = os.getenv("MALWARE_SANDBOX_KEY", "")
TICKET_WEBHOOK_URL = os.getenv("TICKET_WEBHOOK_URL", "")

# SIEM Integration
SPLUNK_HEC_URL = os.getenv("SPLUNK_HEC_URL", "")
SPLUNK_HEC_TOKEN = os.getenv("SPLUNK_HEC_TOKEN", "")
ELASTIC_URL = os.getenv("ELASTIC_URL", "")
ELASTIC_API_KEY = os.getenv("ELASTIC_API_KEY", "")

# API Rate Limiting
API_RATE_LIMIT = int(os.getenv("API_RATE_LIMIT", "100"))  # requests per minute
API_KEY_SECRET = os.getenv("API_KEY_SECRET", "".join(random.choices(string.ascii_letters + string.digits, k=32)))

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
          <div class="category-header justify-between group/header">
            <div class="flex items-center gap-3">
              <div class="category-icon bg-blue-500/20 text-blue-400"><i class="fas fa-magnifying-glass"></i></div>
              <span class="text-sm font-medium text-gray-400">Discovery & Fingerprinting</span>
            </div>
            <div class="flex gap-2 opacity-0 group-hover/header:opacity-100 transition-opacity">
               <button type="button" class="text-[0.65rem] uppercase tracking-wider btn-glass px-2 py-1 rounded hover:bg-blue-500 hover:text-white transition-colors" onclick="selectCategory(this, true)">All</button>
               <button type="button" class="text-[0.65rem] uppercase tracking-wider btn-glass px-2 py-1 rounded hover:bg-slate-600 transition-colors" onclick="selectCategory(this, false)">None</button>
            </div>
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
          <div class="category-header justify-between group/header">
            <div class="flex items-center gap-3">
              <div class="category-icon bg-purple-500/20 text-purple-400"><i class="fas fa-network-wired"></i></div>
              <span class="text-sm font-medium text-gray-400">DNS & Domain Intelligence</span>
            </div>
            <div class="flex gap-2 opacity-0 group-hover/header:opacity-100 transition-opacity">
               <button type="button" class="text-[0.65rem] uppercase tracking-wider btn-glass px-2 py-1 rounded hover:bg-purple-500 hover:text-white transition-colors" onclick="selectCategory(this, true)">All</button>
               <button type="button" class="text-[0.65rem] uppercase tracking-wider btn-glass px-2 py-1 rounded hover:bg-slate-600 transition-colors" onclick="selectCategory(this, false)">None</button>
            </div>
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
          <div class="category-header justify-between group/header">
            <div class="flex items-center gap-3">
              <div class="category-icon bg-red-500/20 text-red-400"><i class="fas fa-biohazard"></i></div>
              <span class="text-sm font-medium text-gray-400">Threat Intelligence</span>
            </div>
            <div class="flex gap-2 opacity-0 group-hover/header:opacity-100 transition-opacity">
               <button type="button" class="text-[0.65rem] uppercase tracking-wider btn-glass px-2 py-1 rounded hover:bg-red-500 hover:text-white transition-colors" onclick="selectCategory(this, true)">All</button>
               <button type="button" class="text-[0.65rem] uppercase tracking-wider btn-glass px-2 py-1 rounded hover:bg-slate-600 transition-colors" onclick="selectCategory(this, false)">None</button>
            </div>
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
        
        <!-- v3.0 Extended OSINT Modules -->
        <div class="mb-6">
          <div class="category-header">
            <div class="category-icon bg-cyan-500/20 text-cyan-400"><i class="fas fa-globe"></i></div>
            <span class="text-sm font-medium text-gray-400">Extended OSINT (v3.0)</span>
          </div>
          <div class="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-5 gap-3">
            {% for label, val, icon in [
              ('Hunter.io', 'hunter_io', 'fa-envelope'),
              ('Censys', 'censys', 'fa-server'),
              ('GitHub Dorks', 'github_dorks', 'fa-brands fa-github'),
              ('FullHunt', 'fullhunt', 'fa-crosshairs'),
              ('BinaryEdge', 'binaryedge', 'fa-database'),
              ('BuiltWith', 'builtwith', 'fa-cubes'),
              ('LeakCheck', 'leakcheck', 'fa-droplet')
            ] %}
            <label class="module-card px-3 py-2.5 cursor-pointer flex items-center gap-3 group">
              <input type="checkbox" name="services" value="{{ val }}" class="hidden peer">
              <div class="w-8 h-8 rounded-lg bg-cyan-500/10 flex items-center justify-center text-cyan-400 group-hover:bg-cyan-500/20 peer-checked:bg-cyan-500 peer-checked:text-white transition-all">
                <i class="{{ 'fab' if 'brands' in icon else 'fas' }} {{ icon.replace('fa-brands ', '') }} text-sm"></i>
              </div>
              <span class="text-sm text-gray-300 group-hover:text-white transition-colors">{{ label }}</span>
            </label>
            {% endfor %}
          </div>
        </div>
        
        <!-- v3.0 Vulnerability & Monitoring -->
        <div class="mb-6">
          <div class="category-header">
            <div class="category-icon bg-orange-500/20 text-orange-400"><i class="fas fa-shield-virus"></i></div>
            <span class="text-sm font-medium text-gray-400">Vulnerability & Monitoring (v3.0)</span>
          </div>
          <div class="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-5 gap-3">
            {% for label, val, icon in [
              ('Enhanced CVE', 'enhanced_cve', 'fa-bug-slash'),
              ('Cert Monitor', 'cert_monitor', 'fa-certificate')
            ] %}
            <label class="module-card px-3 py-2.5 cursor-pointer flex items-center gap-3 group">
              <input type="checkbox" name="services" value="{{ val }}" class="hidden peer">
              <div class="w-8 h-8 rounded-lg bg-orange-500/10 flex items-center justify-center text-orange-400 group-hover:bg-orange-500/20 peer-checked:bg-orange-500 peer-checked:text-white transition-all">
                <i class="fas {{ icon }} text-sm"></i>
              </div>
              <span class="text-sm text-gray-300 group-hover:text-white transition-colors">{{ label }}</span>
            </label>
            {% endfor %}
          </div>
        </div>
        
        <!-- v3.0 Active Security Testing (Semi/Active Mode) -->
        <div class="mb-6">
          <div class="category-header">
            <div class="category-icon bg-pink-500/20 text-pink-400"><i class="fas fa-bolt"></i></div>
            <span class="text-sm font-medium text-gray-400">Active Security Testing (v3.0 - Requires Authorization)</span>
          </div>
          <div class="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-5 gap-3">
            {% for label, val, icon in [
              ('Auth Testing', 'auth_test', 'fa-key'),
              ('API Security', 'api_security', 'fa-plug'),
              ('XXE Detection', 'xxe_test', 'fa-code'),
              ('SSRF Detection', 'ssrf_test', 'fa-network-wired'),
              ('Open Redirects', 'redirect_test', 'fa-share'),
              ('Header Injection', 'header_test', 'fa-heading')
            ] %}
            <label class="module-card px-3 py-2.5 cursor-pointer flex items-center gap-3 group">
              <input type="checkbox" name="services" value="{{ val }}" class="hidden peer">
              <div class="w-8 h-8 rounded-lg bg-pink-500/10 flex items-center justify-center text-pink-400 group-hover:bg-pink-500/20 peer-checked:bg-pink-500 peer-checked:text-white transition-all">
                <i class="fas {{ icon }} text-sm"></i>
              </div>
              <span class="text-sm text-gray-300 group-hover:text-white transition-colors">{{ label }}</span>
            </label>
            {% endfor %}
          </div>
          <p class="text-xs text-pink-400/70 mt-2 ml-2"><i class="fas fa-exclamation-triangle mr-1"></i>These modules require explicit authorization and semi/active mode.</p>
        </div>
        
        <!-- v4.0 Innovative Analysis -->
        <div class="mb-6">
          <div class="category-header">
            <div class="category-icon bg-indigo-500/20 text-indigo-400"><i class="fas fa-lightbulb"></i></div>
            <span class="text-sm font-medium text-gray-400">Innovative Analysis (v4.0 - No API Required)</span>
          </div>
          <div class="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-5 gap-3">
            {% for label, val, icon in [
              ('Scan Diff', 'scan_diff', 'fa-code-compare'),
              ('Wordlist Gen', 'wordlist_gen', 'fa-list-ol'),
              ('Password Policy', 'password_policy', 'fa-key'),
              ('Tech Timeline', 'tech_timeline', 'fa-timeline'),
              ('Entropy Scan', 'entropy_scan', 'fa-chart-bar'),
              ('Attack Map', 'attack_map', 'fa-diagram-project'),
              ('Report Narrative', 'report_narrative', 'fa-file-lines'),
              ('Delta Alerts', 'delta_alerts', 'fa-bell')
            ] %}
            <label class="module-card px-3 py-2.5 cursor-pointer flex items-center gap-3 group">
              <input type="checkbox" name="services" value="{{ val }}" class="hidden peer">
              <div class="w-8 h-8 rounded-lg bg-indigo-500/10 flex items-center justify-center text-indigo-400 group-hover:bg-indigo-500/20 peer-checked:bg-indigo-500 peer-checked:text-white transition-all">
                <i class="fas {{ icon }} text-sm"></i>
              </div>
              <span class="text-sm text-gray-300 group-hover:text-white transition-colors">{{ label }}</span>
            </label>
            {% endfor %}
          </div>
          <p class="text-xs text-indigo-400/70 mt-2 ml-2"><i class="fas fa-sparkles mr-1"></i>100% local processing - no external APIs needed.</p>
        </div>
        
        <!-- v5.0 Advanced Security -->
        <div class="mb-6">
          <div class="category-header">
            <div class="category-icon bg-rose-500/20 text-rose-400"><i class="fas fa-shield-virus"></i></div>
            <span class="text-sm font-medium text-gray-400">Advanced Security (v5.0)</span>
          </div>
          <div class="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-5 gap-3">
            {% for label, val, icon in [
              ('Crypto Scanner', 'crypto_scan', 'fa-bitcoin-sign'),
              ('Privacy Detector', 'privacy_detect', 'fa-user-secret'),
              ('DB Leak Detect', 'db_leak', 'fa-database'),
              ('JS Deobfuscate', 'js_deobfuscate', 'fa-code'),
              ('Homoglyph Scan', 'homoglyph_scan', 'fa-font'),
              ('Ghost Finder', 'ghost_finder', 'fa-ghost'),
              ('Honeypot Detect', 'honeypot_detect', 'fa-jar'),
              ('Geo Block', 'geo_block', 'fa-globe'),
              ('Compliance Check', 'compliance_check', 'fa-clipboard-check'),
              ('Vuln Predict', 'vuln_predict', 'fa-bug')
            ] %}
            <label class="module-card px-3 py-2.5 cursor-pointer flex items-center gap-3 group">
              <input type="checkbox" name="services" value="{{ val }}" class="hidden peer">
              <div class="w-8 h-8 rounded-lg bg-rose-500/10 flex items-center justify-center text-rose-400 group-hover:bg-rose-500/20 peer-checked:bg-rose-500 peer-checked:text-white transition-all">
                <i class="fas {{ icon }} text-sm"></i>
              </div>
              <span class="text-sm text-gray-300 group-hover:text-white transition-colors">{{ label }}</span>
            </label>
            {% endfor %}
          </div>
          <p class="text-xs text-rose-400/70 mt-2 ml-2"><i class="fas fa-lock mr-1"></i>Advanced threat detection - 100% local.</p>
        </div>
        
        <!-- v5.0 Intelligence & Experimental -->
        <div class="mb-6">
          <div class="category-header">
            <div class="category-icon bg-amber-500/20 text-amber-400"><i class="fas fa-flask"></i></div>
            <span class="text-sm font-medium text-gray-400">Intelligence & Experimental (v5.0)</span>
          </div>
          <div class="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-5 gap-3">
            {% for label, val, icon in [
              ('Media Assets', 'media_scan', 'fa-photo-film'),
              ('Mobile Apps', 'mobile_detect', 'fa-mobile-screen'),
              ('Email Harvest', 'email_harvest', 'fa-envelope-open-text'),
              ('Brand Extract', 'brand_extract', 'fa-palette'),
              ('Website DNA', 'website_dna', 'fa-dna'),
              ('Timing Analysis', 'timing_analysis', 'fa-stopwatch'),
              ('API Fuzzer', 'api_fuzzer', 'fa-plug'),
              ('Link Graph', 'link_graph', 'fa-share-nodes'),
              ('Sub Cluster', 'sub_cluster', 'fa-object-group'),
              ('Site Value', 'site_value', 'fa-coins'),
              ('Cookie Consent', 'cookie_consent', 'fa-cookie-bite')
            ] %}
            <label class="module-card px-3 py-2.5 cursor-pointer flex items-center gap-3 group">
              <input type="checkbox" name="services" value="{{ val }}" class="hidden peer">
              <div class="w-8 h-8 rounded-lg bg-amber-500/10 flex items-center justify-center text-amber-400 group-hover:bg-amber-500/20 peer-checked:bg-amber-500 peer-checked:text-white transition-all">
                <i class="fas {{ icon }} text-sm"></i>
              </div>
              <span class="text-sm text-gray-300 group-hover:text-white transition-colors">{{ label }}</span>
            </label>
            {% endfor %}
          </div>
          <p class="text-xs text-amber-400/70 mt-2 ml-2"><i class="fas fa-wand-sparkles mr-1"></i>Experimental intelligence gathering.</p>
        </div>
        
        <!-- v6.0 SOCMINT & Ransomware Intel -->
        <div class="mb-6">
          <div class="category-header justify-between group/header">
            <div class="flex items-center gap-3">
              <div class="category-icon bg-red-600/20 text-red-400"><i class="fas fa-skull-crossbones"></i></div>
              <span class="text-sm font-medium text-gray-400">SOCMINT & Threat Intel (v6.0)</span>
            </div>
            <div class="flex gap-2 opacity-0 group-hover/header:opacity-100 transition-opacity">
               <button type="button" class="text-[0.65rem] uppercase tracking-wider btn-glass px-2 py-1 rounded hover:bg-red-600 hover:text-white transition-colors" onclick="selectCategory(this, true)">All</button>
               <button type="button" class="text-[0.65rem] uppercase tracking-wider btn-glass px-2 py-1 rounded hover:bg-slate-600 transition-colors" onclick="selectCategory(this, false)">None</button>
            </div>
          </div>
          <div class="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-5 gap-3">
            {% for label, val, icon in [
              ('Social Media Intel', 'social_intel', 'fa-users'),
              ('Social Extractor', 'social_extract', 'fa-share-alt'),
              ('Ransomware Check', 'ransomware_check', 'fa-virus'),
              ('Ransom Groups', 'ransom_groups', 'fa-skull'),
              ('Recent Victims', 'ransom_victims', 'fa-list')
            ] %}
            <label class="module-card px-3 py-2.5 cursor-pointer flex items-center gap-3 group">
              <input type="checkbox" name="services" value="{{ val }}" class="hidden peer">
              <div class="w-8 h-8 rounded-lg bg-red-600/10 flex items-center justify-center text-red-400 group-hover:bg-red-600/20 peer-checked:bg-red-600 peer-checked:text-white transition-all">
                <i class="fas {{ icon }} text-sm"></i>
              </div>
              <span class="text-sm text-gray-300 group-hover:text-white transition-colors">{{ label }}</span>
            </label>
            {% endfor %}
          </div>
          <p class="text-xs text-red-400/70 mt-2 ml-2"><i class="fas fa-exclamation-circle mr-1"></i>SOCMINT & Ransomware intelligence from ransomware.live & ransomlook.io</p>
        </div>
        
        <!-- v6.1.0 Enhanced Analysis (Local-Only) -->
        <div class="mb-6">
          <div class="category-header justify-between group/header">
            <div class="flex items-center gap-3">
              <div class="category-icon bg-emerald-500/20 text-emerald-400"><i class="fas fa-chart-pie"></i></div>
              <span class="text-sm font-medium text-gray-400">Enhanced Analysis (v6.1 - 100% Local)</span>
              <span class="px-2 py-0.5 text-[0.6rem] uppercase tracking-wider bg-emerald-500/20 text-emerald-400 rounded-full">NEW</span>
            </div>
            <div class="flex gap-2 opacity-0 group-hover/header:opacity-100 transition-opacity">
               <button type="button" class="text-[0.65rem] uppercase tracking-wider btn-glass px-2 py-1 rounded hover:bg-emerald-600 hover:text-white transition-colors" onclick="selectCategory(this, true)">All</button>
               <button type="button" class="text-[0.65rem] uppercase tracking-wider btn-glass px-2 py-1 rounded hover:bg-slate-600 transition-colors" onclick="selectCategory(this, false)">None</button>
            </div>
          </div>
          <div class="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-5 gap-3">
            {% for label, val, icon in [
              ('Security Score', 'security_posture', 'fa-gauge-high'),
              ('Attack Vectors', 'attack_vectors', 'fa-route'),
              ('Smart Summary', 'smart_summary', 'fa-wand-magic-sparkles'),
              ('HTTP Fingerprint', 'http_fingerprint', 'fa-fingerprint'),
              ('Input Validation', 'input_validation', 'fa-keyboard'),
              ('CSP Analysis', 'csp_analysis', 'fa-shield-halved'),
              ('Recon Detection', 'recon_detection', 'fa-user-secret'),
              ('JS Complexity', 'js_complexity', 'fa-file-code'),
              ('Session Analysis', 'session_analysis', 'fa-id-badge'),
              ('Rate Limiting', 'rate_limiting', 'fa-tachometer-alt'),
              ('Cache Analysis', 'cache_analysis', 'fa-box-archive'),
              ('Form Security', 'form_security', 'fa-wpforms'),
              ('Meta Tags', 'meta_tags', 'fa-tags')
            ] %}
            <label class="module-card px-3 py-2.5 cursor-pointer flex items-center gap-3 group">
              <input type="checkbox" name="services" value="{{ val }}" class="hidden peer">
              <div class="w-8 h-8 rounded-lg bg-emerald-500/10 flex items-center justify-center text-emerald-400 group-hover:bg-emerald-500/20 peer-checked:bg-emerald-500 peer-checked:text-white transition-all">
                <i class="fas {{ icon }} text-sm"></i>
              </div>
              <span class="text-sm text-gray-300 group-hover:text-white transition-colors">{{ label }}</span>
            </label>
            {% endfor %}
          </div>
          <p class="text-xs text-emerald-400/70 mt-2 ml-2"><i class="fas fa-sparkles mr-1"></i>Intelligent analysis with risk scoring, attack mapping, and smart summaries — no APIs required.</p>
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
      <p>AEGIS v6.0 — Advanced Threat Hunter & SOCMINT Swiss Army Knife</p>
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

    // Category Selection Helper
    window.selectCategory = function(btn, checked) {
       const wrapper = btn.closest('.mb-6');
       wrapper.querySelectorAll('input[type="checkbox"]').forEach(cb => {
         cb.checked = checked;
         cb.dispatchEvent(new Event('change'));
       });
    };

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
  <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
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

    <!-- Analytics Charts -->
    <div class="glass-card p-6 mb-8">
      <h3 class="text-lg font-semibold text-gray-300 mb-6 flex items-center gap-2">
        <i class="fas fa-chart-pie text-purple-400"></i> Threat Landscape Analysis
      </h3>
      <div class="grid md:grid-cols-2 gap-8">
        <div class="h-64 relative">
          <canvas id="riskChart"></canvas>
        </div>
        <div class="h-64 relative">
          <canvas id="coverageChart"></canvas>
        </div>
      </div>
    </div>

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

        {# ============ v5.0 MODULE RESULTS ============ #}

        {% elif key == 'crypto_scan' %}
          <div class="flex items-center gap-3 mb-3">
            <span class="badge {% if value.total_found > 0 %}bad{% else %}ok{% endif %}">{{ value.total_found }} addresses found</span>
            <span class="text-sm text-gray-400">Types: {{ value.types_detected|join(', ') or 'None' }}</span>
          </div>
          {% if value.addresses %}
          <table><thead><tr><th>Type</th><th>Address</th><th>Risk</th></tr></thead>
          <tbody>{% for a in value.addresses[:20] %}
            <tr><td>{{ a.type }}</td><td class="font-mono text-xs">{{ a.address[:40] }}...</td>
            <td><span class="badge {% if a.risk == 'high' %}bad{% else %}warn{% endif %}">{{ a.risk }}</span></td></tr>
          {% endfor %}</tbody></table>
          {% endif %}

        {% elif key == 'privacy_detect' %}
          <div class="flex items-center gap-3 mb-3">
            <span class="badge {% if value.risk_level == 'high' %}bad{% elif value.risk_level == 'medium' %}warn{% else %}ok{% endif %}">{{ value.risk_level }} risk</span>
            <span class="text-sm text-gray-400">Privacy Score: {{ value.privacy_score }}/100</span>
          </div>
          <div class="grid md:grid-cols-2 gap-4">
            <div class="bg-slate-800/40 rounded-lg p-3">
              <div class="text-sm font-medium text-gray-300 mb-2"><i class="fas fa-eye mr-2 text-red-400"></i>Trackers Found</div>
              {% if value.trackers %}<div class="flex flex-wrap gap-2">{% for t in value.trackers %}<span class="badge warn">{{ t }}</span>{% endfor %}</div>
              {% else %}<span class="text-gray-500 text-sm">None detected</span>{% endif %}
            </div>
            <div class="bg-slate-800/40 rounded-lg p-3">
              <div class="text-sm font-medium text-gray-300 mb-2"><i class="fas fa-fingerprint mr-2 text-purple-400"></i>Fingerprinting</div>
              <span class="text-sm text-gray-400">{{ value.fingerprinting_signals }} techniques detected</span>
            </div>
          </div>

        {% elif key == 'homoglyph_scan' %}
          <div class="text-sm text-gray-400 mb-3">Original domain: <span class="text-blue-400">{{ value.original }}</span> · {{ value.total_variants }} variants generated</div>
          <div class="grid md:grid-cols-2 gap-4">
            <div class="bg-slate-800/40 rounded-lg p-3">
              <div class="text-sm font-medium text-gray-300 mb-2"><i class="fas fa-font mr-2 text-yellow-400"></i>Homoglyph Variants</div>
              <div class="flex flex-wrap gap-2">{% for v in value.homoglyph_variants[:10] %}<span class="badge warn">{{ v.variant }}</span>{% endfor %}</div>
            </div>
            <div class="bg-slate-800/40 rounded-lg p-3">
              <div class="text-sm font-medium text-gray-300 mb-2"><i class="fas fa-keyboard mr-2 text-blue-400"></i>Typo Variants</div>
              <div class="flex flex-wrap gap-2">{% for v in value.typo_variants[:10] %}<span class="badge sev-low">{{ v.variant }}</span>{% endfor %}</div>
            </div>
          </div>

        {% elif key == 'ransomware_check' %}
          <div class="flex items-center gap-3 mb-3">
            {% if value.found %}
              <span class="badge bad"><i class="fas fa-exclamation-triangle mr-1"></i>FOUND IN VICTIM LIST</span>
            {% else %}
              <span class="badge ok"><i class="fas fa-check mr-1"></i>Not found</span>
            {% endif %}
            <span class="text-sm text-gray-400">Checked: {{ value.sources_checked|join(', ') }}</span>
          </div>
          {% if value.matches %}
          <table><thead><tr><th>Source</th><th>Group</th><th>Date</th><th>Country</th></tr></thead>
          <tbody>{% for m in value.matches %}
            <tr><td>{{ m.source }}</td><td class="text-red-400 font-bold">{{ m.group }}</td><td>{{ m.date }}</td><td>{{ m.country }}</td></tr>
          {% endfor %}</tbody></table>
          {% endif %}

        {% elif key == 'ransom_groups' %}
          <div class="text-sm text-gray-400 mb-3">{{ value.total_groups }} active ransomware groups tracked</div>
          <table><thead><tr><th>Group Name</th><th>Source</th><th>Status</th></tr></thead>
          <tbody>{% for g in value.groups[:30] %}
            <tr><td class="text-red-400">{{ g.name }}</td><td>{{ g.source }}</td><td><span class="badge {% if g.status == 'active' %}bad{% else %}warn{% endif %}">{{ g.status or 'unknown' }}</span></td></tr>
          {% endfor %}</tbody></table>

        {% elif key == 'ransom_victims' %}
          <div class="text-sm text-gray-400 mb-3">{{ value.total }} recent victims · Retrieved: {{ value.retrieved_at[:10] }}</div>
          <table><thead><tr><th>Victim</th><th>Group</th><th>Date</th><th>Country</th></tr></thead>
          <tbody>{% for v in value.victims %}
            <tr><td>{{ v.name }}</td><td class="text-red-400">{{ v.group }}</td><td>{{ v.date }}</td><td>{{ v.country }}</td></tr>
          {% endfor %}</tbody></table>

        {% elif key == 'social_intel' %}
          <div class="text-sm text-gray-400 mb-3">Query: <span class="text-blue-400">{{ value.query }}</span> · {{ value.total_platforms }} platforms checked</div>
          <div class="grid grid-cols-3 md:grid-cols-5 lg:grid-cols-6 gap-2">
          {% for p in value.profiles[:30] %}
            <a href="{{ p.url }}" target="_blank" class="bg-slate-800/40 rounded-lg p-2 text-center hover:bg-slate-700/60 transition-all">
              <i class="fab {{ p.icon }} text-lg mb-1"></i>
              <div class="text-xs text-gray-400">{{ p.platform }}</div>
            </a>
          {% endfor %}
          </div>

        {% elif key == 'social_extract' %}
          <div class="text-sm text-gray-400 mb-3">{{ value.total_found }} social profiles extracted from page</div>
          <div class="grid md:grid-cols-2 gap-4">
          {% for platform, handles in value.profiles.items() %}
            <div class="bg-slate-800/40 rounded-lg p-3">
              <div class="text-sm font-medium text-gray-300 mb-2 capitalize">{{ platform }}</div>
              <div class="flex flex-wrap gap-2">{% for h in handles %}<span class="badge ok">{{ h }}</span>{% endfor %}</div>
            </div>
          {% endfor %}
          </div>

        {% elif key == 'compliance_check' %}
          <div class="text-sm text-gray-400 mb-3">Overall Score: <span class="text-2xl font-bold {% if value.overall_score >= 70 %}text-green-400{% elif value.overall_score >= 40 %}text-yellow-400{% else %}text-red-400{% endif %}">{{ value.overall_score }}%</span></div>
          <div class="grid md:grid-cols-3 gap-4">
          {% for standard, data in value.compliance.items() %}
            <div class="bg-slate-800/40 rounded-lg p-3">
              <div class="flex justify-between items-center mb-2">
                <span class="text-sm font-medium text-gray-300 uppercase">{{ standard }}</span>
                <span class="badge {% if data.score >= 70 %}ok{% elif data.score >= 40 %}warn{% else %}bad{% endif %}">{{ data.score }}%</span>
              </div>
              <div class="text-xs text-gray-500">{{ data.checks_passed }}/{{ data.total_checks }} checks passed</div>
            </div>
          {% endfor %}
          </div>

        {% elif key == 'ghost_finder' %}
          <div class="text-sm text-gray-400 mb-3">{{ value.paths_checked }} paths checked · {{ value.paths_found }} found</div>
          <div class="grid md:grid-cols-2 gap-4">
            <div class="bg-slate-800/40 rounded-lg p-3">
              <div class="text-sm font-medium text-green-400 mb-2"><i class="fas fa-unlock mr-2"></i>Accessible ({{ value.accessible|length }})</div>
              {% for p in value.accessible %}<div class="text-sm font-mono">{{ p.path }} <span class="badge ok">{{ p.status }}</span></div>{% endfor %}
            </div>
            <div class="bg-slate-800/40 rounded-lg p-3">
              <div class="text-sm font-medium text-yellow-400 mb-2"><i class="fas fa-lock mr-2"></i>Protected ({{ value.protected|length }})</div>
              {% for p in value.protected %}<div class="text-sm font-mono">{{ p.path }} <span class="badge warn">{{ p.status }}</span></div>{% endfor %}
            </div>
          </div>

        {% elif key == 'link_graph' %}
          <div class="grid md:grid-cols-2 gap-4">
            <div class="bg-slate-800/40 rounded-lg p-3">
              <div class="text-sm font-medium text-blue-400 mb-2"><i class="fas fa-link mr-2"></i>Internal Links ({{ value.internal_count }})</div>
              <div class="max-h-40 overflow-y-auto text-xs">{% for l in value.internal_links[:20] %}<div class="font-mono text-gray-400">{{ l }}</div>{% endfor %}</div>
            </div>
            <div class="bg-slate-800/40 rounded-lg p-3">
              <div class="text-sm font-medium text-purple-400 mb-2"><i class="fas fa-external-link mr-2"></i>External Domains ({{ value.external_count }})</div>
              <div class="max-h-40 overflow-y-auto text-xs">{% for d in value.external_domains[:20] %}<div class="font-mono text-gray-400">{{ d }}</div>{% endfor %}</div>
            </div>
          </div>

        {% elif key == 'website_dna' %}
          <div class="text-sm text-gray-400 mb-3">DNA Hash: <span class="font-mono text-blue-400">{{ value.dna_hash }}</span></div>
          <div class="grid md:grid-cols-2 gap-4">
            <div class="bg-slate-800/40 rounded-lg p-3">
              <div class="text-sm font-medium text-gray-300 mb-2">Structure</div>
              <div class="text-xs text-gray-400">Total tags: {{ value.structure.total_tags }} · Unique: {{ value.structure.unique_tags }}</div>
              <div class="text-xs text-gray-400">Scripts: {{ value.structure.script_count }} · Forms: {{ 'Yes' if value.structure.has_forms else 'No' }}</div>
            </div>
            <div class="bg-slate-800/40 rounded-lg p-3">
              <div class="text-sm font-medium text-gray-300 mb-2">Tech Signature</div>
              <div class="flex flex-wrap gap-1">{% for t in value.tech_signature %}<span class="badge sev-low">{{ t }}</span>{% endfor %}</div>
            </div>
          </div>

        {% elif key == 'vuln_predict' %}
          <div class="text-sm text-gray-400 mb-3">{{ value.risk_technologies }} risky technologies detected</div>
          {% if value.predictions %}
          <table><thead><tr><th>Technology</th><th>Potential Issues</th><th>Recommendation</th></tr></thead>
          <tbody>{% for p in value.predictions %}
            <tr><td class="text-yellow-400">{{ p.technology }}</td><td class="text-xs">{{ p.potential_issues|join(', ') }}</td><td class="text-xs text-gray-400">{{ p.recommendation }}</td></tr>
          {% endfor %}</tbody></table>
          {% else %}<p class="text-green-400 text-sm"><i class="fas fa-check mr-1"></i>{{ value.recommendation }}</p>{% endif %}

        {% elif key == 'db_leak' %}
          <div class="flex items-center gap-3 mb-3">
            <span class="badge {% if value.risk_level == 'critical' %}bad{% else %}ok{% endif %}">{{ value.risk_level }} risk</span>
            <span class="text-sm text-gray-400">{{ value.leaks_found }} leak patterns detected</span>
          </div>
          {% if value.details %}
          <table><thead><tr><th>Type</th><th>Matches</th><th>Severity</th></tr></thead>
          <tbody>{% for d in value.details %}
            <tr><td>{{ d.type }}</td><td class="text-xs font-mono">{{ d.matches[:5]|join(', ') }}</td>
            <td><span class="badge {% if d.severity == 'high' %}bad{% else %}warn{% endif %}">{{ d.severity }}</span></td></tr>
          {% endfor %}</tbody></table>
          {% else %}<p class="text-green-400 text-sm"><i class="fas fa-check mr-1"></i>No database leaks detected.</p>{% endif %}

        {% elif key == 'js_deobfuscate' %}
          <div class="flex items-center gap-3 mb-3">
            <span class="badge {% if value.risk_level == 'critical' %}bad{% elif value.risk_level == 'high' %}sev-high{% else %}ok{% endif %}">{{ value.risk_level }} risk</span>
            <span class="text-sm text-gray-400">Obfuscation Score: {{ value.score }}/100</span>
          </div>
          {% if value.techniques %}
          <table><thead><tr><th>Technique</th><th>Occurrences</th><th>Risk</th></tr></thead>
          <tbody>{% for t in value.techniques %}
            <tr><td>{{ t.technique }}</td><td>{{ t.occurrences }}</td>
            <td><span class="badge {% if t.risk == 'high' %}bad{% else %}warn{% endif %}">{{ t.risk }}</span></td></tr>
          {% endfor %}</tbody></table>
          {% else %}<p class="text-green-400 text-sm"><i class="fas fa-check mr-1"></i>No obfuscation patterns detected.</p>{% endif %}

        {% elif key == 'honeypot_detect' %}
          <div class="flex items-center gap-3 mb-3">
            {% if value.is_honeypot %}
              <span class="badge bad"><i class="fas fa-exclamation-triangle mr-1"></i>HONEYPOT DETECTED</span>
            {% else %}
              <span class="badge ok"><i class="fas fa-check mr-1"></i>No honeypot indicators</span>
            {% endif %}
            <span class="text-sm text-gray-400">Confidence: {{ value.confidence }}</span>
          </div>
          {% if value.indicators %}
          <table><thead><tr><th>Type</th><th>Indicator</th><th>Confidence</th></tr></thead>
          <tbody>{% for i in value.indicators %}
            <tr><td>{{ i.type }}</td><td>{{ i.indicator }}</td><td><span class="badge warn">{{ i.confidence }}</span></td></tr>
          {% endfor %}</tbody></table>
          {% endif %}

        {% elif key == 'geo_block' %}
          <div class="flex items-center gap-3 mb-3">
            {% if value.geo_blocked %}
              <span class="badge bad"><i class="fas fa-ban mr-1"></i>GEO-BLOCKED</span>
            {% else %}
              <span class="badge ok"><i class="fas fa-check mr-1"></i>No geo-blocking detected</span>
            {% endif %}
            {% if value.cdn_detected %}<span class="badge sev-low">CDN: {{ value.cdn_detected }}</span>{% endif %}
          </div>
          {% if value.indicators %}<div class="text-xs text-gray-400">Indicators: {{ value.indicators|join(', ') }}</div>{% endif %}

        {% elif key == 'media_scan' %}
          <div class="text-sm text-gray-400 mb-3">{{ value.total_assets }} media assets found</div>
          <div class="grid grid-cols-2 md:grid-cols-5 gap-4">
            {% for type, count in value.summary.items() %}
            <div class="bg-slate-800/40 rounded-lg p-3 text-center">
              <div class="text-2xl font-bold {% if type == 'video' %}text-red-400{% elif type == 'audio' %}text-green-400{% elif type == 'document' %}text-blue-400{% elif type == 'image' %}text-purple-400{% else %}text-yellow-400{% endif %}">{{ count }}</div>
              <div class="text-xs text-gray-400 capitalize">{{ type }}</div>
            </div>
            {% endfor %}
          </div>
          {% if value.assets %}
          <details class="mt-3"><summary class="text-blue-400 text-sm cursor-pointer">View asset URLs</summary>
            <div class="mt-2 grid md:grid-cols-2 gap-2">
            {% for type, urls in value.assets.items() if urls %}
              <div class="bg-slate-900/40 rounded p-2"><div class="text-xs font-bold text-gray-300 mb-1 capitalize">{{ type }}</div>
              {% for u in urls[:5] %}<div class="text-xs text-gray-500 truncate">{{ u }}</div>{% endfor %}</div>
            {% endfor %}
            </div>
          </details>
          {% endif %}

        {% elif key == 'mobile_detect' %}
          <div class="flex items-center gap-3 mb-3">
            {% if value.has_mobile_app %}
              <span class="badge ok"><i class="fas fa-mobile mr-1"></i>Mobile app detected</span>
            {% else %}
              <span class="badge warn">No mobile app found</span>
            {% endif %}
            {% if value.smart_banners %}<span class="badge sev-low">Smart banners</span>{% endif %}
          </div>
          <div class="grid md:grid-cols-2 gap-4">
            {% if value.ios %}
            <div class="bg-slate-800/40 rounded-lg p-3">
              <div class="text-sm font-medium text-gray-300 mb-2"><i class="fab fa-apple mr-2"></i>iOS App</div>
              <div class="text-xs text-gray-400">App ID: {{ value.ios.app_id }}</div>
              <a href="https://{{ value.ios.store_url }}" target="_blank" class="text-xs text-blue-400 hover:underline">View on App Store</a>
            </div>
            {% endif %}
            {% if value.android %}
            <div class="bg-slate-800/40 rounded-lg p-3">
              <div class="text-sm font-medium text-gray-300 mb-2"><i class="fab fa-android mr-2 text-green-400"></i>Android App</div>
              <div class="text-xs text-gray-400">Package: {{ value.android.package }}</div>
              <a href="https://{{ value.android.store_url }}" target="_blank" class="text-xs text-blue-400 hover:underline">View on Play Store</a>
            </div>
            {% endif %}
          </div>

        {% elif key == 'email_harvest' %}
          <div class="grid md:grid-cols-2 gap-4">
            <div class="bg-slate-800/40 rounded-lg p-3">
              <div class="text-sm font-medium text-gray-300 mb-2"><i class="fas fa-envelope mr-2 text-blue-400"></i>Email Services</div>
              {% if value.email_services %}<div class="flex flex-wrap gap-2">{% for s in value.email_services %}<span class="badge ok">{{ s }}</span>{% endfor %}</div>
              {% else %}<span class="text-gray-500 text-sm">None found</span>{% endif %}
            </div>
            <div class="bg-slate-800/40 rounded-lg p-3">
              <div class="text-sm font-medium text-gray-300 mb-2"><i class="fas fa-link mr-2 text-red-400"></i>Unsubscribe Links</div>
              {% if value.unsubscribe_links %}<div class="text-xs text-gray-400">{{ value.unsubscribe_links|length }} found</div>
              {% else %}<span class="text-gray-500 text-sm">None found</span>{% endif %}
            </div>
          </div>

        {% elif key == 'brand_extract' %}
          <div class="text-sm text-gray-400 mb-3">Brand: <span class="text-blue-400 font-bold">{{ value.brand_name or 'Unknown' }}</span> · {{ value.asset_count }} assets found</div>
          <div class="grid md:grid-cols-3 gap-4">
            <div class="bg-slate-800/40 rounded-lg p-3">
              <div class="text-sm font-medium text-gray-300 mb-2"><i class="fas fa-image mr-2 text-purple-400"></i>Logos</div>
              {% if value.logos %}<div class="text-xs text-gray-400">{{ value.logos|length }} found</div>{% else %}<span class="text-gray-500 text-sm">None</span>{% endif %}
            </div>
            <div class="bg-slate-800/40 rounded-lg p-3">
              <div class="text-sm font-medium text-gray-300 mb-2"><i class="fas fa-palette mr-2 text-pink-400"></i>Colors</div>
              <div class="flex flex-wrap gap-1">{% for c in value.colors[:10] %}<div style="background:{{ c }};width:20px;height:20px;border-radius:4px;border:1px solid #444"></div>{% endfor %}</div>
            </div>
            <div class="bg-slate-800/40 rounded-lg p-3">
              <div class="text-sm font-medium text-gray-300 mb-2"><i class="fas fa-font mr-2 text-green-400"></i>Fonts</div>
              <div class="text-xs text-gray-400">{{ value.fonts[:3]|join(', ') }}</div>
            </div>
          </div>

        {% elif key == 'timing_analysis' %}
          <div class="grid grid-cols-2 md:grid-cols-4 gap-4">
            <div class="bg-slate-800/40 rounded-lg p-3 text-center">
              <div class="text-2xl font-bold text-green-400">{{ value.min_ms }}ms</div>
              <div class="text-xs text-gray-400">Min</div>
            </div>
            <div class="bg-slate-800/40 rounded-lg p-3 text-center">
              <div class="text-2xl font-bold text-blue-400">{{ value.avg_ms }}ms</div>
              <div class="text-xs text-gray-400">Average</div>
            </div>
            <div class="bg-slate-800/40 rounded-lg p-3 text-center">
              <div class="text-2xl font-bold text-red-400">{{ value.max_ms }}ms</div>
              <div class="text-xs text-gray-400">Max</div>
            </div>
            <div class="bg-slate-800/40 rounded-lg p-3 text-center">
              <div class="text-2xl font-bold text-yellow-400">{{ value.variance }}ms</div>
              <div class="text-xs text-gray-400">Variance</div>
            </div>
          </div>
          <div class="text-xs text-gray-400 mt-2">{{ value.samples }} samples · {{ 'Consistent' if value.consistent else 'Variable' }} response times</div>

        {% elif key == 'api_fuzzer' %}
          <div class="text-sm text-gray-400 mb-3">{{ value.total_found }} API endpoints discovered</div>
          <div class="grid md:grid-cols-4 gap-4 mb-3">
            {% for cat, endpoints in value.categorized.items() %}
            <div class="bg-slate-800/40 rounded-lg p-3 text-center">
              <div class="text-2xl font-bold {% if cat == 'rest' %}text-blue-400{% elif cat == 'graphql' %}text-pink-400{% elif cat == 'websocket' %}text-green-400{% else %}text-gray-400{% endif %}">{{ endpoints|length }}</div>
              <div class="text-xs text-gray-400 capitalize">{{ cat }}</div>
            </div>
            {% endfor %}
          </div>
          {% if value.endpoints %}
          <details><summary class="text-blue-400 text-sm cursor-pointer">View endpoints</summary>
            <div class="mt-2 text-xs font-mono bg-slate-900/40 rounded p-2 max-h-40 overflow-y-auto">{% for e in value.endpoints[:30] %}<div class="text-gray-400">{{ e }}</div>{% endfor %}</div>
          </details>
          {% endif %}

        {% elif key == 'sub_cluster' %}
          <div class="text-sm text-gray-400 mb-3">{{ value.total }} subdomains clustered</div>
          <div class="grid md:grid-cols-4 gap-4">
            {% for category, subs in value.clusters.items() %}
            <div class="bg-slate-800/40 rounded-lg p-3">
              <div class="flex justify-between items-center mb-2">
                <span class="text-sm font-medium text-gray-300 capitalize">{{ category }}</span>
                <span class="badge sev-low">{{ subs|length }}</span>
              </div>
              <div class="text-xs text-gray-400 max-h-24 overflow-y-auto">{% for s in subs[:5] %}<div>{{ s }}</div>{% endfor %}</div>
            </div>
            {% endfor %}
          </div>

        {% elif key == 'site_value' %}
          <div class="flex items-center gap-3 mb-3">
            <span class="badge {% if value.category == 'enterprise' %}ok{% elif value.category == 'business' %}warn{% else %}sev-low{% endif %}">{{ value.category|upper }}</span>
            <span class="text-sm text-gray-400">Complexity Score: {{ value.complexity_score }}/100</span>
          </div>
          <div class="grid grid-cols-2 md:grid-cols-4 gap-4">
            <div class="bg-slate-800/40 rounded-lg p-3 text-center">
              <div class="text-2xl font-bold text-blue-400">{{ value.indicators.content_words }}</div>
              <div class="text-xs text-gray-400">Words</div>
            </div>
            <div class="bg-slate-800/40 rounded-lg p-3 text-center">
              <div class="text-2xl font-bold text-green-400">{{ value.indicators.forms }}</div>
              <div class="text-xs text-gray-400">Forms</div>
            </div>
            <div class="bg-slate-800/40 rounded-lg p-3 text-center">
              <div class="text-2xl font-bold text-yellow-400">{{ value.indicators.scripts }}</div>
              <div class="text-xs text-gray-400">Scripts</div>
            </div>
            <div class="bg-slate-800/40 rounded-lg p-3 text-center">
              <div class="text-2xl font-bold text-purple-400">{{ value.indicators.social_links|length }}</div>
              <div class="text-xs text-gray-400">Social Links</div>
            </div>
          </div>

        {% elif key == 'cookie_consent' %}
          <div class="flex items-center gap-3 mb-3">
            {% if value.has_banner %}
              <span class="badge ok"><i class="fas fa-check mr-1"></i>Cookie banner detected</span>
            {% else %}
              <span class="badge warn"><i class="fas fa-times mr-1"></i>No cookie banner</span>
            {% endif %}
            <span class="text-sm text-gray-400">Compliance Score: {{ value.compliance_score }}%</span>
          </div>
          <div class="grid md:grid-cols-3 gap-4">
            <div class="bg-slate-800/40 rounded-lg p-3">
              <div class="text-sm font-medium text-gray-300 mb-2">Consent Managers</div>
              {% if value.consent_managers %}<div class="flex flex-wrap gap-1">{% for m in value.consent_managers %}<span class="badge sev-low">{{ m }}</span>{% endfor %}</div>
              {% else %}<span class="text-gray-500 text-sm">None detected</span>{% endif %}
            </div>
            <div class="bg-slate-800/40 rounded-lg p-3 text-center">
              <div class="text-2xl font-bold {% if value.reject_option %}text-green-400{% else %}text-red-400{% endif %}">{{ 'Yes' if value.reject_option else 'No' }}</div>
              <div class="text-xs text-gray-400">Reject Option</div>
            </div>
            <div class="bg-slate-800/40 rounded-lg p-3 text-center">
              <div class="text-2xl font-bold {% if value.granular_control %}text-green-400{% else %}text-red-400{% endif %}">{{ 'Yes' if value.granular_control else 'No' }}</div>
              <div class="text-xs text-gray-400">Granular Control</div>
            </div>
          </div>

        {% elif key == 'github_dorks' %}
          <div class="text-sm text-gray-400 mb-3">{{ value.total_results }} results found from {{ value.query_count }} queries</div>
          {% if value.results %}
          <table><thead><tr><th>Repository</th><th>File</th><th>Query</th><th>Link</th></tr></thead>
          <tbody>{% for r in value.results[:30] %}
            <tr>
              <td class="text-sm">{{ r.repo }}</td>
              <td class="font-mono text-xs truncate max-w-[200px]">{{ r.path }}</td>
              <td><span class="badge warn">{{ r.query }}</span></td>
              <td><a href="{{ r.url }}" target="_blank" class="text-blue-400 hover:underline"><i class="fas fa-external-link text-xs"></i></a></td>
            </tr>
          {% endfor %}</tbody></table>
          {% else %}<p class="text-green-400 text-sm"><i class="fas fa-check mr-1"></i>No sensitive data found in GitHub.</p>{% endif %}

        {% elif key == 'hunter_io' %}
          <div class="flex items-center gap-3 mb-3">
            <span class="badge ok">{{ value.emails_found }} emails found</span>
            <span class="text-sm text-gray-400">Domain: {{ value.domain or 'N/A' }}</span>
          </div>
          {% if value.emails %}
          <table><thead><tr><th>Email</th><th>Type</th><th>Confidence</th><th>Sources</th></tr></thead>
          <tbody>{% for e in value.emails[:20] %}
            <tr>
              <td class="font-mono text-sm">{{ e.value }}</td>
              <td>{{ e.type or 'unknown' }}</td>
              <td><span class="badge {% if e.confidence > 80 %}ok{% elif e.confidence > 50 %}warn{% else %}sev-low{% endif %}">{{ e.confidence }}%</span></td>
              <td class="text-xs text-gray-400">{{ e.sources|length if e.sources else 0 }}</td>
            </tr>
          {% endfor %}</tbody></table>
          {% else %}<p class="text-gray-400 text-sm">No emails found for this domain.</p>{% endif %}

        {% elif key == 'enhanced_cve' %}
          <div class="text-sm text-gray-400 mb-3">{{ value.total_cves }} CVEs found for detected technologies</div>
          {% if value.cves %}
          <table><thead><tr><th>CVE ID</th><th>Technology</th><th>CVSS</th><th>Severity</th><th>Description</th></tr></thead>
          <tbody>{% for c in value.cves[:30] %}
            <tr>
              <td><a href="https://nvd.nist.gov/vuln/detail/{{ c.id }}" target="_blank" class="text-blue-400 hover:underline font-mono text-xs">{{ c.id }}</a></td>
              <td>{{ c.tech }}</td>
              <td class="font-bold {% if c.cvss >= 9 %}text-red-500{% elif c.cvss >= 7 %}text-orange-400{% elif c.cvss >= 4 %}text-yellow-400{% else %}text-green-400{% endif %}">{{ c.cvss or 'N/A' }}</td>
              <td><span class="badge {% if c.severity == 'critical' %}bad{% elif c.severity == 'high' %}sev-high{% elif c.severity == 'medium' %}sev-medium{% else %}sev-low{% endif %}">{{ c.severity }}</span></td>
              <td class="text-xs text-gray-400 max-w-xs truncate">{{ c.description[:100] }}...</td>
            </tr>
          {% endfor %}</tbody></table>
          {% else %}<p class="text-green-400 text-sm"><i class="fas fa-check mr-1"></i>No known CVEs found for detected technologies.</p>{% endif %}

        {% elif key == 'cert_monitor' %}
          {% set days = value.get('days_left', value.get('days_until_expiry', 'N/A')) %}
          <div class="flex items-center gap-3 mb-3">
            {% if value.get('expiring_soon') or (days is number and days < 30) %}
              <span class="badge bad"><i class="fas fa-exclamation-triangle mr-1"></i>Certificate expiring soon!</span>
            {% else %}
              <span class="badge ok"><i class="fas fa-check mr-1"></i>Certificate OK</span>
            {% endif %}
            <span class="text-sm text-gray-400">Days until expiry: <span class="font-bold {% if days is number and days < 30 %}text-red-400{% elif days is number and days < 60 %}text-yellow-400{% else %}text-green-400{% endif %}">{{ days }}</span></span>
          </div>
          <div class="grid md:grid-cols-2 gap-4">
            <div class="bg-slate-800/40 rounded-lg p-3">
              <div class="text-sm font-medium text-gray-300 mb-2"><i class="fas fa-certificate mr-2 text-green-400"></i>Certificate Details</div>
              <div class="text-xs text-gray-400 space-y-1">
                <div><span class="text-gray-500">Subject:</span> {{ value.get('subject', value.get('common_name', 'N/A')) }}</div>
                <div><span class="text-gray-500">Issuer:</span> {{ value.get('issuer', 'N/A') }}</div>
                <div><span class="text-gray-500">Valid From:</span> {{ value.get('not_before', value.get('valid_from', 'N/A')) }}</div>
                <div><span class="text-gray-500">Valid Until:</span> {{ value.get('not_after', value.get('valid_until', 'N/A')) }}</div>
              </div>
            </div>
            <div class="bg-slate-800/40 rounded-lg p-3">
              <div class="text-sm font-medium text-gray-300 mb-2"><i class="fas fa-shield-alt mr-2 text-blue-400"></i>Security</div>
              <div class="text-xs text-gray-400 space-y-1">
                <div><span class="text-gray-500">Algorithm:</span> {{ value.get('signature_algorithm', value.get('algorithm', 'N/A')) }}</div>
                <div><span class="text-gray-500">Key Size:</span> {{ value.get('key_size', value.get('key_bits', 'N/A')) }} bits</div>
                {% if value.get('san') %}<div><span class="text-gray-500">SAN:</span> {{ value.san[:3]|join(', ') }}{% if value.san|length > 3 %}...{% endif %}</div>{% endif %}
              </div>
            </div>
          </div>

        {% elif key == 'auth_weakness' %}
          <div class="flex items-center gap-3 mb-3">
            {% if value.vulnerabilities_found %}
              <span class="badge bad"><i class="fas fa-unlock mr-1"></i>{{ value.vulnerabilities_found }} issues found</span>
            {% else %}
              <span class="badge ok"><i class="fas fa-lock mr-1"></i>No auth weaknesses</span>
            {% endif %}
          </div>
          {% if value.findings %}
          <table><thead><tr><th>Issue</th><th>Severity</th><th>Details</th><th>Recommendation</th></tr></thead>
          <tbody>{% for f in value.findings %}
            <tr>
              <td>{{ f.issue }}</td>
              <td><span class="badge {% if f.severity == 'critical' %}bad{% elif f.severity == 'high' %}sev-high{% elif f.severity == 'medium' %}sev-medium{% else %}sev-low{% endif %}">{{ f.severity }}</span></td>
              <td class="text-xs text-gray-400">{{ f.details }}</td>
              <td class="text-xs text-gray-400">{{ f.recommendation }}</td>
            </tr>
          {% endfor %}</tbody></table>
          {% endif %}

        {% elif key == 'api_security' %}
          <div class="flex items-center gap-3 mb-3">
            {% if value.issues_found %}
              <span class="badge bad"><i class="fas fa-bug mr-1"></i>{{ value.issues_found }} API security issues</span>
            {% else %}
              <span class="badge ok"><i class="fas fa-check mr-1"></i>API appears secure</span>
            {% endif %}
          </div>
          {% if value.findings %}
          <table><thead><tr><th>Endpoint</th><th>Issue</th><th>Severity</th><th>Details</th></tr></thead>
          <tbody>{% for f in value.findings %}
            <tr>
              <td class="font-mono text-xs">{{ f.endpoint }}</td>
              <td>{{ f.issue }}</td>
              <td><span class="badge {% if f.severity == 'high' %}bad{% else %}warn{% endif %}">{{ f.severity }}</span></td>
              <td class="text-xs text-gray-400">{{ f.details }}</td>
            </tr>
          {% endfor %}</tbody></table>
          {% endif %}

        {% elif key == 'xxe_detection' %}
          <div class="flex items-center gap-3 mb-3">
            {% if value.vulnerable %}
              <span class="badge bad"><i class="fas fa-exclamation-triangle mr-1"></i>XXE VULNERABLE</span>
            {% else %}
              <span class="badge ok"><i class="fas fa-check mr-1"></i>No XXE detected</span>
            {% endif %}
          </div>
          {% if value.findings %}
          <table><thead><tr><th>Endpoint</th><th>Method</th><th>Status</th><th>Evidence</th></tr></thead>
          <tbody>{% for f in value.findings %}
            <tr>
              <td class="font-mono text-xs">{{ f.endpoint }}</td>
              <td>{{ f.method }}</td>
              <td><span class="badge {% if f.vulnerable %}bad{% else %}ok{% endif %}">{{ 'Vulnerable' if f.vulnerable else 'Safe' }}</span></td>
              <td class="text-xs text-gray-400">{{ f.evidence }}</td>
            </tr>
          {% endfor %}</tbody></table>
          {% endif %}

        {% elif key == 'ssrf_detection' %}
          <div class="flex items-center gap-3 mb-3">
            {% if value.vulnerable %}
              <span class="badge bad"><i class="fas fa-exclamation-triangle mr-1"></i>SSRF VULNERABLE</span>
            {% else %}
              <span class="badge ok"><i class="fas fa-check mr-1"></i>No SSRF detected</span>
            {% endif %}
          </div>
          {% if value.findings %}
          <table><thead><tr><th>Endpoint</th><th>Parameter</th><th>Status</th><th>Evidence</th></tr></thead>
          <tbody>{% for f in value.findings %}
            <tr>
              <td class="font-mono text-xs">{{ f.endpoint }}</td>
              <td><span class="badge warn">{{ f.parameter }}</span></td>
              <td><span class="badge {% if f.vulnerable %}bad{% else %}ok{% endif %}">{{ 'Vulnerable' if f.vulnerable else 'Safe' }}</span></td>
              <td class="text-xs text-gray-400">{{ f.evidence }}</td>
            </tr>
          {% endfor %}</tbody></table>
          {% endif %}

        {% elif key == 'open_redirect' %}
          <div class="flex items-center gap-3 mb-3">
            {% if value.vulnerable %}
              <span class="badge bad"><i class="fas fa-external-link mr-1"></i>OPEN REDIRECT FOUND</span>
            {% else %}
              <span class="badge ok"><i class="fas fa-check mr-1"></i>No open redirects</span>
            {% endif %}
          </div>
          {% if value.findings %}
          <table><thead><tr><th>URL</th><th>Parameter</th><th>Redirects To</th></tr></thead>
          <tbody>{% for f in value.findings %}
            <tr>
              <td class="font-mono text-xs truncate max-w-xs">{{ f.url }}</td>
              <td><span class="badge warn">{{ f.parameter }}</span></td>
              <td class="text-xs text-gray-400">{{ f.redirects_to }}</td>
            </tr>
          {% endfor %}</tbody></table>
          {% endif %}

        {% elif key == 'header_injection' %}
          <div class="flex items-center gap-3 mb-3">
            {% if value.vulnerable %}
              <span class="badge bad"><i class="fas fa-exclamation-triangle mr-1"></i>HEADER INJECTION FOUND</span>
            {% else %}
              <span class="badge ok"><i class="fas fa-check mr-1"></i>No header injection</span>
            {% endif %}
          </div>
          {% if value.findings %}
          <table><thead><tr><th>Endpoint</th><th>Header</th><th>Payload</th><th>Evidence</th></tr></thead>
          <tbody>{% for f in value.findings %}
            <tr>
              <td class="font-mono text-xs">{{ f.endpoint }}</td>
              <td>{{ f.header }}</td>
              <td class="font-mono text-xs text-red-400">{{ f.payload }}</td>
              <td class="text-xs text-gray-400">{{ f.evidence }}</td>
            </tr>
          {% endfor %}</tbody></table>
          {% endif %}

        {% elif key == 'leakcheck' or key.startswith('leakcheck_') %}
          <div class="flex items-center gap-3 mb-3">
            {% if value.found %}
              <span class="badge bad"><i class="fas fa-exclamation-triangle mr-1"></i>BREACH DETECTED</span>
            {% else %}
              <span class="badge ok"><i class="fas fa-check mr-1"></i>No breaches found</span>
            {% endif %}
            <span class="text-sm text-gray-400">Email: {{ value.email or 'N/A' }}</span>
          </div>
          {% if value.sources %}
          <table><thead><tr><th>Source</th><th>Date</th><th>Data Types</th></tr></thead>
          <tbody>{% for s in value.sources %}
            <tr>
              <td class="text-red-400">{{ s.name }}</td>
              <td>{{ s.date or 'Unknown' }}</td>
              <td class="text-xs text-gray-400">{{ s.data_types|join(', ') if s.data_types else 'Unknown' }}</td>
            </tr>
          {% endfor %}</tbody></table>
          {% endif %}

        {% elif key == 'waf_detect' %}
          <div class="flex items-center gap-3 mb-3">
            {% if value.detected %}
              <span class="badge warn"><i class="fas fa-shield-alt mr-1"></i>WAF Detected: {{ value.waf_name }}</span>
            {% else %}
              <span class="badge sev-low"><i class="fas fa-question-circle mr-1"></i>No WAF detected</span>
            {% endif %}
          </div>
          {% if value.indicators %}
          <div class="text-xs text-gray-400">Indicators: {{ value.indicators|join(', ') }}</div>
          {% endif %}

        {% elif key == 'port_scan' %}
          <div class="text-sm text-gray-400 mb-3">{{ value.ports_scanned }} ports scanned · {{ value.open_ports|length if value.open_ports else 0 }} open</div>
          {% if value.open_ports %}
          <table><thead><tr><th>Port</th><th>Service</th><th>State</th><th>Banner</th></tr></thead>
          <tbody>{% for p in value.open_ports %}
            <tr>
              <td class="font-mono">{{ p.port }}</td>
              <td>{{ p.service or 'unknown' }}</td>
              <td><span class="badge {% if p.state == 'open' %}ok{% else %}warn{% endif %}">{{ p.state }}</span></td>
              <td class="text-xs text-gray-400 truncate max-w-xs">{{ p.banner or 'N/A' }}</td>
            </tr>
          {% endfor %}</tbody></table>
          {% else %}<p class="text-gray-400 text-sm">No open ports found.</p>{% endif %}

        {% elif key == 'subdomain_takeover' %}
          <div class="flex items-center gap-3 mb-3">
            {% if value.vulnerable_count > 0 %}
              <span class="badge bad"><i class="fas fa-exclamation-triangle mr-1"></i>{{ value.vulnerable_count }} VULNERABLE</span>
            {% else %}
              <span class="badge ok"><i class="fas fa-check mr-1"></i>No takeover risks</span>
            {% endif %}
          </div>
          {% if value.results %}
          <table><thead><tr><th>Subdomain</th><th>CNAME</th><th>Service</th><th>Status</th></tr></thead>
          <tbody>{% for r in value.results %}
            <tr>
              <td class="font-mono text-sm">{{ r.subdomain }}</td>
              <td class="font-mono text-xs">{{ r.cname }}</td>
              <td>{{ r.service or 'Unknown' }}</td>
              <td><span class="badge {% if r.vulnerable %}bad{% else %}ok{% endif %}">{{ 'Vulnerable' if r.vulnerable else 'Safe' }}</span></td>
            </tr>
          {% endfor %}</tbody></table>
          {% endif %}

        {% elif key == 'email_security' %}
          <div class="grid md:grid-cols-4 gap-4">
            <div class="bg-slate-800/40 rounded-lg p-3 text-center">
              <div class="text-2xl font-bold {% if value.spf.valid %}text-green-400{% else %}text-red-400{% endif %}">{{ 'Pass' if value.spf.valid else 'Fail' }}</div>
              <div class="text-xs text-gray-400">SPF</div>
            </div>
            <div class="bg-slate-800/40 rounded-lg p-3 text-center">
              <div class="text-2xl font-bold {% if value.dkim.found %}text-green-400{% else %}text-yellow-400{% endif %}">{{ 'Pass' if value.dkim.found else 'N/A' }}</div>
              <div class="text-xs text-gray-400">DKIM</div>
            </div>
            <div class="bg-slate-800/40 rounded-lg p-3 text-center">
              <div class="text-2xl font-bold {% if value.dmarc.valid %}text-green-400{% else %}text-red-400{% endif %}">{{ 'Pass' if value.dmarc.valid else 'Fail' }}</div>
              <div class="text-xs text-gray-400">DMARC</div>
            </div>
            <div class="bg-slate-800/40 rounded-lg p-3 text-center">
              <div class="text-2xl font-bold {% if value.score >= 80 %}text-green-400{% elif value.score >= 50 %}text-yellow-400{% else %}text-red-400{% endif %}">{{ value.score }}%</div>
              <div class="text-xs text-gray-400">Score</div>
            </div>
          </div>
          {% if value.recommendations %}<div class="text-xs text-gray-400 mt-3">{{ value.recommendations|join(', ') }}</div>{% endif %}

        {% elif key == 'attack_map' %}
          <div class="text-sm text-gray-400 mb-3">{{ value.get('total_assets', 0) }} assets mapped across {{ value.get('categories', {})|length }} categories</div>
          <div class="grid md:grid-cols-3 gap-4">
            {% for category, assets in value.get('categories', value.get('assets', {})).items() %}
            <div class="bg-slate-800/40 rounded-lg p-3">
              <div class="flex justify-between items-center mb-2">
                <span class="text-sm font-medium text-gray-300 capitalize">{{ category }}</span>
                <span class="badge sev-low">{{ assets|length if assets is iterable else assets }}</span>
              </div>
              {% if assets is iterable and assets is not string %}
              <div class="text-xs text-gray-400 max-h-24 overflow-y-auto">{% for a in assets[:8] %}<div class="truncate">{{ a }}</div>{% endfor %}{% if assets|length > 8 %}<div class="text-blue-400">+{{ assets|length - 8 }} more</div>{% endif %}</div>
              {% endif %}
            </div>
            {% endfor %}
          </div>
          {% if value.get('risk_areas') %}
          <div class="mt-4"><div class="text-sm font-medium text-red-400 mb-2"><i class="fas fa-exclamation-triangle mr-2"></i>High Risk Areas</div>
          <div class="flex flex-wrap gap-2">{% for r in value.risk_areas %}<span class="badge bad">{{ r }}</span>{% endfor %}</div></div>
          {% endif %}

        {% elif key == 'report_narrative' %}
          <div class="prose prose-invert max-w-none">
            {% if value.get('executive_summary') %}
            <div class="bg-slate-800/40 rounded-lg p-4 mb-4">
              <h3 class="text-lg font-bold text-blue-400 mb-2"><i class="fas fa-file-alt mr-2"></i>Executive Summary</h3>
              <p class="text-gray-300 text-sm">{{ value.executive_summary }}</p>
            </div>
            {% endif %}
            {% if value.get('key_findings') %}
            <div class="bg-slate-800/40 rounded-lg p-4 mb-4">
              <h3 class="text-lg font-bold text-yellow-400 mb-2"><i class="fas fa-search mr-2"></i>Key Findings</h3>
              <ul class="list-disc pl-5 text-sm text-gray-300 space-y-1">{% for finding in value.key_findings %}<li>{{ finding }}</li>{% endfor %}</ul>
            </div>
            {% endif %}
            {% if value.get('recommendations') %}
            <div class="bg-slate-800/40 rounded-lg p-4">
              <h3 class="text-lg font-bold text-green-400 mb-2"><i class="fas fa-clipboard-check mr-2"></i>Recommendations</h3>
              <ul class="list-disc pl-5 text-sm text-gray-300 space-y-1">{% for rec in value.recommendations %}<li>{{ rec }}</li>{% endfor %}</ul>
            </div>
            {% endif %}
          </div>

        {% elif key == 'scan_diff' %}
          <div class="flex items-center gap-3 mb-3">
            <span class="badge {% if value.get('changes_detected') %}warn{% else %}ok{% endif %}">{{ value.get('total_changes', 0) }} changes detected</span>
            <span class="text-sm text-gray-400">Compared with previous scan</span>
          </div>
          <div class="grid md:grid-cols-3 gap-4">
            <div class="bg-green-900/20 rounded-lg p-3 border border-green-500/30">
              <div class="text-sm font-medium text-green-400 mb-2"><i class="fas fa-plus mr-2"></i>Added ({{ value.get('added', [])|length }})</div>
              <div class="text-xs text-gray-400 max-h-32 overflow-y-auto">{% for a in value.get('added', [])[:10] %}<div class="truncate">{{ a }}</div>{% endfor %}</div>
            </div>
            <div class="bg-red-900/20 rounded-lg p-3 border border-red-500/30">
              <div class="text-sm font-medium text-red-400 mb-2"><i class="fas fa-minus mr-2"></i>Removed ({{ value.get('removed', [])|length }})</div>
              <div class="text-xs text-gray-400 max-h-32 overflow-y-auto">{% for r in value.get('removed', [])[:10] %}<div class="truncate">{{ r }}</div>{% endfor %}</div>
            </div>
            <div class="bg-yellow-900/20 rounded-lg p-3 border border-yellow-500/30">
              <div class="text-sm font-medium text-yellow-400 mb-2"><i class="fas fa-exchange-alt mr-2"></i>Changed ({{ value.get('changed', [])|length }})</div>
              <div class="text-xs text-gray-400 max-h-32 overflow-y-auto">{% for c in value.get('changed', [])[:10] %}<div class="truncate">{{ c }}</div>{% endfor %}</div>
            </div>
          </div>

        {% elif key == 'delta_alerts' %}
          <div class="flex items-center gap-3 mb-3">
            <span class="badge {% if value.get('alerts') %}bad{% else %}ok{% endif %}">{{ value.get('alerts', [])|length }} alerts</span>
          </div>
          {% if value.get('alerts') %}
          <table><thead><tr><th>Alert</th><th>Severity</th><th>Details</th><th>Time</th></tr></thead>
          <tbody>{% for a in value.alerts %}
            <tr>
              <td>{{ a.get('type', 'Unknown') }}</td>
              <td><span class="badge {% if a.get('severity') == 'critical' %}bad{% elif a.get('severity') == 'high' %}sev-high{% else %}warn{% endif %}">{{ a.get('severity', 'medium') }}</span></td>
              <td class="text-xs text-gray-400">{{ a.get('details', '') }}</td>
              <td class="text-xs text-gray-500">{{ a.get('timestamp', '') }}</td>
            </tr>
          {% endfor %}</tbody></table>
          {% else %}<p class="text-green-400 text-sm"><i class="fas fa-check mr-1"></i>No significant changes detected since last scan.</p>{% endif %}

        {% elif key == 'entropy_scan' %}
          <div class="text-sm text-gray-400 mb-3">{{ value.get('total_secrets', 0) }} high-entropy strings detected</div>
          {% if value.get('secrets') %}
          <table><thead><tr><th>Type</th><th>Value</th><th>Entropy</th><th>Severity</th></tr></thead>
          <tbody>{% for s in value.secrets[:20] %}
            <tr>
              <td>{{ s.get('type', 'Unknown') }}</td>
              <td class="font-mono text-xs truncate max-w-xs">{{ s.get('value', '')[:40] }}...</td>
              <td>{{ s.get('entropy', 0)|round(2) }}</td>
              <td><span class="badge {% if s.get('severity') == 'critical' %}bad{% else %}warn{% endif %}">{{ s.get('severity', 'medium') }}</span></td>
            </tr>
          {% endfor %}</tbody></table>
          {% else %}<p class="text-green-400 text-sm"><i class="fas fa-check mr-1"></i>No secrets detected via entropy analysis.</p>{% endif %}

        {% elif key == 'wordlist_gen' %}
          <div class="text-sm text-gray-400 mb-3">{{ value.get('total_words', 0) }} words generated for bruteforce/fuzzing</div>
          <div class="grid md:grid-cols-4 gap-4">
            {% for category, words in value.get('categories', {}).items() %}
            <div class="bg-slate-800/40 rounded-lg p-3">
              <div class="text-sm font-medium text-gray-300 capitalize mb-2">{{ category }}</div>
              <div class="text-xs text-gray-400 max-h-32 overflow-y-auto font-mono">{% for w in words[:15] %}<div>{{ w }}</div>{% endfor %}</div>
            </div>
            {% endfor %}
          </div>
          {% if value.get('wordlist') %}
          <details class="mt-3"><summary class="text-blue-400 text-sm cursor-pointer">View full wordlist ({{ value.wordlist|length }} words)</summary>
            <pre class="bg-slate-900/60 rounded p-3 text-xs mt-2 max-h-48 overflow-y-auto">{{ value.wordlist[:100]|join('\n') }}</pre>
          </details>
          {% endif %}

        {% elif key == 'password_policy' %}
          <div class="grid md:grid-cols-2 gap-4">
            <div class="bg-slate-800/40 rounded-lg p-3">
              <div class="text-sm font-medium text-gray-300 mb-2"><i class="fas fa-lock mr-2 text-blue-400"></i>Detected Policy</div>
              <div class="space-y-2">
                <div class="flex justify-between text-xs"><span class="text-gray-400">Min Length:</span><span class="font-bold">{{ value.get('min_length', '?') }}</span></div>
                <div class="flex justify-between text-xs"><span class="text-gray-400">Requires Uppercase:</span><span class="font-bold {% if value.get('requires_uppercase') %}text-green-400{% else %}text-red-400{% endif %}">{{ 'Yes' if value.get('requires_uppercase') else 'No' }}</span></div>
                <div class="flex justify-between text-xs"><span class="text-gray-400">Requires Numbers:</span><span class="font-bold {% if value.get('requires_numbers') %}text-green-400{% else %}text-red-400{% endif %}">{{ 'Yes' if value.get('requires_numbers') else 'No' }}</span></div>
                <div class="flex justify-between text-xs"><span class="text-gray-400">Requires Special:</span><span class="font-bold {% if value.get('requires_special') %}text-green-400{% else %}text-red-400{% endif %}">{{ 'Yes' if value.get('requires_special') else 'No' }}</span></div>
              </div>
            </div>
            <div class="bg-slate-800/40 rounded-lg p-3">
              <div class="text-sm font-medium text-gray-300 mb-2"><i class="fas fa-shield-alt mr-2 text-green-400"></i>Strength Analysis</div>
              <div class="text-2xl font-bold text-center {% if value.get('strength_score', 0) >= 80 %}text-green-400{% elif value.get('strength_score', 0) >= 50 %}text-yellow-400{% else %}text-red-400{% endif %}">{{ value.get('strength_score', 0) }}%</div>
              <div class="text-xs text-gray-400 text-center">{{ value.get('strength_label', 'Unknown') }}</div>
            </div>
          </div>

        {% elif key == 'tech_timeline' %}
          <div class="text-sm text-gray-400 mb-3">Technology evolution over {{ value.get('snapshots', [])|length }} snapshots</div>
          {% if value.get('snapshots') %}
          <div class="relative">
            <div class="absolute left-4 top-0 bottom-0 w-0.5 bg-blue-500/30"></div>
            <div class="space-y-4 pl-10">
              {% for snapshot in value.snapshots[:10] %}
              <div class="relative">
                <div class="absolute -left-10 w-4 h-4 rounded-full bg-blue-500 border-2 border-slate-800"></div>
                <div class="bg-slate-800/40 rounded-lg p-3">
                  <div class="text-xs text-blue-400 mb-1">{{ snapshot.get('date', 'Unknown') }}</div>
                  <div class="flex flex-wrap gap-1">{% for tech in snapshot.get('technologies', [])[:8] %}<span class="badge sev-low">{{ tech }}</span>{% endfor %}</div>
                </div>
              </div>
              {% endfor %}
            </div>
          </div>
          {% else %}<p class="text-gray-400 text-sm">No historical snapshots available.</p>{% endif %}

        {% else %}
          {# Generic JSON fallback for unrendered modules #}
          <details open><summary class="text-blue-400 text-sm cursor-pointer">View data</summary>
            <pre class="bg-slate-900/60 rounded p-3 text-xs mt-2 overflow-x-auto max-h-96">{{ value | tojson(indent=2) }}</pre>
          </details>
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

  <script>
    document.addEventListener('DOMContentLoaded', function() {
      Chart.defaults.color = '#9ca3af';
      Chart.defaults.borderColor = 'rgba(75, 85, 99, 0.1)';

      // Risk Chart
      const ctxRisk = document.getElementById('riskChart').getContext('2d');
      new Chart(ctxRisk, {
        type: 'doughnut',
        data: {
          labels: ['Critical', 'High', 'Medium', 'Low'],
          datasets: [{
            data: [
              {{ results.get('cve_alerts', {}).get('rows', [])|length }} + {{ results.get('social_intel', {}).get('profiles', [])|length }}, 
              {{ results.get('_summary', {}).get('vt_malicious', 0) }} + {{ results.get('ransomware_check', {}).get('groups', [])|length }},
              {{ results.get('_summary', {}).get('missing_sec_headers', 0) }},
              {{ results.get('_summary', {}).get('subdomains', 0) }}
            ],
            backgroundColor: ['#ef4444', '#f97316', '#f59e0b', '#3b82f6'],
            borderWidth: 0,
            hoverOffset: 4
          }]
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          plugins: {
            legend: { position: 'right', labels: { font: { family: 'Inter' }, usePointStyle: true } },
            title: { display: true, text: 'Findings Distribution', color: '#e5e7eb', font: { size: 14 } }
          },
          cutout: '70%'
        }
      });

      // Coverage Chart
      const ctxCov = document.getElementById('coverageChart').getContext('2d');
      new Chart(ctxCov, {
        type: 'radar',
        data: {
          labels: ['Recon', 'Network', 'Web Sec', 'Threat Intel', 'Compliance', 'SOCMINT'],
          datasets: [{
            label: 'Assessment Depth',
            data: [
              {{ 90 if results.get('subdomain_scan') else 20 }},
              {{ 85 if results.get('port_scan') or results.get('dns') else 20 }},
              {{ 95 if results.get('headers') or results.get('sec_headers') else 10 }},
              {{ 80 if results.get('virustotal') or results.get('abuseipdb') else 0 }},
              {{ 75 if results.get('privacy_detect') or results.get('gdpr') else 0 }},
              {{ 85 if results.get('social_intel') or results.get('social_extract') else 0 }}
            ],
            borderColor: '#8b5cf6',
            backgroundColor: 'rgba(139, 92, 246, 0.2)',
            pointBackgroundColor: '#8b5cf6',
            pointBorderColor: '#fff',
            pointHoverBackgroundColor: '#fff',
            pointHoverBorderColor: '#8b5cf6'
          }]
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          scales: {
            r: {
              angleLines: { color: 'rgba(75, 85, 99, 0.2)' },
              grid: { color: 'rgba(75, 85, 99, 0.2)' },
              pointLabels: { color: '#9ca3af', font: { size: 11 } },
              ticks: { display: false, backdropColor: 'transparent' }
            }
          },
          plugins: {
            legend: { display: false },
            title: { display: true, text: 'Security Coverage Map', color: '#e5e7eb', font: { size: 14 } }
          }
        }
      });
    });
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

def is_public_http_url(u: str) -> bool:
    """
    Basic SSRF guard: ensure URL uses http/https and resolves to a public IP.
    """
    try:
        parsed = urlparse(u)
        if parsed.scheme not in ("http", "https"):
            return False
        host = parsed.hostname
        if not host:
            return False
        ip = socket.gethostbyname(host)
        # Convert to integer to check ranges
        parts = ip.split(".")
        if len(parts) != 4:
            return False
        octets = [int(p) for p in parts]
        ip_int = (octets[0] << 24) | (octets[1] << 16) | (octets[2] << 8) | octets[3]
        # Private/loopback/link-local/reserved ranges we want to block
        private_ranges = [
            (0x0A000000, 0x0AFFFFFF),       # 10.0.0.0/8
            (0xAC100000, 0xAC1FFFFF),       # 172.16.0.0/12
            (0xC0A80000, 0xC0A8FFFF),       # 192.168.0.0/16
            (0x7F000000, 0x7FFFFFFF),       # 127.0.0.0/8 loopback
            (0xA9FE0000, 0xA9FEFFFF),       # 169.254.0.0/16 link-local
            (0x00000000, 0x00FFFFFF),       # 0.0.0.0/8
            (0xE0000000, 0xEFFFFFFF),       # 224.0.0.0/4 multicast
        ]
        for start, end in private_ranges:
            if start <= ip_int <= end:
                return False
        return True
    except Exception:
        return False

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

# ================================================================================
#                          PHASE 2: AI-POWERED THREAT ANALYSIS
# ================================================================================

class AIThreatAnalyzer:
    """AI-powered threat analysis engine for intelligent risk assessment."""
    
    def __init__(self):
        self.client = None
        if OPENAI_API_KEY and OPENAI_AVAILABLE:
            openai.api_key = OPENAI_API_KEY
            self.client = "openai"
        elif ANTHROPIC_API_KEY and ANTHROPIC_AVAILABLE:
            self.client = "anthropic"
    
    def generate_executive_summary(self, results: dict) -> str:
        """Generate an AI-powered executive summary of scan results."""
        if not AI_ENABLED or not self.client:
            return self._fallback_summary(results)
        
        summary = results.get("_summary", {})
        findings_text = self._extract_key_findings(results)
        
        prompt = f"""Analyze these security scan results and provide a concise executive summary (3-4 sentences):

Risk Score: {summary.get('risk_score', 0)}/100
Risk Level: {summary.get('risk_level', 'unknown')}
Key Findings:
{findings_text}

Focus on: business impact, critical vulnerabilities, and recommended immediate actions."""

        try:
            if self.client == "openai":
                response = openai.chat.completions.create(
                    model=AI_MODEL,
                    messages=[{"role": "user", "content": prompt}],
                    max_tokens=300,
                    temperature=0.3
                )
                return response.choices[0].message.content
            elif self.client == "anthropic":
                client = anthropic.Anthropic(api_key=ANTHROPIC_API_KEY)
                response = client.messages.create(
                    model="claude-3-sonnet-20240229",
                    max_tokens=300,
                    messages=[{"role": "user", "content": prompt}]
                )
                return response.content[0].text
        except Exception as e:
            logger.warning(f"AI summary generation failed: {e}")
            return self._fallback_summary(results)
        
        return self._fallback_summary(results)
    
    def _fallback_summary(self, results: dict) -> str:
        """Generate a rule-based summary when AI is unavailable."""
        summary = results.get("_summary", {})
        risk_level = summary.get("risk_level", "unknown")
        risk_score = summary.get("risk_score", 0)
        
        if risk_level == "critical":
            severity = "Critical security issues detected requiring immediate attention."
        elif risk_level == "high":
            severity = "High-risk vulnerabilities found that should be prioritized."
        elif risk_level == "medium":
            severity = "Moderate security concerns identified for review."
        else:
            severity = "No significant security issues detected."
        
        return f"{severity} Overall risk score: {risk_score}/100."
    
    def _extract_key_findings(self, results: dict) -> str:
        """Extract key findings from scan results for AI context."""
        findings = []
        
        if results.get("ssl_tls", {}).get("grade"):
            findings.append(f"- SSL/TLS Grade: {results['ssl_tls']['grade']}")
        
        if results.get("sec_headers", {}).get("rows"):
            missing = sum(1 for r in results["sec_headers"]["rows"] if r.get("status") != "OK")
            findings.append(f"- Missing Security Headers: {missing}")
        
        if results.get("virustotal", {}).get("data"):
            stats = results["virustotal"]["data"].get("attributes", {}).get("last_analysis_stats", {})
            findings.append(f"- VirusTotal Malicious: {stats.get('malicious', 0)}")
        
        if results.get("js_secrets", {}).get("secrets_found"):
            findings.append(f"- Exposed Secrets: {len(results['js_secrets']['secrets_found'])}")
        
        if results.get("subdomain_takeover", {}).get("vulnerable"):
            findings.append(f"- Subdomain Takeover Risks: {len(results['subdomain_takeover']['vulnerable'])}")
        
        if results.get("cors", {}).get("vulnerable"):
            findings.append("- CORS Misconfiguration Detected")
        
        return "\n".join(findings) if findings else "No critical findings."
    
    def smart_risk_scoring(self, results: dict) -> dict:
        """ML-enhanced risk scoring with context awareness."""
        base_score = results.get("_summary", {}).get("risk_score", 0)
        
        # Weighted factors based on real-world impact
        weights = {
            "exposed_secrets": 25,
            "subdomain_takeover": 20,
            "cors_vulnerable": 15,
            "weak_tls": 15,
            "missing_headers": 5,
            "open_risky_ports": 10,
            "vt_malicious": 20,
            "hibp_breaches": 10,
        }
        
        adjusted_score = base_score
        factors = []
        
        # Check each weighted factor
        if results.get("js_secrets", {}).get("secrets_found"):
            count = len(results["js_secrets"]["secrets_found"])
            adjusted_score += weights["exposed_secrets"] * min(count, 3)
            factors.append(f"+{weights['exposed_secrets'] * min(count, 3)} (exposed secrets)")
        
        if results.get("subdomain_takeover", {}).get("vulnerable"):
            count = len(results["subdomain_takeover"]["vulnerable"])
            adjusted_score += weights["subdomain_takeover"] * count
            factors.append(f"+{weights['subdomain_takeover'] * count} (subdomain takeover)")
        
        if results.get("cors", {}).get("vulnerable"):
            adjusted_score += weights["cors_vulnerable"]
            factors.append(f"+{weights['cors_vulnerable']} (CORS misconfiguration)")
        
        if results.get("ssl_tls", {}).get("grade") in ["D", "F"]:
            adjusted_score += weights["weak_tls"]
            factors.append(f"+{weights['weak_tls']} (weak TLS)")
        
        # Normalize to 0-100
        adjusted_score = min(100, max(0, adjusted_score))
        
        # Determine severity level
        if adjusted_score >= 80:
            level = "critical"
        elif adjusted_score >= 60:
            level = "high"
        elif adjusted_score >= 40:
            level = "medium"
        else:
            level = "low"
        
        return {
            "score": adjusted_score,
            "level": level,
            "factors": factors,
            "confidence": "high" if len(factors) > 2 else "medium"
        }
    
    def generate_remediation_advice(self, finding_type: str, details: dict) -> str:
        """Generate AI-powered remediation recommendations."""
        remediation_db = {
            "missing_csp": "Implement Content-Security-Policy header with strict directives. Start with 'default-src self' and gradually allow trusted sources.",
            "weak_tls": "Upgrade to TLS 1.3 or TLS 1.2 with strong cipher suites. Disable SSLv3, TLS 1.0, and TLS 1.1.",
            "cors_vulnerable": "Restrict Access-Control-Allow-Origin to specific trusted domains. Never use wildcard (*) with credentials.",
            "exposed_secrets": "Immediately rotate all exposed credentials. Use environment variables or secret management systems.",
            "subdomain_takeover": "Remove dangling DNS records or claim the external service. Regularly audit DNS CNAME records.",
            "missing_hsts": "Add Strict-Transport-Security header with max-age of at least 31536000 and includeSubDomains.",
        }
        return remediation_db.get(finding_type, "Consult security documentation for remediation guidance.")


# Initialize global AI analyzer
ai_analyzer = AIThreatAnalyzer()


# ================================================================================
#                     PHASE 3: VULNERABILITY CORRELATION ENGINE
# ================================================================================

class VulnerabilityCorrelator:
    """Advanced vulnerability correlation with CVE, EPSS, and KEV integration."""
    
    NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    EPSS_API_URL = "https://api.first.org/data/v1/epss"
    KEV_JSON_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    EXPLOITDB_API_URL = "https://www.exploit-db.com/search"
    
    def __init__(self):
        self.kev_cache = {}
        self.kev_last_fetch = None
    
    def cve_deep_match(self, tech_stack: list, version_hints: dict = None) -> list:
        """Deep CVE matching with version-aware lookup."""
        cves = []
        version_hints = version_hints or {}
        
        # Technology to CPE mapping
        tech_cpe_map = {
            "apache": "cpe:2.3:a:apache:http_server",
            "nginx": "cpe:2.3:a:nginx:nginx",
            "wordpress": "cpe:2.3:a:wordpress:wordpress",
            "django": "cpe:2.3:a:djangoproject:django",
            "react": "cpe:2.3:a:facebook:react",
            "jquery": "cpe:2.3:a:jquery:jquery",
            "php": "cpe:2.3:a:php:php",
            "nodejs": "cpe:2.3:a:nodejs:node.js",
            "express": "cpe:2.3:a:expressjs:express",
            "tomcat": "cpe:2.3:a:apache:tomcat",
            "iis": "cpe:2.3:a:microsoft:iis",
        }
        
        for tech in tech_stack:
            tech_lower = tech.lower()
            for key, cpe in tech_cpe_map.items():
                if key in tech_lower:
                    try:
                        params = {"cpeName": cpe, "resultsPerPage": 5}
                        resp = SESSION.get(self.NVD_API_URL, params=params, timeout=15)
                        if resp.ok:
                            data = resp.json()
                            for vuln in data.get("vulnerabilities", [])[:5]:
                                cve_data = vuln.get("cve", {})
                                cve_id = cve_data.get("id", "")
                                
                                # Get CVSS score
                                cvss = None
                                metrics = cve_data.get("metrics", {})
                                if metrics.get("cvssMetricV31"):
                                    cvss = metrics["cvssMetricV31"][0].get("cvssData", {}).get("baseScore")
                                elif metrics.get("cvssMetricV2"):
                                    cvss = metrics["cvssMetricV2"][0].get("cvssData", {}).get("baseScore")
                                
                                desc = ""
                                for d in cve_data.get("descriptions", []):
                                    if d.get("lang") == "en":
                                        desc = d.get("value", "")[:200]
                                        break
                                
                                cves.append({
                                    "id": cve_id,
                                    "technology": tech,
                                    "cvss": cvss,
                                    "description": desc,
                                    "severity": self._cvss_to_severity(cvss)
                                })
                    except Exception as e:
                        logger.debug(f"CVE lookup failed for {tech}: {e}")
                    break
        
        return cves
    
    def _cvss_to_severity(self, cvss: float) -> str:
        """Convert CVSS score to severity label."""
        if cvss is None:
            return "unknown"
        if cvss >= 9.0:
            return "critical"
        elif cvss >= 7.0:
            return "high"
        elif cvss >= 4.0:
            return "medium"
        else:
            return "low"
    
    def epss_scoring(self, cve_ids: list) -> dict:
        """Get EPSS (Exploit Prediction Scoring System) scores for CVEs."""
        if not cve_ids:
            return {"scores": [], "error": None}
        
        try:
            params = {"cve": ",".join(cve_ids[:50])}  # API limit
            resp = SESSION.get(self.EPSS_API_URL, params=params, timeout=15)
            if resp.ok:
                data = resp.json()
                scores = []
                for item in data.get("data", []):
                    scores.append({
                        "cve": item.get("cve"),
                        "epss": float(item.get("epss", 0)),
                        "percentile": float(item.get("percentile", 0)),
                        "date": item.get("date")
                    })
                return {"scores": scores, "error": None}
            return {"scores": [], "error": f"API returned {resp.status_code}"}
        except Exception as e:
            return {"scores": [], "error": str(e)}
    
    def kev_cross_reference(self, cve_ids: list) -> dict:
        """Check CVEs against CISA Known Exploited Vulnerabilities catalog."""
        # Cache KEV data for 1 hour
        now = datetime.now()
        if not self.kev_cache or not self.kev_last_fetch or (now - self.kev_last_fetch).seconds > 3600:
            try:
                resp = SESSION.get(self.KEV_JSON_URL, timeout=15)
                if resp.ok:
                    kev_data = resp.json()
                    self.kev_cache = {v["cveID"]: v for v in kev_data.get("vulnerabilities", [])}
                    self.kev_last_fetch = now
            except Exception as e:
                logger.warning(f"KEV fetch failed: {e}")
        
        kev_matches = []
        for cve_id in cve_ids:
            if cve_id in self.kev_cache:
                kev = self.kev_cache[cve_id]
                kev_matches.append({
                    "cve": cve_id,
                    "vendor": kev.get("vendorProject"),
                    "product": kev.get("product"),
                    "vulnerability_name": kev.get("vulnerabilityName"),
                    "date_added": kev.get("dateAdded"),
                    "due_date": kev.get("dueDate"),
                    "known_ransomware": kev.get("knownRansomwareCampaignUse", "Unknown")
                })
        
        return {
            "matches": kev_matches,
            "total_checked": len(cve_ids),
            "kev_count": len(kev_matches),
            "in_kev": len(kev_matches) > 0
        }
    
    def vulnerability_prioritization(self, vulns: list) -> list:
        """Prioritize vulnerabilities based on EPSS, KEV, and CVSS."""
        prioritized = []
        
        cve_ids = [v.get("id") for v in vulns if v.get("id")]
        epss_data = self.epss_scoring(cve_ids)
        kev_data = self.kev_cross_reference(cve_ids)
        
        # Create lookup tables
        epss_lookup = {s["cve"]: s for s in epss_data.get("scores", [])}
        kev_lookup = {m["cve"]: m for m in kev_data.get("matches", [])}
        
        for vuln in vulns:
            cve_id = vuln.get("id", "")
            cvss = vuln.get("cvss", 0) or 0
            
            # Calculate priority score
            priority_score = cvss * 10  # Base score
            
            # EPSS boost
            if cve_id in epss_lookup:
                epss = epss_lookup[cve_id].get("epss", 0)
                priority_score += epss * 30  # High EPSS = high priority
                vuln["epss"] = epss
                vuln["epss_percentile"] = epss_lookup[cve_id].get("percentile")
            
            # KEV boost (critical)
            if cve_id in kev_lookup:
                priority_score += 50  # KEV = immediate attention
                vuln["in_kev"] = True
                vuln["kev_details"] = kev_lookup[cve_id]
            else:
                vuln["in_kev"] = False
            
            vuln["priority_score"] = round(priority_score, 2)
            prioritized.append(vuln)
        
        # Sort by priority score descending
        prioritized.sort(key=lambda x: x.get("priority_score", 0), reverse=True)
        
        return prioritized


# Initialize global vulnerability correlator
vuln_correlator = VulnerabilityCorrelator()


def enhanced_cve_lookup(tech_stack: list) -> dict:
    """Enhanced CVE lookup with EPSS and KEV correlation."""
    cves = vuln_correlator.cve_deep_match(tech_stack)
    if cves:
        cves = vuln_correlator.vulnerability_prioritization(cves)
    
    kev_count = sum(1 for c in cves if c.get("in_kev"))
    high_epss = sum(1 for c in cves if c.get("epss", 0) > 0.1)
    
    return {
        "vulnerabilities": cves,
        "total": len(cves),
        "kev_count": kev_count,
        "high_epss_count": high_epss,
        "critical_count": sum(1 for c in cves if c.get("severity") == "critical")
    }


# ================================================================================
#                        PHASE 4: EXTENDED OSINT MODULES
# ================================================================================

def hunter_io_lookup(domain: str) -> dict:
    """Email enumeration via Hunter.io API."""
    if not HUNTER_API_KEY:
        return {"error": "HUNTER_API_KEY not configured"}
    
    try:
        resp = SESSION.get(
            "https://api.hunter.io/v2/domain-search",
            params={"domain": domain, "api_key": HUNTER_API_KEY},
            timeout=15
        )
        if resp.ok:
            data = resp.json().get("data", {})
            return {
                "domain": domain,
                "organization": data.get("organization"),
                "emails_found": len(data.get("emails", [])),
                "emails": [
                    {
                        "email": e.get("value"),
                        "type": e.get("type"),
                        "confidence": e.get("confidence"),
                        "position": e.get("position"),
                        "department": e.get("department")
                    }
                    for e in data.get("emails", [])[:20]
                ],
                "pattern": data.get("pattern"),
                "disposable": data.get("disposable")
            }
        return {"error": f"API returned {resp.status_code}"}
    except Exception as e:
        return {"error": str(e)}


def censys_search(domain: str) -> dict:
    """Asset discovery via Censys Search API."""
    if not CENSYS_API_ID or not CENSYS_API_SECRET:
        return {"error": "CENSYS_API_ID and CENSYS_API_SECRET not configured"}
    
    if not CENSYS_AVAILABLE:
        return {"error": "censys library not installed"}
    
    try:
        h = CensysHosts(api_id=CENSYS_API_ID, api_secret=CENSYS_API_SECRET)
        query = f"services.tls.certificates.leaf_data.names: {domain}"
        results = []
        
        for page in h.search(query, per_page=25, pages=1):
            for host in page:
                results.append({
                    "ip": host.get("ip"),
                    "services": [
                        {"port": s.get("port"), "service_name": s.get("service_name")}
                        for s in host.get("services", [])[:5]
                    ],
                    "location": host.get("location", {}).get("country"),
                    "autonomous_system": host.get("autonomous_system", {}).get("name")
                })
        
        return {
            "domain": domain,
            "hosts_found": len(results),
            "hosts": results[:20]
        }
    except Exception as e:
        return {"error": str(e)}


def leakcheck_lookup(email: str) -> dict:
    """Credential leak checking via LeakCheck API."""
    if not LEAKCHECK_API_KEY:
        return {"error": "LEAKCHECK_API_KEY not configured"}
    
    try:
        resp = SESSION.get(
            f"https://leakcheck.io/api/public",
            params={"key": LEAKCHECK_API_KEY, "check": email, "type": "email"},
            timeout=15
        )
        if resp.ok:
            data = resp.json()
            if data.get("success"):
                return {
                    "email": email,
                    "found": data.get("found", 0),
                    "sources": data.get("sources", [])[:10],
                    "fields": data.get("fields", [])
                }
            return {"email": email, "found": 0, "sources": []}
        return {"error": f"API returned {resp.status_code}"}
    except Exception as e:
        return {"error": str(e)}


def github_dork_search(domain: str) -> dict:
    """Search GitHub for exposed secrets/configs related to domain."""
    dorks = [
        f'"{domain}" password',
        f'"{domain}" api_key',
        f'"{domain}" secret',
        f'"{domain}" AWS_SECRET',
        f'"{domain}" BEGIN RSA PRIVATE KEY',
        f'filename:.env "{domain}"',
        f'filename:config "{domain}"',
    ]
    
    results = []
    headers = {"Accept": "application/vnd.github+json"}
    if GITHUB_TOKEN:
        headers["Authorization"] = f"Bearer {GITHUB_TOKEN}"
    
    for dork in dorks[:3]:  # Limit to avoid rate limits
        try:
            resp = SESSION.get(
                "https://api.github.com/search/code",
                params={"q": dork, "per_page": 5},
                headers=headers,
                timeout=15
            )
            if resp.ok:
                data = resp.json()
                for item in data.get("items", [])[:3]:
                    results.append({
                        "dork": dork,
                        "repository": item.get("repository", {}).get("full_name"),
                        "path": item.get("path"),
                        "url": item.get("html_url"),
                        "score": item.get("score")
                    })
            time.sleep(1)  # Rate limit
        except Exception as e:
            logger.debug(f"GitHub dork failed: {e}")
    
    return {
        "domain": domain,
        "dorks_searched": len(dorks),
        "findings": results,
        "potential_leaks": len(results)
    }


def fullhunt_lookup(domain: str) -> dict:
    """Attack surface discovery via FullHunt API."""
    if not FULLHUNT_API_KEY:
        return {"error": "FULLHUNT_API_KEY not configured"}
    
    try:
        resp = SESSION.get(
            f"https://fullhunt.io/api/v1/domain/{domain}/subdomains",
            headers={"X-API-KEY": FULLHUNT_API_KEY},
            timeout=15
        )
        if resp.ok:
            data = resp.json()
            return {
                "domain": domain,
                "subdomains": data.get("subdomains", [])[:50],
                "total": data.get("subdomain_count", 0)
            }
        return {"error": f"API returned {resp.status_code}"}
    except Exception as e:
        return {"error": str(e)}


def binaryedge_lookup(domain: str) -> dict:
    """Host intelligence via BinaryEdge API."""
    if not BINARYEDGE_API_KEY:
        return {"error": "BINARYEDGE_API_KEY not configured"}
    
    try:
        resp = SESSION.get(
            f"https://api.binaryedge.io/v2/query/domains/subdomain/{domain}",
            headers={"X-Key": BINARYEDGE_API_KEY},
            timeout=15
        )
        if resp.ok:
            data = resp.json()
            return {
                "domain": domain,
                "subdomains": data.get("events", [])[:50],
                "total": data.get("total", 0)
            }
        return {"error": f"API returned {resp.status_code}"}
    except Exception as e:
        return {"error": str(e)}


def builtwith_lookup(domain: str) -> dict:
    """Technology profiling via BuiltWith API."""
    if not BUILTWITH_API_KEY:
        return {"error": "BUILTWITH_API_KEY not configured"}
    
    try:
        resp = SESSION.get(
            "https://api.builtwith.com/free1/api.json",
            params={"KEY": BUILTWITH_API_KEY, "LOOKUP": domain},
            timeout=15
        )
        if resp.ok:
            data = resp.json()
            groups = data.get("groups", [])
            technologies = []
            for group in groups:
                for cat in group.get("categories", []):
                    technologies.extend([
                        {"name": t.get("name"), "category": cat.get("name")}
                        for t in cat.get("live", [])
                    ])
            return {
                "domain": domain,
                "technologies": technologies[:30],
                "total": len(technologies)
            }
        return {"error": f"API returned {resp.status_code}"}
    except Exception as e:
        return {"error": str(e)}


# ================================================================================
#                      PHASE 5: ACTIVE SECURITY TESTING SUITE
# ================================================================================

def auth_weakness_scan(url: str) -> dict:
    """Test for authentication weaknesses (authorized testing only)."""
    findings = []
    
    # Common authentication endpoints
    auth_endpoints = [
        "/login", "/signin", "/auth", "/authenticate",
        "/admin/login", "/api/login", "/api/auth",
        "/user/login", "/account/login"
    ]
    
    for endpoint in auth_endpoints:
        target = urljoin(url, endpoint)
        try:
            # Check if endpoint exists
            resp = SESSION.get(target, timeout=10, allow_redirects=False)
            if resp.status_code in [200, 301, 302, 401, 403]:
                finding = {
                    "endpoint": endpoint,
                    "status": resp.status_code,
                    "issues": []
                }
                
                # Check for missing security headers on login
                if "X-Frame-Options" not in resp.headers:
                    finding["issues"].append("Clickjacking possible (no X-Frame-Options)")
                
                # Check for rate limiting headers
                if "X-RateLimit-Limit" not in resp.headers and "RateLimit" not in str(resp.headers):
                    finding["issues"].append("No rate limiting detected")
                
                # Check for password field autocomplete
                if resp.status_code == 200 and "autocomplete" in resp.text.lower():
                    if 'autocomplete="off"' not in resp.text.lower() and 'autocomplete="new-password"' not in resp.text.lower():
                        finding["issues"].append("Password autocomplete may be enabled")
                
                if finding["issues"]:
                    findings.append(finding)
        except Exception:
            pass
    
    return {
        "endpoints_checked": len(auth_endpoints),
        "findings": findings,
        "issues_found": sum(len(f.get("issues", [])) for f in findings)
    }


def api_security_scan(url: str) -> dict:
    """API security testing including GraphQL introspection."""
    results = {"rest_api": [], "graphql": None, "issues": []}
    
    # Common API endpoints
    api_endpoints = [
        "/api", "/api/v1", "/api/v2",
        "/rest", "/v1", "/v2",
        "/swagger.json", "/openapi.json",
        "/api-docs", "/swagger-ui.html"
    ]
    
    for endpoint in api_endpoints:
        target = urljoin(url, endpoint)
        try:
            resp = SESSION.get(target, timeout=10)
            if resp.status_code == 200:
                results["rest_api"].append({
                    "endpoint": endpoint,
                    "status": resp.status_code,
                    "content_type": resp.headers.get("Content-Type", ""),
                    "size": len(resp.content)
                })
                
                # Check for exposed API documentation
                if "swagger" in endpoint.lower() or "openapi" in endpoint.lower():
                    results["issues"].append(f"API documentation exposed at {endpoint}")
        except Exception:
            pass
    
    # GraphQL introspection check
    graphql_endpoints = ["/graphql", "/api/graphql", "/graphql/console"]
    introspection_query = '{"query": "{ __schema { types { name } } }"}'
    
    for endpoint in graphql_endpoints:
        target = urljoin(url, endpoint)
        try:
            resp = SESSION.post(
                target,
                data=introspection_query,
                headers={"Content-Type": "application/json"},
                timeout=10
            )
            if resp.status_code == 200 and "__schema" in resp.text:
                results["graphql"] = {
                    "endpoint": endpoint,
                    "introspection_enabled": True,
                    "severity": "medium"
                }
                results["issues"].append(f"GraphQL introspection enabled at {endpoint}")
                break
        except Exception:
            pass
    
    return results


def xxe_detection(url: str) -> dict:
    """Detect potential XXE vulnerabilities (safe payloads only)."""
    xxe_endpoints = ["/api/upload", "/upload", "/import", "/parse"]
    findings = []
    
    # Safe XXE detection payload (doesn't actually exploit)
    safe_payload = '''<?xml version="1.0"?>
<!DOCTYPE test [<!ENTITY xxe SYSTEM "file:///nonexistent">]>
<test>&xxe;</test>'''
    
    for endpoint in xxe_endpoints:
        target = urljoin(url, endpoint)
        try:
            resp = SESSION.post(
                target,
                data=safe_payload,
                headers={"Content-Type": "application/xml"},
                timeout=10
            )
            # Check for XML parsing errors that indicate XXE processing
            error_indicators = ["entity", "dtd", "doctype", "external", "system"]
            if any(ind in resp.text.lower() for ind in error_indicators):
                findings.append({
                    "endpoint": endpoint,
                    "indicator": "XML entity processing detected",
                    "status": resp.status_code,
                    "severity": "high"
                })
        except Exception:
            pass
    
    return {
        "endpoints_tested": len(xxe_endpoints),
        "findings": findings,
        "vulnerable": len(findings) > 0
    }


def ssrf_detection(url: str) -> dict:
    """Detect potential SSRF vulnerabilities."""
    ssrf_params = ["url", "uri", "path", "dest", "redirect", "target", "rurl", "fetch", "link"]
    findings = []
    
    # Canary URL - use a safe domain that doesn't exist
    canary = "http://ssrf-canary.internal.test"
    
    parsed = urlparse(url)
    base_url = f"{parsed.scheme}://{parsed.netloc}"
    
    for param in ssrf_params:
        test_url = f"{url}?{param}={quote(canary)}"
        try:
            resp = SESSION.get(test_url, timeout=10, allow_redirects=False)
            # Check if the canary appears in response or if there's a connection attempt
            if canary in resp.text or resp.status_code in [500, 502, 503]:
                findings.append({
                    "parameter": param,
                    "indicator": "Potential SSRF - URL parameter may be fetched",
                    "status": resp.status_code,
                    "severity": "high"
                })
        except Exception:
            pass
    
    return {
        "parameters_tested": len(ssrf_params),
        "findings": findings,
        "potential_ssrf": len(findings) > 0
    }


def open_redirect_scan(url: str) -> dict:
    """Scan for open redirect vulnerabilities."""
    redirect_params = ["url", "redirect", "next", "return", "returnUrl", "goto", "destination", "redir", "out", "continue"]
    findings = []
    
    evil_domain = "https://evil.com"
    
    for param in redirect_params:
        test_url = f"{url}?{param}={quote(evil_domain)}"
        try:
            resp = SESSION.get(test_url, timeout=10, allow_redirects=False)
            if resp.status_code in [301, 302, 303, 307, 308]:
                location = resp.headers.get("Location", "")
                if evil_domain in location:
                    findings.append({
                        "parameter": param,
                        "redirect_to": location,
                        "status": resp.status_code,
                        "severity": "medium"
                    })
        except Exception:
            pass
    
    return {
        "parameters_tested": len(redirect_params),
        "findings": findings,
        "vulnerable": len(findings) > 0
    }


def header_injection_test(url: str) -> dict:
    """Test for HTTP header injection vulnerabilities."""
    findings = []
    
    # Test Host header injection
    try:
        resp = SESSION.get(
            url,
            headers={"Host": "evil.com"},
            timeout=10,
            allow_redirects=False
        )
        if "evil.com" in resp.text or "evil.com" in str(resp.headers):
            findings.append({
                "type": "Host Header Injection",
                "severity": "high",
                "indicator": "Host header reflected in response"
            })
    except Exception:
        pass
    
    # Test X-Forwarded-Host
    try:
        resp = SESSION.get(
            url,
            headers={"X-Forwarded-Host": "evil.com"},
            timeout=10
        )
        if "evil.com" in resp.text:
            findings.append({
                "type": "X-Forwarded-Host Injection",
                "severity": "medium",
                "indicator": "X-Forwarded-Host reflected in response"
            })
    except Exception:
        pass
    
    return {
        "tests_performed": 2,
        "findings": findings,
        "vulnerable": len(findings) > 0
    }


# ================================================================================
#                    PHASE 6: CONTINUOUS ATTACK SURFACE MONITORING
# ================================================================================

def change_detection(scan_id_old: int, scan_id_new: int, db) -> dict:
    """Detect changes between two scans."""
    try:
        old_row = db.execute("SELECT results FROM scans WHERE id=?", (scan_id_old,)).fetchone()
        new_row = db.execute("SELECT results FROM scans WHERE id=?", (scan_id_new,)).fetchone()
        
        if not old_row or not new_row:
            return {"error": "Scan not found"}
        
        old_results = json.loads(old_row["results"])
        new_results = json.loads(new_row["results"])
        
        changes = {
            "subdomains": {"added": [], "removed": []},
            "open_ports": {"added": [], "removed": []},
            "technologies": {"added": [], "removed": []},
            "security_headers": {"improved": [], "degraded": []},
            "risk_score_delta": 0
        }
        
        # Subdomain changes
        old_subs = set(old_results.get("subdomain_scan", {}).get("found", []))
        new_subs = set(new_results.get("subdomain_scan", {}).get("found", []))
        changes["subdomains"]["added"] = list(new_subs - old_subs)
        changes["subdomains"]["removed"] = list(old_subs - new_subs)
        
        # Technology changes
        old_tech = set(old_results.get("tech", {}).get("stack", []))
        new_tech = set(new_results.get("tech", {}).get("stack", []))
        changes["technologies"]["added"] = list(new_tech - old_tech)
        changes["technologies"]["removed"] = list(old_tech - new_tech)
        
        # Risk score change
        old_score = old_results.get("_summary", {}).get("risk_score", 0)
        new_score = new_results.get("_summary", {}).get("risk_score", 0)
        changes["risk_score_delta"] = new_score - old_score
        
        # Determine if changes are concerning
        changes["alert_worthy"] = (
            len(changes["subdomains"]["added"]) > 0 or
            abs(changes["risk_score_delta"]) >= 10 or
            len(changes["technologies"]["added"]) > 0
        )
        
        return changes
    except Exception as e:
        return {"error": str(e)}


def trend_analysis(domain: str, db, limit: int = 10) -> dict:
    """Analyze security trends over time for a domain."""
    try:
        rows = db.execute(
            "SELECT id, results, scan_date FROM scans WHERE url LIKE ? ORDER BY id DESC LIMIT ?",
            (f"%{domain}%", limit)
        ).fetchall()
        
        if len(rows) < 2:
            return {"error": "Need at least 2 scans for trend analysis"}
        
        data_points = []
        for row in rows:
            results = json.loads(row["results"])
            summary = results.get("_summary", {})
            data_points.append({
                "scan_id": row["id"],
                "date": row["scan_date"],
                "risk_score": summary.get("risk_score", 0),
                "subdomains": summary.get("subdomains", 0),
                "missing_headers": summary.get("missing_sec_headers", 0)
            })
        
        # Calculate trends
        risk_scores = [d["risk_score"] for d in data_points]
        trend = "stable"
        if len(risk_scores) >= 2:
            if risk_scores[0] > risk_scores[-1] + 10:
                trend = "improving"
            elif risk_scores[0] < risk_scores[-1] - 10:
                trend = "degrading"
        
        return {
            "domain": domain,
            "total_scans": len(data_points),
            "data_points": data_points,
            "trend": trend,
            "average_risk": statistics.mean(risk_scores) if risk_scores else 0,
            "risk_std_dev": statistics.stdev(risk_scores) if len(risk_scores) > 1 else 0
        }
    except Exception as e:
        return {"error": str(e)}


def cert_expiry_monitor(domain: str) -> dict:
    """Monitor SSL certificate expiration."""
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
        
        not_after = datetime.strptime(cert.get('notAfter', ''), '%b %d %H:%M:%S %Y %Z')
        days_until_expiry = (not_after - datetime.utcnow()).days
        
        alert_level = "ok"
        if days_until_expiry < 0:
            alert_level = "critical"
        elif days_until_expiry < 7:
            alert_level = "high"
        elif days_until_expiry < 30:
            alert_level = "medium"
        elif days_until_expiry < 60:
            alert_level = "low"
        
        return {
            "domain": domain,
            "expires": not_after.isoformat(),
            "days_until_expiry": days_until_expiry,
            "alert_level": alert_level,
            "issuer": dict(x[0] for x in cert.get('issuer', [])),
            "san": [x[1] for x in cert.get('subjectAltName', [])]
        }
    except Exception as e:
        return {"error": str(e)}


# ================================================================================
#                       PHASE 8: INTEGRATION & AUTOMATION HUB
# ================================================================================

def export_splunk_format(results: dict, url: str) -> list:
    """Export scan results in Splunk HEC format."""
    events = []
    timestamp = int(time.time())
    
    # Main summary event
    events.append({
        "time": timestamp,
        "source": "aegis",
        "sourcetype": "aegis:scan",
        "event": {
            "url": url,
            "risk_score": results.get("_summary", {}).get("risk_score", 0),
            "risk_level": results.get("_summary", {}).get("risk_level", "unknown"),
            "subdomains_count": results.get("_summary", {}).get("subdomains", 0),
            "vt_malicious": results.get("_summary", {}).get("vt_malicious", 0)
        }
    })
    
    # Vulnerability events
    for vuln in results.get("cve_alerts", {}).get("rows", []):
        events.append({
            "time": timestamp,
            "source": "aegis",
            "sourcetype": "aegis:vulnerability",
            "event": {
                "url": url,
                "cve_id": vuln.get("id"),
                "cvss": vuln.get("cvss"),
                "severity": vuln.get("severity"),
                "technology": vuln.get("tech")
            }
        })
    
    return events


def export_elastic_format(results: dict, url: str) -> list:
    """Export scan results in Elasticsearch bulk format."""
    docs = []
    timestamp = datetime.utcnow().isoformat()
    
    # Main document
    docs.append({
        "_index": "aegis-scans",
        "_source": {
            "@timestamp": timestamp,
            "url": url,
            "domain": get_domain(url),
            "risk": results.get("_summary", {}),
            "scan_metadata": results.get("_meta", {})
        }
    })
    
    return docs


def send_discord_notification(message: str, webhook_url: str = None) -> bool:
    """Send notification to Discord webhook."""
    url = webhook_url or DISCORD_WEBHOOK_URL
    if not url:
        return False
    
    try:
        resp = requests.post(url, json={"content": message}, timeout=10)
        return resp.ok
    except Exception:
        return False


def send_teams_notification(message: str, webhook_url: str = None) -> bool:
    """Send notification to Microsoft Teams webhook."""
    url = webhook_url or TEAMS_WEBHOOK_URL
    if not url:
        return False
    
    try:
        payload = {
            "@type": "MessageCard",
            "@context": "http://schema.org/extensions",
            "summary": "AEGIS Alert",
            "themeColor": "FF0000",
            "title": "AEGIS Security Alert",
            "text": message
        }
        resp = requests.post(url, json=payload, timeout=10)
        return resp.ok
    except Exception:
        return False


def send_telegram_notification(message: str) -> bool:
    """Send notification to Telegram."""
    if not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID:
        return False
    
    try:
        url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
        resp = requests.post(url, json={"chat_id": TELEGRAM_CHAT_ID, "text": message, "parse_mode": "HTML"}, timeout=10)
        return resp.ok
    except Exception:
        return False


# ================================================================================
#                      PHASE 9: MULTI-TARGET CAMPAIGN SCANNING
# ================================================================================

class CampaignManager:
    """Manage multi-target scanning campaigns."""
    
    def __init__(self, db_connection):
        self.db = db_connection
    
    def create_campaign(self, name: str, domains: list, services: list, mode: str = "defensive") -> int:
        """Create a new scanning campaign."""
        campaign_data = {
            "domains": domains,
            "services": services,
            "mode": mode,
            "status": "pending",
            "created_at": datetime.utcnow().isoformat()
        }
        
        cur = self.db.execute(
            "INSERT INTO campaigns (name, domains, status, created_at) VALUES (?, ?, ?, ?)",
            (name, json.dumps(campaign_data), "pending", datetime.utcnow().isoformat())
        )
        self.db.commit()
        return cur.lastrowid
    
    def get_campaign_status(self, campaign_id: int) -> dict:
        """Get campaign execution status."""
        row = self.db.execute("SELECT * FROM campaigns WHERE id=?", (campaign_id,)).fetchone()
        if not row:
            return {"error": "Campaign not found"}
        
        return {
            "id": row["id"],
            "name": row["name"],
            "status": row["status"],
            "domains": json.loads(row["domains"]),
            "created_at": row["created_at"]
        }


def asset_discovery(seed_domain: str) -> dict:
    """Discover related assets from a seed domain."""
    discovered = {
        "subdomains": [],
        "related_domains": [],
        "ip_ranges": [],
        "email_patterns": []
    }
    
    # Get subdomains from multiple sources
    try:
        # crt.sh
        resp = SESSION.get(
            "https://crt.sh/",
            params={"q": f"%.{seed_domain}", "output": "json"},
            timeout=15
        )
        if resp.ok:
            for entry in resp.json():
                name = entry.get("name_value", "")
                for line in name.split("\n"):
                    subdomain = line.strip().lower()
                    if subdomain and not subdomain.startswith("*") and subdomain not in discovered["subdomains"]:
                        discovered["subdomains"].append(subdomain)
    except Exception:
        pass
    
    # Limit results
    discovered["subdomains"] = discovered["subdomains"][:100]
    
    return {
        "seed_domain": seed_domain,
        "discovered": discovered,
        "total_assets": len(discovered["subdomains"]) + len(discovered["related_domains"])
    }


def generate_executive_report(scan_ids: list, db) -> str:
    """Generate executive summary report for multiple scans."""
    scans_data = []
    
    for scan_id in scan_ids:
        row = db.execute("SELECT url, results, scan_date FROM scans WHERE id=?", (scan_id,)).fetchone()
        if row:
            results = json.loads(row["results"])
            scans_data.append({
                "url": row["url"],
                "scan_date": row["scan_date"],
                "summary": results.get("_summary", {})
            })
    
    if not scans_data:
        return "No scan data available."
    
    # Generate summary
    total_risk = sum(s["summary"].get("risk_score", 0) for s in scans_data)
    avg_risk = total_risk / len(scans_data) if scans_data else 0
    
    high_risk = [s for s in scans_data if s["summary"].get("risk_score", 0) >= 60]
    
    report = f"""
# AEGIS Executive Security Report
Generated: {datetime.utcnow().isoformat()}

## Summary
- **Total Targets Scanned**: {len(scans_data)}
- **Average Risk Score**: {avg_risk:.1f}/100
- **High Risk Targets**: {len(high_risk)}

## High Risk Targets
"""
    
    for target in high_risk:
        report += f"- {target['url']} (Risk: {target['summary'].get('risk_score', 0)})\n"
    
    return report

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
            try:
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
            except TimeoutError:
                # Some futures timed out, collect what we have and continue
                crawled['stats']['errors'] += 1
                for future in futures:
                    future.cancel()
    
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


# ================================================================================
#                     PHASE 6: INNOVATIVE ANALYSIS FEATURES (v4.0)
# ================================================================================

class EntropyScanner:
    """Find high-entropy strings that may be secrets using Shannon entropy."""
    
    def __init__(self):
        self.high_entropy_threshold = 4.5  # Bits per character
        self.min_string_length = 16
        self.max_string_length = 256
        
        # Common false positive patterns to filter
        self.false_positive_patterns = [
            re.compile(r'^[A-Za-z0-9+/=]+$'),  # Pure base64 (might be legit data)
            re.compile(r'^[0-9a-f]+$', re.I),  # Pure hex (might be hash)
            re.compile(r'^[A-Z_]+$'),  # Constants
            re.compile(r'^(https?://|ftp://)'),  # URLs
        ]
        
        # String extraction pattern
        self.string_pattern = re.compile(r'["\']([A-Za-z0-9+/=_\-\.]{16,256})["\']')
    
    def calculate_entropy(self, data: str) -> float:
        """Calculate Shannon entropy of a string."""
        if not data:
            return 0.0
        
        import math
        from collections import Counter
        
        counts = Counter(data)
        length = len(data)
        entropy = 0.0
        
        for count in counts.values():
            probability = count / length
            entropy -= probability * math.log2(probability)
        
        return entropy
    
    def is_false_positive(self, s: str) -> bool:
        """Check if string is likely a false positive."""
        # Skip if matches common patterns
        for pattern in self.false_positive_patterns:
            if pattern.match(s):
                # But allow if entropy is very high
                if self.calculate_entropy(s) < 5.5:
                    return True
        
        # Skip if too uniform
        unique_chars = len(set(s))
        if unique_chars < len(s) * 0.3:
            return True
        
        return False
    
    def categorize_secret(self, s: str, entropy: float) -> str:
        """Categorize potential secret type."""
        s_lower = s.lower()
        
        if s.startswith('AKIA'):
            return "AWS Access Key"
        if s.startswith('ghp_') or s.startswith('gho_'):
            return "GitHub Token"
        if s.startswith('sk-') or s.startswith('pk_'):
            return "API Key (Stripe-like)"
        if s.startswith('eyJ'):
            return "JWT Token"
        if 'BEGIN' in s and 'PRIVATE' in s:
            return "Private Key"
        if entropy > 5.5:
            return "High-Entropy Secret"
        if entropy > 5.0:
            return "Possible API Key"
        return "Potential Secret"
    
    def scan_content(self, content: str) -> list:
        """Scan content for high-entropy strings."""
        findings = []
        seen = set()
        
        matches = self.string_pattern.findall(content)
        
        for match in matches:
            if match in seen:
                continue
            seen.add(match)
            
            if len(match) < self.min_string_length:
                continue
            
            entropy = self.calculate_entropy(match)
            
            if entropy >= self.high_entropy_threshold:
                if not self.is_false_positive(match):
                    category = self.categorize_secret(match, entropy)
                    severity = "critical" if entropy > 5.5 else "high" if entropy > 5.0 else "medium"
                    
                    findings.append({
                        "value": match[:40] + "..." if len(match) > 40 else match,
                        "entropy": round(entropy, 2),
                        "length": len(match),
                        "category": category,
                        "severity": severity,
                    })
        
        # Sort by entropy descending
        findings.sort(key=lambda x: x["entropy"], reverse=True)
        return findings[:20]  # Limit to top 20
    
    def scan_url(self, url: str) -> dict:
        """Scan URL and its JavaScript files for high-entropy secrets."""
        result = {
            "secrets_found": [],
            "js_files_scanned": 0,
            "total_strings_analyzed": 0,
            "high_entropy_count": 0
        }
        
        try:
            # Scan main page
            resp = SESSION.get(url, timeout=DEFAULT_TIMEOUT)
            soup = BeautifulSoup(resp.text, 'html.parser')
            
            all_content = [resp.text]
            
            # Get all JavaScript files
            for script in soup.find_all('script', src=True):
                try:
                    js_url = urljoin(url, script['src'])
                    js_resp = SESSION.get(js_url, timeout=10)
                    if js_resp.ok:
                        all_content.append(js_resp.text)
                        result["js_files_scanned"] += 1
                except Exception:
                    pass
            
            # Scan inline scripts
            for script in soup.find_all('script', src=False):
                if script.string:
                    all_content.append(script.string)
            
            # Analyze all content
            for content in all_content:
                strings = self.string_pattern.findall(content)
                result["total_strings_analyzed"] += len(strings)
                
                findings = self.scan_content(content)
                result["secrets_found"].extend(findings)
            
            # Deduplicate
            seen = set()
            unique = []
            for f in result["secrets_found"]:
                if f["value"] not in seen:
                    seen.add(f["value"])
                    unique.append(f)
            
            result["secrets_found"] = unique[:20]
            result["high_entropy_count"] = len(result["secrets_found"])
            
        except Exception as e:
            result["error"] = str(e)
        
        return result


class ReconWordlistGenerator:
    """Generate custom wordlists from target content for bruteforce."""
    
    def __init__(self):
        self.word_pattern = re.compile(r'\b[a-zA-Z][a-zA-Z0-9_-]{2,30}\b')
        self.path_pattern = re.compile(r'(?:href|src|action)=["\']/?([a-zA-Z0-9_\-/]+)["\']', re.I)
        self.js_identifier = re.compile(r'\b(?:var|let|const|function)\s+([a-zA-Z_][a-zA-Z0-9_]*)', re.I)
        
        # Common words to filter out
        self.stopwords = {
            'the', 'and', 'for', 'are', 'but', 'not', 'you', 'all', 'can', 'had',
            'her', 'was', 'one', 'our', 'out', 'has', 'have', 'this', 'that',
            'with', 'they', 'from', 'been', 'will', 'your', 'more', 'when',
            'class', 'function', 'return', 'const', 'var', 'let', 'import',
            'export', 'default', 'true', 'false', 'null', 'undefined', 'type',
            'script', 'style', 'div', 'span', 'img', 'src', 'href', 'link',
        }
    
    def extract_from_html(self, content: str, url: str) -> set:
        """Extract potential wordlist entries from HTML content."""
        words = set()
        
        try:
            soup = BeautifulSoup(content, 'html.parser')
            
            # Extract from title
            if soup.title and soup.title.string:
                words.update(self.word_pattern.findall(soup.title.string))
            
            # Extract from meta tags
            for meta in soup.find_all('meta', attrs={'name': True, 'content': True}):
                words.update(self.word_pattern.findall(meta.get('content', '')))
            
            # Extract from links and paths
            for tag in soup.find_all(['a', 'link', 'script', 'img', 'form']):
                for attr in ['href', 'src', 'action']:
                    val = tag.get(attr, '')
                    if val:
                        # Extract path segments
                        path = urlparse(val).path
                        segments = [s for s in path.split('/') if s and len(s) > 2]
                        words.update(segments)
            
            # Extract from headings and important text
            for tag in soup.find_all(['h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'strong', 'b']):
                if tag.string:
                    words.update(self.word_pattern.findall(tag.string))
            
            # Extract from id and class attributes
            for tag in soup.find_all(True):
                for attr in ['id', 'class', 'name', 'data-page', 'data-section']:
                    val = tag.get(attr, '')
                    if isinstance(val, list):
                        val = ' '.join(val)
                    words.update(self.word_pattern.findall(val))
            
        except Exception:
            pass
        
        return words
    
    def extract_from_robots(self, url: str) -> set:
        """Extract paths from robots.txt."""
        words = set()
        
        try:
            robots_url = urljoin(url, '/robots.txt')
            resp = SESSION.get(robots_url, timeout=10)
            if resp.ok:
                for line in resp.text.splitlines():
                    if ':' in line:
                        parts = line.split(':', 1)
                        if len(parts) == 2:
                            path = parts[1].strip()
                            segments = [s for s in path.split('/') if s and len(s) > 2]
                            words.update(segments)
        except Exception:
            pass
        
        return words
    
    def extract_from_sitemap(self, url: str) -> set:
        """Extract paths from sitemap.xml."""
        words = set()
        
        try:
            for sitemap_path in ['/sitemap.xml', '/sitemap_index.xml', '/sitemap.gz']:
                sitemap_url = urljoin(url, sitemap_path)
                resp = SESSION.get(sitemap_url, timeout=10)
                if resp.ok and '<url>' in resp.text.lower():
                    # Extract URLs from sitemap
                    urls = re.findall(r'<loc>([^<]+)</loc>', resp.text, re.I)
                    for u in urls[:100]:
                        path = urlparse(u).path
                        segments = [s for s in path.split('/') if s and len(s) > 2]
                        words.update(segments)
                    break
        except Exception:
            pass
        
        return words
    
    def extract_from_javascript(self, content: str) -> set:
        """Extract identifiers from JavaScript."""
        words = set()
        
        # Function and variable names
        words.update(self.js_identifier.findall(content))
        
        # Object properties
        props = re.findall(r'\.([a-zA-Z_][a-zA-Z0-9_]{2,30})', content)
        words.update(props)
        
        # String literals that look like endpoints
        endpoints = re.findall(r'["\']/?([a-zA-Z][a-zA-Z0-9_/-]{2,50})["\']', content)
        for ep in endpoints:
            segments = [s for s in ep.split('/') if s and len(s) > 2]
            words.update(segments)
        
        return words
    
    def generate_wordlist(self, url: str) -> dict:
        """Generate comprehensive wordlist from target."""
        result = {
            "subdomains": [],
            "directories": [],
            "parameters": [],
            "combined": [],
            "sources": {},
            "stats": {}
        }
        
        all_words = set()
        
        try:
            # Get main page
            resp = SESSION.get(url, timeout=DEFAULT_TIMEOUT)
            
            # Extract from HTML
            html_words = self.extract_from_html(resp.text, url)
            result["sources"]["html"] = len(html_words)
            all_words.update(html_words)
            
            # Extract from robots.txt
            robots_words = self.extract_from_robots(url)
            result["sources"]["robots"] = len(robots_words)
            all_words.update(robots_words)
            
            # Extract from sitemap
            sitemap_words = self.extract_from_sitemap(url)
            result["sources"]["sitemap"] = len(sitemap_words)
            all_words.update(sitemap_words)
            
            # Extract from JavaScript
            soup = BeautifulSoup(resp.text, 'html.parser')
            js_words = set()
            
            for script in soup.find_all('script', src=True):
                try:
                    js_url = urljoin(url, script['src'])
                    js_resp = SESSION.get(js_url, timeout=10)
                    if js_resp.ok:
                        js_words.update(self.extract_from_javascript(js_resp.text))
                except Exception:
                    pass
            
            for script in soup.find_all('script', src=False):
                if script.string:
                    js_words.update(self.extract_from_javascript(script.string))
            
            result["sources"]["javascript"] = len(js_words)
            all_words.update(js_words)
            
            # Filter and categorize
            filtered = set()
            for word in all_words:
                word_lower = word.lower()
                if word_lower not in self.stopwords and len(word) > 2:
                    filtered.add(word_lower)
            
            # Generate subdomain variations
            subdomains = []
            for word in sorted(filtered)[:100]:
                if len(word) <= 20 and word.isalnum():
                    subdomains.append(word)
                    # Add common variations
                    subdomains.append(f"{word}-api")
                    subdomains.append(f"{word}-dev")
                    subdomains.append(f"api-{word}")
            
            # Generate directory variations
            directories = []
            for word in sorted(filtered)[:100]:
                directories.append(f"/{word}")
                directories.append(f"/{word}/")
                directories.append(f"/api/{word}")
            
            result["subdomains"] = sorted(set(subdomains))[:200]
            result["directories"] = sorted(set(directories))[:200]
            result["combined"] = sorted(filtered)[:500]
            result["stats"] = {
                "total_unique_words": len(filtered),
                "subdomain_variations": len(result["subdomains"]),
                "directory_variations": len(result["directories"]),
            }
            
        except Exception as e:
            result["error"] = str(e)
        
        return result


class PasswordPolicyDetector:
    """Detect password complexity requirements from login forms."""
    
    def __init__(self):
        self.login_patterns = [
            re.compile(r'<form[^>]*(?:login|signin|auth)[^>]*>', re.I),
            re.compile(r'<input[^>]*type=["\']password["\'][^>]*>', re.I),
        ]
        
        self.register_patterns = [
            re.compile(r'<form[^>]*(?:register|signup|create)[^>]*>', re.I),
            re.compile(r'<input[^>]*(?:confirm|repeat|retype).*?password', re.I),
        ]
    
    def find_forms(self, url: str) -> dict:
        """Find login and registration forms."""
        result = {
            "login_forms": [],
            "register_forms": [],
            "password_fields": []
        }
        
        try:
            # Check common auth endpoints
            endpoints = [
                url, 
                urljoin(url, '/login'),
                urljoin(url, '/signin'),
                urljoin(url, '/register'),
                urljoin(url, '/signup'),
                urljoin(url, '/auth'),
            ]
            
            for endpoint in endpoints:
                try:
                    resp = SESSION.get(endpoint, timeout=10, allow_redirects=True)
                    if resp.status_code == 200:
                        soup = BeautifulSoup(resp.text, 'html.parser')
                        
                        # Find password fields
                        for inp in soup.find_all('input', {'type': 'password'}):
                            field_info = {
                                "url": endpoint,
                                "name": inp.get('name', ''),
                                "id": inp.get('id', ''),
                                "minlength": inp.get('minlength'),
                                "maxlength": inp.get('maxlength'),
                                "pattern": inp.get('pattern'),
                                "required": inp.has_attr('required'),
                                "autocomplete": inp.get('autocomplete'),
                            }
                            result["password_fields"].append(field_info)
                        
                        # Determine form type
                        for form in soup.find_all('form'):
                            form_text = str(form).lower()
                            form_info = {
                                "url": endpoint,
                                "action": form.get('action', ''),
                                "method": form.get('method', 'GET'),
                            }
                            
                            if any(k in form_text for k in ['register', 'signup', 'create account']):
                                result["register_forms"].append(form_info)
                            elif any(k in form_text for k in ['login', 'signin', 'sign in']):
                                result["login_forms"].append(form_info)
                            elif soup.find('input', {'type': 'password'}):
                                result["login_forms"].append(form_info)
                    
                except Exception:
                    continue
            
        except Exception as e:
            result["error"] = str(e)
        
        return result
    
    def analyze_javascript_validation(self, content: str) -> dict:
        """Analyze JavaScript for password validation rules."""
        rules = {
            "min_length": None,
            "max_length": None,
            "requires_uppercase": False,
            "requires_lowercase": False,
            "requires_number": False,
            "requires_special": False,
            "patterns": []
        }
        
        # Look for common patterns
        patterns = [
            (r'(?:password|pass).*?\.length\s*[<>=]+\s*(\d+)', 'length'),
            (r'minlength[\'"]?\s*[:=]\s*(\d+)', 'min_length'),
            (r'(?:password).*?(?:at least|minimum|min)\s*(\d+)', 'min_length'),
            (r'[A-Z]', 'requires_uppercase'),
            (r'[a-z]', 'requires_lowercase'),
            (r'[0-9]|\\d', 'requires_number'),
            (r'[!@#$%^&*(),.?":{}|<>]|special', 'requires_special'),
        ]
        
        for pattern, rule_name in patterns:
            matches = re.findall(pattern, content, re.I)
            if matches:
                if rule_name in ['min_length', 'length']:
                    try:
                        val = int(matches[0])
                        if val > 0 and val < 100:
                            rules["min_length"] = val
                    except (ValueError, IndexError):
                        pass
                elif rule_name.startswith('requires_'):
                    rules[rule_name] = True
        
        # Look for regex patterns
        regex_patterns = re.findall(r'/([^/]+)/[gimsuy]*', content)
        for p in regex_patterns[:10]:
            if len(p) > 10 and any(c in p for c in ['[', '^', '$', '+']):
                rules["patterns"].append(p[:100])
        
        return rules
    
    def estimate_policy(self, url: str) -> dict:
        """Estimate password requirements for a target."""
        result = {
            "forms_found": 0,
            "password_fields": [],
            "estimated_policy": {
                "min_length": 8,  # Default assumption
                "max_length": None,
                "requires_uppercase": False,
                "requires_lowercase": False,
                "requires_number": False,
                "requires_special": False,
                "confidence": "low"
            },
            "html5_validation": [],
            "javascript_validation": {},
            "recommendations": []
        }
        
        try:
            # Find forms
            forms = self.find_forms(url)
            result["forms_found"] = len(forms.get("login_forms", [])) + len(forms.get("register_forms", []))
            result["password_fields"] = forms.get("password_fields", [])
            
            # Analyze HTML5 validation attributes
            for field in result["password_fields"]:
                if field.get("minlength"):
                    try:
                        result["estimated_policy"]["min_length"] = max(
                            result["estimated_policy"]["min_length"],
                            int(field["minlength"])
                        )
                        result["estimated_policy"]["confidence"] = "medium"
                    except ValueError:
                        pass
                
                if field.get("maxlength"):
                    try:
                        result["estimated_policy"]["max_length"] = int(field["maxlength"])
                    except ValueError:
                        pass
                
                if field.get("pattern"):
                    result["html5_validation"].append({
                        "field": field.get("name") or field.get("id"),
                        "pattern": field["pattern"]
                    })
                    
                    # Analyze pattern
                    pattern = field["pattern"]
                    if '[A-Z]' in pattern or '(?=.*[A-Z])' in pattern:
                        result["estimated_policy"]["requires_uppercase"] = True
                    if '[a-z]' in pattern or '(?=.*[a-z])' in pattern:
                        result["estimated_policy"]["requires_lowercase"] = True
                    if '\\d' in pattern or '[0-9]' in pattern:
                        result["estimated_policy"]["requires_number"] = True
                    if any(c in pattern for c in ['!', '@', '#', '$', '%', 'special']):
                        result["estimated_policy"]["requires_special"] = True
                    
                    result["estimated_policy"]["confidence"] = "high"
            
            # Analyze JavaScript validation
            resp = SESSION.get(url, timeout=DEFAULT_TIMEOUT)
            soup = BeautifulSoup(resp.text, 'html.parser')
            
            for script in soup.find_all('script', src=False):
                if script.string:
                    js_rules = self.analyze_javascript_validation(script.string)
                    if js_rules.get("min_length"):
                        result["estimated_policy"]["min_length"] = max(
                            result["estimated_policy"]["min_length"],
                            js_rules["min_length"]
                        )
                    for key in ["requires_uppercase", "requires_lowercase", "requires_number", "requires_special"]:
                        if js_rules.get(key):
                            result["estimated_policy"][key] = True
                            result["estimated_policy"]["confidence"] = "medium"
                    
                    if js_rules.get("patterns"):
                        result["javascript_validation"]["patterns"] = js_rules["patterns"]
            
            # Generate recommendations
            policy = result["estimated_policy"]
            if policy["min_length"] < 12:
                result["recommendations"].append("Consider minimum 12+ character passwords")
            if not policy["requires_uppercase"] or not policy["requires_lowercase"]:
                result["recommendations"].append("Enforce mixed case requirements")
            if not policy["requires_special"]:
                result["recommendations"].append("Consider requiring special characters")
            if not policy["max_length"] or policy["max_length"] > 128:
                result["recommendations"].append("Set reasonable max length (64-128 chars)")
            
        except Exception as e:
            result["error"] = str(e)
        
        return result


class TechnologyTimeline:
    """Track technology changes over time using Archive.org Wayback Machine."""
    
    def __init__(self):
        self.cdx_api = "http://web.archive.org/cdx/search/cdx"
        self.wayback_url = "http://web.archive.org/web"
    
    def get_snapshots(self, domain: str, count: int = 10) -> list:
        """Get historical snapshots from Wayback Machine."""
        snapshots = []
        
        try:
            params = {
                "url": domain,
                "output": "json",
                "limit": count * 3,  # Get more to filter
                "fl": "timestamp,original,statuscode",
                "filter": "statuscode:200",
                "collapse": "timestamp:6"  # One per month
            }
            
            resp = SESSION.get(self.cdx_api, params=params, timeout=15)
            if resp.ok:
                data = resp.json()
                if len(data) > 1:  # First row is header
                    for row in data[1:count+1]:
                        if len(row) >= 3:
                            snapshots.append({
                                "timestamp": row[0],
                                "url": row[1],
                                "status": row[2],
                                "date": f"{row[0][:4]}-{row[0][4:6]}-{row[0][6:8]}",
                                "wayback_url": f"{self.wayback_url}/{row[0]}/{row[1]}"
                            })
        except Exception as e:
            logger.debug(f"Wayback snapshot fetch failed: {e}")
        
        return snapshots
    
    def fingerprint_snapshot(self, wayback_url: str) -> dict:
        """Fingerprint technologies in a historical snapshot."""
        tech = {
            "server": None,
            "frameworks": [],
            "libraries": [],
            "cms": None,
            "cdn": None,
        }
        
        try:
            resp = SESSION.get(wayback_url, timeout=15, allow_redirects=True)
            if not resp.ok:
                return tech
            
            html = resp.text.lower()
            headers = {k.lower(): v for k, v in resp.headers.items()}
            
            # Server detection
            if 'x-powered-by' in headers:
                tech["server"] = headers.get('x-powered-by')
            if 'server' in headers:
                tech["server"] = headers.get('server')
            
            # Framework detection
            frameworks = {
                'react': ['react', 'reactdom', '__react'],
                'angular': ['ng-', 'angular', 'ng-app'],
                'vue': ['vue.js', 'v-if', 'v-for'],
                'jquery': ['jquery'],
                'bootstrap': ['bootstrap'],
                'tailwind': ['tailwind'],
            }
            
            for fw, patterns in frameworks.items():
                if any(p in html for p in patterns):
                    tech["frameworks"].append(fw)
            
            # CMS detection
            cms_patterns = {
                'WordPress': ['wp-content', 'wp-includes', 'wordpress'],
                'Drupal': ['drupal', 'sites/all', 'sites/default'],
                'Joomla': ['joomla', '/components/com_'],
                'Shopify': ['shopify', 'myshopify'],
                'Squarespace': ['squarespace'],
            }
            
            for cms, patterns in cms_patterns.items():
                if any(p in html for p in patterns):
                    tech["cms"] = cms
                    break
            
            # CDN detection from headers
            if 'cloudflare' in str(headers).lower():
                tech["cdn"] = "Cloudflare"
            elif 'x-amz' in str(headers).lower():
                tech["cdn"] = "CloudFront"
            elif 'akamai' in str(headers).lower():
                tech["cdn"] = "Akamai"
            
        except Exception:
            pass
        
        return tech
    
    def build_timeline(self, domain: str) -> dict:
        """Build technology evolution timeline for a domain."""
        result = {
            "domain": domain,
            "snapshots_analyzed": 0,
            "timeline": [],
            "changes": [],
            "first_seen": {},
            "no_longer_seen": {}
        }
        
        try:
            snapshots = self.get_snapshots(domain, count=10)
            result["snapshots_analyzed"] = len(snapshots)
            
            prev_tech = None
            
            for snapshot in snapshots:
                tech = self.fingerprint_snapshot(snapshot["wayback_url"])
                
                entry = {
                    "date": snapshot["date"],
                    "timestamp": snapshot["timestamp"],
                    **tech
                }
                result["timeline"].append(entry)
                
                # Detect changes
                if prev_tech:
                    # Check for new frameworks
                    new_fw = set(tech.get("frameworks", [])) - set(prev_tech.get("frameworks", []))
                    removed_fw = set(prev_tech.get("frameworks", [])) - set(tech.get("frameworks", []))
                    
                    if new_fw:
                        result["changes"].append({
                            "date": snapshot["date"],
                            "type": "added",
                            "category": "framework",
                            "items": list(new_fw)
                        })
                        for fw in new_fw:
                            if fw not in result["first_seen"]:
                                result["first_seen"][fw] = snapshot["date"]
                    
                    if removed_fw:
                        result["changes"].append({
                            "date": snapshot["date"],
                            "type": "removed",
                            "category": "framework",
                            "items": list(removed_fw)
                        })
                        for fw in removed_fw:
                            result["no_longer_seen"][fw] = snapshot["date"]
                    
                    # Check CMS changes
                    if tech.get("cms") != prev_tech.get("cms"):
                        result["changes"].append({
                            "date": snapshot["date"],
                            "type": "changed",
                            "category": "cms",
                            "from": prev_tech.get("cms"),
                            "to": tech.get("cms")
                        })
                
                prev_tech = tech
            
            result["timeline"].reverse()  # Oldest first
            result["changes"].reverse()
            
        except Exception as e:
            result["error"] = str(e)
        
        return result


class ScanDiffAnalyzer:
    """Compare scan results and highlight changes."""
    
    def compare_lists(self, current: list, previous: list) -> dict:
        """Compare two lists and find additions/removals."""
        current_set = set(current) if current else set()
        previous_set = set(previous) if previous else set()
        
        return {
            "added": list(current_set - previous_set),
            "removed": list(previous_set - current_set),
            "unchanged": list(current_set & previous_set),
            "total_current": len(current_set),
            "total_previous": len(previous_set)
        }
    
    def compare_dicts(self, current: dict, previous: dict, key: str = None) -> dict:
        """Compare two dictionaries for changes."""
        changes = {
            "added_keys": [],
            "removed_keys": [],
            "modified_keys": [],
            "unchanged_keys": []
        }
        
        current = current or {}
        previous = previous or {}
        
        all_keys = set(current.keys()) | set(previous.keys())
        
        for k in all_keys:
            if k.startswith('_'):
                continue
            
            if k in current and k not in previous:
                changes["added_keys"].append(k)
            elif k in previous and k not in current:
                changes["removed_keys"].append(k)
            elif current.get(k) != previous.get(k):
                changes["modified_keys"].append(k)
            else:
                changes["unchanged_keys"].append(k)
        
        return changes
    
    def analyze(self, current_results: dict, previous_results: dict) -> dict:
        """Comprehensive diff analysis between two scan results."""
        if not previous_results:
            return {
                "has_previous": False,
                "message": "No previous scan to compare",
                "changes": []
            }
        
        result = {
            "has_previous": True,
            "changes": [],
            "summary": {
                "total_changes": 0,
                "critical_changes": 0,
                "new_findings": 0,
                "resolved_findings": 0
            }
        }
        
        # Compare subdomains
        current_subs = []
        previous_subs = []
        
        if current_results.get("subdomain_scan", {}).get("rows"):
            current_subs = [r.get("subdomain") for r in current_results["subdomain_scan"]["rows"]]
        if previous_results.get("subdomain_scan", {}).get("rows"):
            previous_subs = [r.get("subdomain") for r in previous_results["subdomain_scan"]["rows"]]
        
        sub_diff = self.compare_lists(current_subs, previous_subs)
        if sub_diff["added"] or sub_diff["removed"]:
            result["changes"].append({
                "category": "Subdomains",
                "type": "list_change",
                "added": sub_diff["added"][:10],
                "removed": sub_diff["removed"][:10],
                "severity": "high" if sub_diff["added"] else "info"
            })
            result["summary"]["total_changes"] += len(sub_diff["added"]) + len(sub_diff["removed"])
        
        # Compare technologies
        current_tech = current_results.get("tech", {}).get("stack", [])
        previous_tech = previous_results.get("tech", {}).get("stack", [])
        
        tech_diff = self.compare_lists(current_tech, previous_tech)
        if tech_diff["added"] or tech_diff["removed"]:
            result["changes"].append({
                "category": "Technologies",
                "type": "list_change",
                "added": tech_diff["added"],
                "removed": tech_diff["removed"],
                "severity": "medium"
            })
            result["summary"]["total_changes"] += len(tech_diff["added"]) + len(tech_diff["removed"])
        
        # Compare security headers
        current_headers = {r.get("header"): r.get("status") for r in current_results.get("sec_headers", {}).get("rows", [])}
        previous_headers = {r.get("header"): r.get("status") for r in previous_results.get("sec_headers", {}).get("rows", [])}
        
        header_changes = []
        for header in set(list(current_headers.keys()) + list(previous_headers.keys())):
            curr = current_headers.get(header)
            prev = previous_headers.get(header)
            if curr != prev:
                header_changes.append({
                    "header": header,
                    "from": prev,
                    "to": curr,
                    "improved": curr == "OK" and prev != "OK"
                })
        
        if header_changes:
            improved = [h for h in header_changes if h.get("improved")]
            degraded = [h for h in header_changes if not h.get("improved")]
            
            result["changes"].append({
                "category": "Security Headers",
                "type": "status_change",
                "improved": len(improved),
                "degraded": len(degraded),
                "details": header_changes[:10],
                "severity": "high" if degraded else "info"
            })
            result["summary"]["total_changes"] += len(header_changes)
            if degraded:
                result["summary"]["critical_changes"] += len(degraded)
        
        # Compare risk scores
        current_score = current_results.get("_summary", {}).get("risk_score", 0)
        previous_score = previous_results.get("_summary", {}).get("risk_score", 0)
        
        if current_score != previous_score:
            result["changes"].append({
                "category": "Risk Score",
                "type": "score_change",
                "from": previous_score,
                "to": current_score,
                "delta": current_score - previous_score,
                "severity": "critical" if current_score > previous_score + 20 else "medium"
            })
            result["summary"]["total_changes"] += 1
            if current_score > previous_score + 20:
                result["summary"]["critical_changes"] += 1
        
        # Compare JS secrets
        current_secrets = [s.get("value") for s in current_results.get("js_secrets", {}).get("secrets_found", [])]
        previous_secrets = [s.get("value") for s in previous_results.get("js_secrets", {}).get("secrets_found", [])]
        
        secret_diff = self.compare_lists(current_secrets, previous_secrets)
        if secret_diff["added"]:
            result["changes"].append({
                "category": "Exposed Secrets",
                "type": "new_finding",
                "count": len(secret_diff["added"]),
                "severity": "critical"
            })
            result["summary"]["new_findings"] += len(secret_diff["added"])
            result["summary"]["critical_changes"] += len(secret_diff["added"])
        
        if secret_diff["removed"]:
            result["summary"]["resolved_findings"] += len(secret_diff["removed"])
        
        return result


class AttackSurfaceMapper:
    """Build visual map of attack surface."""
    
    def collect_assets(self, results: dict) -> dict:
        """Collect all discovered assets from scan results."""
        assets = {
            "domains": set(),
            "subdomains": set(),
            "ips": set(),
            "emails": set(),
            "ports": [],
            "technologies": set(),
            "endpoints": set(),
            "external_links": set()
        }
        
        # Base domain
        meta = results.get("_meta", {})
        if meta.get("base_domain"):
            assets["domains"].add(meta["base_domain"])
        
        # Subdomains and IPs
        for row in results.get("subdomain_scan", {}).get("rows", []):
            if row.get("subdomain"):
                assets["subdomains"].add(row["subdomain"])
            for ip in row.get("a_records", []):
                assets["ips"].add(ip)
        
        # Port scan results
        if results.get("port_scan", {}).get("open_ports"):
            assets["ports"] = results["port_scan"]["open_ports"]
        
        # Technologies
        if results.get("tech", {}).get("stack"):
            assets["technologies"].update(results["tech"]["stack"])
        
        # Crawler data
        crawler = results.get("crawler", {})
        if crawler.get("emails"):
            assets["emails"].update(crawler["emails"])
        if crawler.get("external_links"):
            for link in crawler["external_links"][:50]:
                assets["external_links"].add(link)
        
        # Endpoints from exposure checks
        for row in results.get("exposure_checks", {}).get("rows", []):
            if row.get("status") in [200, 301, 302]:
                assets["endpoints"].add(row.get("path", ""))
        
        return {k: list(v) if isinstance(v, set) else v for k, v in assets.items()}
    
    def build_graph(self, assets: dict, results: dict) -> dict:
        """Build graph representation of attack surface."""
        nodes = []
        edges = []
        node_ids = {}
        
        def add_node(id: str, label: str, group: str, size: int = 10, data: dict = None):
            if id not in node_ids:
                node_ids[id] = len(nodes)
                nodes.append({
                    "id": id,
                    "label": label[:30],
                    "group": group,
                    "size": size,
                    "data": data or {}
                })
            return node_ids[id]
        
        def add_edge(from_id: str, to_id: str, label: str = ""):
            edges.append({
                "from": from_id,
                "to": to_id,
                "label": label
            })
        
        # Add main domain as central node
        base_domain = results.get("_meta", {}).get("base_domain", "target")
        add_node(base_domain, base_domain, "domain", 30)
        
        # Add subdomains
        for sub in assets.get("subdomains", [])[:30]:
            add_node(sub, sub, "subdomain", 15)
            add_edge(base_domain, sub, "subdomain")
        
        # Add IPs
        for ip in assets.get("ips", [])[:20]:
            add_node(ip, ip, "ip", 12)
            # Connect IPs to subdomains
            for row in results.get("subdomain_scan", {}).get("rows", []):
                if ip in row.get("a_records", []):
                    add_edge(row.get("subdomain", ""), ip, "resolves")
        
        # Add technologies
        for tech in assets.get("technologies", [])[:15]:
            tech_id = f"tech_{tech}"
            add_node(tech_id, tech, "technology", 8)
            add_edge(base_domain, tech_id, "uses")
        
        # Add open ports
        for port_info in assets.get("ports", [])[:10]:
            port_id = f"port_{port_info['port']}"
            add_node(port_id, f"{port_info['port']}/{port_info['service']}", "port", 8)
            if assets.get("ips"):
                add_edge(assets["ips"][0], port_id, "exposes")
        
        # Add emails
        for email in assets.get("emails", [])[:10]:
            add_node(email, email, "email", 8)
            add_edge(base_domain, email, "email")
        
        return {
            "nodes": nodes,
            "edges": edges,
            "stats": {
                "total_nodes": len(nodes),
                "total_edges": len(edges),
                "groups": {
                    "domains": len([n for n in nodes if n["group"] == "domain"]),
                    "subdomains": len([n for n in nodes if n["group"] == "subdomain"]),
                    "ips": len([n for n in nodes if n["group"] == "ip"]),
                    "technologies": len([n for n in nodes if n["group"] == "technology"]),
                    "ports": len([n for n in nodes if n["group"] == "port"]),
                    "emails": len([n for n in nodes if n["group"] == "email"]),
                }
            }
        }
    
    def map_surface(self, results: dict) -> dict:
        """Generate complete attack surface map."""
        assets = self.collect_assets(results)
        graph = self.build_graph(assets, results)
        
        # Calculate attack surface score
        score = 0
        score += len(assets.get("subdomains", [])) * 2
        score += len(assets.get("ips", [])) * 5
        score += len(assets.get("ports", [])) * 10
        score += len(assets.get("endpoints", [])) * 3
        score += len(assets.get("technologies", [])) * 1
        
        return {
            "assets": assets,
            "graph": graph,
            "attack_surface_score": min(100, score),
            "summary": {
                "total_subdomains": len(assets.get("subdomains", [])),
                "total_ips": len(assets.get("ips", [])),
                "total_ports": len(assets.get("ports", [])),
                "total_technologies": len(assets.get("technologies", [])),
                "total_endpoints": len(assets.get("endpoints", [])),
                "total_emails": len(assets.get("emails", [])),
            }
        }


class ReportNarrativeGenerator:
    """Generate management-friendly report narratives."""
    
    def __init__(self):
        self.severity_descriptions = {
            "critical": "requires immediate attention and remediation",
            "high": "should be addressed as a priority",
            "medium": "warrants attention in the near term",
            "low": "can be addressed during regular maintenance",
            "info": "is informational and may not require action"
        }
        
        self.finding_explanations = {
            "missing_csp": "The website is missing Content Security Policy headers, which help prevent cross-site scripting (XSS) attacks. Think of this like leaving a door without a lock - while it might work fine normally, it's vulnerable to break-ins.",
            
            "weak_tls": "The website uses outdated encryption protocols. This is similar to using an old, easily-picked lock on your front door when stronger options are available.",
            
            "exposed_secrets": "Sensitive credentials (like passwords or API keys) were found exposed in the website's code. This is like leaving your house keys under the doormat where anyone can find them.",
            
            "cors_vulnerable": "The website allows other websites to request data from it without proper restrictions. This could allow malicious websites to steal information from your users.",
            
            "subdomain_takeover": "Some subdomains point to services that are no longer active, which could allow attackers to take control of them. It's like having an unused building on your property that squatters could occupy.",
            
            "js_secrets": "JavaScript files on the website contain what appear to be passwords, API keys, or other sensitive information that should not be publicly visible.",
            
            "missing_headers": "Several security headers that help protect against common attacks are not configured. These headers are like additional security features on a car - not strictly required, but highly recommended.",
        }
    
    def generate_severity_summary(self, results: dict) -> str:
        """Generate natural language severity summary."""
        summary = results.get("_summary", {})
        risk_level = summary.get("risk_level", "unknown")
        risk_score = summary.get("risk_score", 0)
        
        if risk_level == "critical":
            return f"The security assessment has identified **critical issues** that require immediate attention. With a risk score of {risk_score}/100, the target's security posture is significantly below acceptable levels and urgent remediation is recommended."
        elif risk_level == "high":
            return f"The assessment reveals **high-risk vulnerabilities** that should be prioritized. The risk score of {risk_score}/100 indicates substantial security gaps that could be exploited by attackers."
        elif risk_level == "medium":
            return f"Several **moderate security concerns** were identified. With a risk score of {risk_score}/100, the target has room for improvement but is not immediately at critical risk."
        else:
            return f"The security posture appears **relatively healthy** with a risk score of {risk_score}/100. Some improvements are recommended but no critical issues were detected."
    
    def explain_finding(self, finding_type: str, details: dict = None) -> str:
        """Provide non-technical explanation for a finding."""
        base = self.finding_explanations.get(finding_type, 
            "A security concern was identified that may require attention.")
        
        if details:
            if isinstance(details, dict) and details.get("count"):
                base += f" ({details['count']} instances found)"
        
        return base
    
    def generate_executive_summary(self, results: dict) -> str:
        """Generate executive summary for management."""
        summary = results.get("_summary", {})
        meta = results.get("_meta", {})
        
        url = meta.get("base_domain", "the target")
        risk_score = summary.get("risk_score", 0)
        
        # Count issues by severity
        high_count = 0
        medium_count = 0
        
        if results.get("js_secrets", {}).get("secrets_found"):
            high_count += len(results["js_secrets"]["secrets_found"])
        if results.get("subdomain_takeover", {}).get("vulnerable"):
            high_count += len(results["subdomain_takeover"]["vulnerable"])
        if results.get("cors", {}).get("vulnerable"):
            medium_count += 1
        
        missing_headers = 0
        for row in results.get("sec_headers", {}).get("rows", []):
            if row.get("status") != "OK":
                missing_headers += 1
        
        sections = [
            f"## Executive Summary\n\n",
            f"A comprehensive security assessment of **{url}** was conducted on {meta.get('scan_time', 'today')}.\n\n",
            self.generate_severity_summary(results),
            f"\n\n### Key Findings\n\n"
        ]
        
        findings = []
        if high_count > 0:
            findings.append(f"- **{high_count} high-severity issues** identified that {self.severity_descriptions['high']}")
        if medium_count > 0:
            findings.append(f"- **{medium_count} medium-severity concerns** that {self.severity_descriptions['medium']}")
        if missing_headers > 0:
            findings.append(f"- **{missing_headers} security headers** are missing or improperly configured")
        
        if not findings:
            findings.append("- No critical security issues were detected during this assessment")
        
        sections.append("\n".join(findings))
        sections.append("\n\n### Recommendations\n\n")
        
        recs = self.generate_recommendations(results)
        sections.append("\n".join([f"{i+1}. {r['recommendation']}" for i, r in enumerate(recs[:5])]))
        
        return "".join(sections)
    
    def generate_recommendations(self, results: dict) -> list:
        """Generate prioritized recommendations in plain language."""
        recommendations = []
        
        # Check for exposed secrets
        if results.get("js_secrets", {}).get("secrets_found"):
            recommendations.append({
                "priority": 1,
                "severity": "critical",
                "category": "Data Exposure",
                "recommendation": "Immediately rotate all exposed credentials and remove sensitive data from client-side code.",
                "business_impact": "Exposed credentials could lead to data breaches, unauthorized access, and regulatory penalties."
            })
        
        # Check for subdomain takeover
        if results.get("subdomain_takeover", {}).get("vulnerable"):
            recommendations.append({
                "priority": 2,
                "severity": "high",
                "category": "Infrastructure",
                "recommendation": "Review and remove unused DNS records pointing to inactive services.",
                "business_impact": "Attackers could hijack these subdomains to host malicious content under your brand."
            })
        
        # Check TLS/SSL
        if results.get("ssl_tls", {}).get("grade") in ["D", "F"]:
            recommendations.append({
                "priority": 3,
                "severity": "high",
                "category": "Encryption",
                "recommendation": "Upgrade to TLS 1.2 or 1.3 with modern cipher suites.",
                "business_impact": "Weak encryption could allow attackers to intercept sensitive data in transit."
            })
        
        # Check security headers
        missing_headers = [r for r in results.get("sec_headers", {}).get("rows", []) if r.get("status") != "OK"]
        if len(missing_headers) > 3:
            recommendations.append({
                "priority": 4,
                "severity": "medium",
                "category": "Configuration",
                "recommendation": f"Implement missing security headers: {', '.join([h['header'] for h in missing_headers[:3]])}.",
                "business_impact": "Missing headers leave the application vulnerable to common web attacks."
            })
        
        # CORS issues
        if results.get("cors", {}).get("vulnerable"):
            recommendations.append({
                "priority": 5,
                "severity": "medium",
                "category": "Access Control",
                "recommendation": "Restrict Cross-Origin Resource Sharing (CORS) to trusted domains only.",
                "business_impact": "Misconfigured CORS could allow malicious websites to steal user data."
            })
        
        return sorted(recommendations, key=lambda x: x["priority"])
    
    def generate_full_report(self, results: dict) -> dict:
        """Generate complete narrative report."""
        return {
            "executive_summary": self.generate_executive_summary(results),
            "severity_summary": self.generate_severity_summary(results),
            "recommendations": self.generate_recommendations(results),
            "format": "narrative",
            "generated_at": datetime.now().isoformat()
        }


class DeltaAlertManager:
    """Manage delta alerts for change detection."""
    
    def __init__(self):
        self.diff_analyzer = ScanDiffAnalyzer()
    
    def get_baseline(self, domain: str, db) -> dict:
        """Get baseline scan for a domain."""
        try:
            row = db.execute(
                "SELECT results FROM scans WHERE url LIKE ? ORDER BY id DESC LIMIT 1 OFFSET 1",
                (f"%{domain}%",)
            ).fetchone()
            if row:
                return json.loads(row["results"])
        except Exception:
            pass
        return None
    
    def check_for_changes(self, current_results: dict, db) -> dict:
        """Check for significant changes from baseline."""
        meta = current_results.get("_meta", {})
        domain = meta.get("base_domain", "")
        
        baseline = self.get_baseline(domain, db)
        
        if not baseline:
            return {
                "has_baseline": False,
                "message": "No baseline scan available for comparison",
                "alerts": []
            }
        
        diff = self.diff_analyzer.analyze(current_results, baseline)
        
        alerts = []
        
        for change in diff.get("changes", []):
            severity = change.get("severity", "info")
            if severity in ["critical", "high"]:
                alerts.append({
                    "type": "change_detected",
                    "category": change.get("category"),
                    "severity": severity,
                    "description": self._describe_change(change),
                    "timestamp": datetime.now().isoformat()
                })
        
        return {
            "has_baseline": True,
            "alerts": alerts,
            "total_changes": diff.get("summary", {}).get("total_changes", 0),
            "critical_changes": diff.get("summary", {}).get("critical_changes", 0),
            "diff_summary": diff.get("summary", {}),
            "changes": diff.get("changes", [])[:10]
        }
    
    def _describe_change(self, change: dict) -> str:
        """Generate human-readable description of a change."""
        category = change.get("category", "Unknown")
        change_type = change.get("type", "change")
        
        if change_type == "list_change":
            added = len(change.get("added", []))
            removed = len(change.get("removed", []))
            return f"{category}: {added} new items added, {removed} items removed"
        
        elif change_type == "score_change":
            delta = change.get("delta", 0)
            direction = "increased" if delta > 0 else "decreased"
            return f"{category} {direction} by {abs(delta)} points"
        
        elif change_type == "new_finding":
            return f"{category}: {change.get('count', 0)} new findings detected"
        
        return f"{category} has changed"


# Initialize v4.0 feature instances
entropy_scanner = EntropyScanner()
wordlist_generator = ReconWordlistGenerator()
password_detector = PasswordPolicyDetector()
tech_timeline = TechnologyTimeline()
scan_diff_analyzer = ScanDiffAnalyzer()
attack_surface_mapper = AttackSurfaceMapper()
report_narrative_gen = ReportNarrativeGenerator()
delta_alert_manager = DeltaAlertManager()


# ============================================================================
# AEGIS v5.0 - ADVANCED FEATURES (23 Modules - 100% Local, No API Required)
# ============================================================================

class CryptoAddressScanner:
    """Scan for exposed cryptocurrency wallet addresses."""
    
    PATTERNS = {
        "bitcoin": r'\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b',
        "bitcoin_bech32": r'\bbc1[a-z0-9]{39,59}\b',
        "ethereum": r'\b0x[a-fA-F0-9]{40}\b',
        "monero": r'\b4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}\b',
        "litecoin": r'\b[LM][a-km-zA-HJ-NP-Z1-9]{26,33}\b',
        "dogecoin": r'\bD[5-9A-HJ-NP-U][1-9A-HJ-NP-Za-km-z]{32}\b',
        "ripple": r'\br[0-9a-zA-Z]{24,34}\b',
        "solana": r'\b[1-9A-HJ-NP-Za-km-z]{32,44}\b',
    }
    
    def scan(self, content: str, urls: list = None) -> dict:
        """Scan content for cryptocurrency addresses."""
        findings = []
        seen = set()
        
        for crypto_type, pattern in self.PATTERNS.items():
            matches = re.findall(pattern, content)
            for match in matches:
                if match not in seen and len(match) > 20:
                    seen.add(match)
                    findings.append({
                        "type": crypto_type,
                        "address": match,
                        "risk": "high" if crypto_type in ["bitcoin", "ethereum"] else "medium"
                    })
        
        return {
            "total_found": len(findings),
            "addresses": findings[:50],
            "types_detected": list(set(f["type"] for f in findings))
        }


class MediaAssetScanner:
    """Find audio, video, and document files on target."""
    
    EXTENSIONS = {
        "video": [".mp4", ".webm", ".avi", ".mov", ".mkv", ".flv", ".wmv"],
        "audio": [".mp3", ".wav", ".ogg", ".flac", ".aac", ".m4a"],
        "document": [".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx"],
        "archive": [".zip", ".rar", ".7z", ".tar", ".gz"],
        "image": [".jpg", ".jpeg", ".png", ".gif", ".webp", ".svg", ".ico"]
    }
    
    def scan(self, html_content: str, base_url: str) -> dict:
        """Extract media asset URLs from HTML."""
        assets = {"video": [], "audio": [], "document": [], "archive": [], "image": []}
        seen = set()
        
        url_pattern = r'(?:href|src|data-src|poster)=["\']([^"\']+)["\']'
        matches = re.findall(url_pattern, html_content, re.I)
        
        for url in matches:
            if url in seen:
                continue
            seen.add(url)
            
            lower_url = url.lower()
            for asset_type, exts in self.EXTENSIONS.items():
                if any(lower_url.endswith(ext) for ext in exts):
                    full_url = urljoin(base_url, url) if not url.startswith("http") else url
                    assets[asset_type].append(full_url)
                    break
        
        return {
            "total_assets": sum(len(v) for v in assets.values()),
            "assets": {k: v[:20] for k, v in assets.items()},
            "summary": {k: len(v) for k, v in assets.items()}
        }


class MobileAppDetector:
    """Detect mobile app presence and deep links."""
    
    def scan(self, html_content: str, headers: dict = None) -> dict:
        """Detect mobile app indicators."""
        results = {"ios": {}, "android": {}, "deep_links": [], "smart_banners": False}
        
        # iOS App Store
        ios_match = re.search(r'apps\.apple\.com/[^/]+/app/[^/]+/id(\d+)', html_content)
        if ios_match:
            results["ios"]["app_id"] = ios_match.group(1)
            results["ios"]["store_url"] = ios_match.group(0)
        
        # Android Play Store
        android_match = re.search(r'play\.google\.com/store/apps/details\?id=([a-zA-Z0-9_.]+)', html_content)
        if android_match:
            results["android"]["package"] = android_match.group(1)
            results["android"]["store_url"] = android_match.group(0)
        
        # Smart App Banners
        if 'apple-itunes-app' in html_content or 'smart-app-banner' in html_content.lower():
            results["smart_banners"] = True
        
        # Deep Links / Universal Links
        deep_patterns = [
            r'apple-app-site-association',
            r'\.well-known/assetlinks\.json',
            r'intent://[^"\'<>\s]+',
            r'[a-z]+://[^"\'<>\s]+(?:open|launch|app)'
        ]
        for pattern in deep_patterns:
            matches = re.findall(pattern, html_content, re.I)
            results["deep_links"].extend(matches[:10])
        
        results["has_mobile_app"] = bool(results["ios"] or results["android"])
        return results


class EmailTemplateHarvester:
    """Extract email-related templates and patterns."""
    
    def scan(self, html_content: str, base_url: str) -> dict:
        """Find email templates and subscription forms."""
        results = {
            "newsletter_forms": [],
            "email_patterns": [],
            "unsubscribe_links": [],
            "email_services": []
        }
        
        # Newsletter/subscription forms
        form_patterns = [
            r'<form[^>]*(?:newsletter|subscribe|signup|email)[^>]*>.*?</form>',
            r'<input[^>]*(?:newsletter|subscribe)[^>]*>'
        ]
        for pattern in form_patterns:
            matches = re.findall(pattern, html_content, re.I | re.S)
            results["newsletter_forms"].extend(matches[:5])
        
        # Email service providers
        services = {
            "mailchimp": r'mailchimp|mc_embed|list-manage\.com',
            "sendgrid": r'sendgrid',
            "mailgun": r'mailgun',
            "constant_contact": r'constantcontact',
            "hubspot": r'hubspot|hs-scripts',
            "klaviyo": r'klaviyo',
            "convertkit": r'convertkit'
        }
        for service, pattern in services.items():
            if re.search(pattern, html_content, re.I):
                results["email_services"].append(service)
        
        # Unsubscribe links
        unsub = re.findall(r'href=["\']([^"\']*unsubscribe[^"\']*)["\']', html_content, re.I)
        results["unsubscribe_links"] = unsub[:10]
        
        return results


class PrivacyLeakDetector:
    """Find tracking pixels, analytics, and fingerprinting scripts."""
    
    TRACKERS = {
        "google_analytics": r'google-analytics\.com|gtag|ga\(|_gaq',
        "facebook_pixel": r'facebook\.com/tr|fbq\(|connect\.facebook\.net',
        "hotjar": r'hotjar\.com|hjSetting',
        "mixpanel": r'mixpanel\.com|mixpanel\.track',
        "segment": r'segment\.com|analytics\.js',
        "heap": r'heap\.io|heapanalytics',
        "amplitude": r'amplitude\.com',
        "fullstory": r'fullstory\.com|FS\.identify',
        "mouseflow": r'mouseflow\.com',
        "clarity": r'clarity\.ms',
        "tiktok_pixel": r'analytics\.tiktok\.com',
        "linkedin_insight": r'snap\.licdn\.com|linkedin\.com/px',
    }
    
    FINGERPRINTING = [
        r'fingerprint2?\.js', r'clientjs', r'canvas.*toDataURL',
        r'webgl.*getParameter', r'AudioContext', r'navigator\.plugins',
        r'screen\.(width|height|colorDepth)', r'timezone.*offset'
    ]
    
    def scan(self, html_content: str, js_content: str = "") -> dict:
        """Detect privacy-invasive tracking and fingerprinting."""
        combined = html_content + js_content
        
        trackers_found = []
        for name, pattern in self.TRACKERS.items():
            if re.search(pattern, combined, re.I):
                trackers_found.append(name)
        
        fingerprinting = []
        for pattern in self.FINGERPRINTING:
            if re.search(pattern, combined, re.I):
                fingerprinting.append(pattern)
        
        # Third-party cookies indicators
        cookie_domains = re.findall(r'\.set(?:Cookie|Item)\s*\([^)]+\)', combined)
        
        return {
            "trackers": trackers_found,
            "fingerprinting_signals": len(fingerprinting),
            "fingerprinting_techniques": fingerprinting[:10],
            "cookie_operations": len(cookie_domains),
            "privacy_score": max(0, 100 - len(trackers_found) * 10 - len(fingerprinting) * 5),
            "risk_level": "high" if len(trackers_found) > 5 else "medium" if len(trackers_found) > 2 else "low"
        }


class DatabaseLeakDetector:
    """Detect database information in error messages and responses."""
    
    PATTERNS = {
        "mysql_error": r'(mysql_fetch|mysql_query|mysqli_|SQLSTATE\[)',
        "postgresql_error": r'(pg_query|PG::|PostgreSQL)',
        "mongodb_error": r'(MongoError|MongoDB|ObjectId\()',
        "sqlite_error": r'(sqlite3\.|SQLite3::)',
        "oracle_error": r'(ORA-\d+|Oracle error)',
        "mssql_error": r'(ODBC SQL Server|Microsoft SQL)',
        "table_names": r'(?:FROM|INTO|UPDATE|TABLE)\s+[`"\[]?(\w+)[`"\]]?',
        "column_names": r'(?:column|field)\s+[\'"`](\w+)[\'"`]',
        "connection_strings": r'(?:host|server|database|user|password)\s*[=:]\s*[\'"]?(\w+)',
    }
    
    def scan(self, content: str, error_pages: list = None) -> dict:
        """Detect database leaks in content."""
        leaks = []
        
        for leak_type, pattern in self.PATTERNS.items():
            matches = re.findall(pattern, content, re.I)
            if matches:
                leaks.append({
                    "type": leak_type,
                    "matches": list(set(matches))[:10],
                    "severity": "high" if "error" in leak_type or "connection" in leak_type else "medium"
                })
        
        return {
            "leaks_found": len(leaks),
            "details": leaks,
            "database_types": [l["type"].split("_")[0] for l in leaks if "error" in l["type"]],
            "risk_level": "critical" if any(l["severity"] == "high" for l in leaks) else "low"
        }


class JSDeobfuscationAnalyzer:
    """Analyze JavaScript for obfuscation patterns indicating malicious code."""
    
    OBFUSCATION_PATTERNS = {
        "eval_usage": r'\beval\s*\(',
        "base64_decode": r'atob\s*\(|btoa\s*\(',
        "char_code": r'fromCharCode\s*\(',
        "hex_encoding": r'\\x[0-9a-f]{2}',
        "unicode_escape": r'\\u[0-9a-f]{4}',
        "packed_code": r'eval\s*\(\s*function\s*\(\s*p\s*,\s*a\s*,\s*c\s*,\s*k',
        "obfuscator_io": r'_0x[a-f0-9]{4,}',
        "jsfuck": r'\[\s*!\s*\+\s*\[\s*\]\s*\]',
        "array_rotation": r'\.push\s*\(\s*\w+\s*\.\s*shift\s*\(\s*\)\s*\)',
        "string_split": r'\.split\s*\(\s*[\'"][^\'"]+[\'"]\s*\)\s*\.reverse',
    }
    
    def analyze(self, js_content: str) -> dict:
        """Analyze JavaScript for obfuscation indicators."""
        findings = []
        obfuscation_score = 0
        
        for name, pattern in self.OBFUSCATION_PATTERNS.items():
            matches = re.findall(pattern, js_content, re.I)
            if matches:
                findings.append({
                    "technique": name,
                    "occurrences": len(matches),
                    "risk": "high" if name in ["eval_usage", "packed_code", "jsfuck"] else "medium"
                })
                obfuscation_score += len(matches) * (3 if "high" in str(findings[-1]) else 1)
        
        # Check entropy of variable names
        var_names = re.findall(r'\b(?:var|let|const)\s+(\w+)', js_content)
        short_vars = sum(1 for v in var_names if len(v) <= 2 or re.match(r'^_0x|^[a-z]{1,2}\d', v))
        
        return {
            "obfuscation_detected": obfuscation_score > 5,
            "score": min(100, obfuscation_score),
            "techniques": findings,
            "suspicious_variables": short_vars,
            "risk_level": "critical" if obfuscation_score > 20 else "high" if obfuscation_score > 10 else "low"
        }


class BrandAssetExtractor:
    """Extract branding elements: logos, colors, fonts."""
    
    def extract(self, html_content: str, css_content: str = "") -> dict:
        """Extract brand assets from content."""
        # Logo detection
        logos = re.findall(r'(?:src|href)=["\']([^"\']*(?:logo|brand|icon)[^"\']*)["\']', html_content, re.I)
        
        # Favicon
        favicons = re.findall(r'<link[^>]*rel=["\'](?:icon|shortcut icon)["\'][^>]*href=["\']([^"\']+)["\']', html_content, re.I)
        
        # Colors from CSS
        colors = list(set(re.findall(r'#[0-9a-fA-F]{3,6}\b', css_content + html_content)))
        rgb_colors = re.findall(r'rgba?\s*\([^)]+\)', css_content + html_content)
        
        # Fonts
        fonts = re.findall(r'font-family:\s*([^;}{]+)', css_content + html_content)
        google_fonts = re.findall(r'fonts\.googleapis\.com/css[^"\']+family=([^&"\']+)', html_content)
        
        # Brand name from title/meta
        title_match = re.search(r'<title>([^<]+)</title>', html_content, re.I)
        og_site = re.search(r'og:site_name["\'\s]+content=["\']([^"\']+)', html_content, re.I)
        
        return {
            "logos": logos[:10],
            "favicons": favicons[:5],
            "colors": colors[:20],
            "fonts": list(set(fonts))[:10],
            "google_fonts": google_fonts,
            "brand_name": og_site.group(1) if og_site else (title_match.group(1) if title_match else None),
            "asset_count": len(logos) + len(favicons)
        }


class HomoglyphScanner:
    """Detect typosquatting domains using Unicode homoglyphs."""
    
    HOMOGLYPHS = {
        'a': ['а', 'ɑ', 'α', '@'],
        'e': ['е', 'ё', 'ε', '3'],
        'o': ['о', '0', 'ο', 'ө'],
        'i': ['і', '1', 'l', '|', 'ı'],
        'c': ['с', 'ç', '¢'],
        's': ['ѕ', '$', '5'],
        'p': ['р', 'ρ'],
        'x': ['х', '×'],
        'y': ['у', 'ý'],
        'n': ['п', 'η'],
        'k': ['к', 'κ'],
        'h': ['һ', 'н'],
        'g': ['ɡ', '9'],
        'b': ['Ь', '6'],
        'd': ['ԁ', 'ɗ'],
        'w': ['ω', 'ш'],
        'm': ['м', 'rn'],
        't': ['т', '+'],
    }
    
    def scan(self, domain: str) -> dict:
        """Generate potential typosquatting variants."""
        base = domain.split('.')[0].lower()
        variants = []
        
        # Homoglyph substitution
        for i, char in enumerate(base):
            if char in self.HOMOGLYPHS:
                for replacement in self.HOMOGLYPHS[char]:
                    variant = base[:i] + replacement + base[i+1:]
                    variants.append({"type": "homoglyph", "variant": variant, "original_char": char})
        
        # Common typos
        typos = [
            base.replace('www', 'ww'), base.replace('www', 'wwww'),
            base + 's', base[:-1] if len(base) > 3 else base,
            base[:len(base)//2] + base[len(base)//2] + base[len(base)//2:],  # double letter
        ]
        for typo in typos:
            if typo != base:
                variants.append({"type": "typo", "variant": typo})
        
        # TLD swaps
        tld_variants = [f"{base}.co", f"{base}.net", f"{base}.org", f"{base}.io", f"{base}.app"]
        
        return {
            "original": domain,
            "homoglyph_variants": [v for v in variants if v["type"] == "homoglyph"][:20],
            "typo_variants": [v for v in variants if v["type"] == "typo"][:10],
            "tld_variants": tld_variants,
            "total_variants": len(variants) + len(tld_variants)
        }


class GhostAssetFinder:
    """Find hidden pages not in robots.txt or sitemap."""
    
    COMMON_HIDDEN = [
        "/admin", "/administrator", "/wp-admin", "/login", "/signin",
        "/dashboard", "/panel", "/console", "/manager", "/cpanel",
        "/phpmyadmin", "/adminer", "/.git", "/.svn", "/.env",
        "/api", "/api/v1", "/api/v2", "/graphql", "/rest",
        "/backup", "/old", "/new", "/test", "/dev", "/staging",
        "/debug", "/trace", "/status", "/health", "/metrics",
        "/config", "/settings", "/setup", "/install", "/upgrade",
        "/.well-known", "/robots.txt", "/sitemap.xml", "/humans.txt"
    ]
    
    def scan(self, base_url: str, session=None) -> dict:
        """Find hidden/ghost assets."""
        found = []
        checked = 0
        
        if not session:
            session = requests.Session()
            session.headers.update({"User-Agent": "Mozilla/5.0 AEGIS Scanner"})
        
        for path in self.COMMON_HIDDEN:
            try:
                url = urljoin(base_url, path)
                resp = session.head(url, timeout=3, allow_redirects=False)
                checked += 1
                
                if resp.status_code in [200, 301, 302, 401, 403]:
                    found.append({
                        "path": path,
                        "status": resp.status_code,
                        "accessible": resp.status_code == 200,
                        "protected": resp.status_code in [401, 403]
                    })
            except:
                pass
        
        return {
            "paths_checked": checked,
            "paths_found": len(found),
            "accessible": [p for p in found if p["accessible"]],
            "protected": [p for p in found if p["protected"]],
            "all_findings": found
        }


class HoneypotDetector:
    """Detect decoy/honeypot systems."""
    
    HONEYPOT_INDICATORS = {
        "kippo": ["cowrie", "kippo", "SSH-2.0-OpenSSH_5.1p1"],
        "glastopf": ["glastopf", "phpMyAdmin 2.6.4"],
        "dionaea": ["dionaea", "Microsoft-IIS/5.0"],
        "conpot": ["conpot", "Siemens"],
        "elastichoney": ["elastichoney", "elasticsearch"],
        "generic": ["honeypot", "tarpit", "decoy", "canary"]
    }
    
    def detect(self, headers: dict, content: str, banner: str = "") -> dict:
        """Detect honeypot indicators."""
        findings = []
        combined = str(headers) + content + banner
        
        for honey_type, patterns in self.HONEYPOT_INDICATORS.items():
            for pattern in patterns:
                if pattern.lower() in combined.lower():
                    findings.append({
                        "type": honey_type,
                        "indicator": pattern,
                        "confidence": "high" if honey_type != "generic" else "medium"
                    })
        
        # Behavioral checks
        behavioral = []
        if headers.get("Server", "").count("/") > 3:
            behavioral.append("Unusually detailed server header")
        if "X-Powered-By" in headers and "honeypot" in str(headers.get("X-Powered-By", "")).lower():
            behavioral.append("Honeypot signature in headers")
        
        return {
            "is_honeypot": len(findings) > 0,
            "confidence": "high" if len(findings) > 2 else "medium" if findings else "low",
            "indicators": findings,
            "behavioral_signals": behavioral
        }


class GeoBlockDetector:
    """Detect geographic blocking and CDN behavior."""
    
    def detect(self, headers: dict, response_code: int, content: str = "") -> dict:
        """Detect geo-blocking indicators."""
        indicators = []
        
        # CDN detection
        cdn_headers = {
            "cloudflare": ["cf-ray", "cf-cache-status"],
            "akamai": ["x-akamai-transformed", "akamai-origin-hop"],
            "fastly": ["x-served-by", "x-cache"],
            "aws_cloudfront": ["x-amz-cf-id", "x-amz-cf-pop"],
            "azure_cdn": ["x-azure-ref"],
        }
        
        detected_cdn = None
        for cdn, cdn_hdrs in cdn_headers.items():
            if any(h.lower() in [k.lower() for k in headers.keys()] for h in cdn_hdrs):
                detected_cdn = cdn
                break
        
        # Geo-block indicators
        geo_patterns = [
            r'not available in your (?:country|region)',
            r'access denied.*(?:location|geographic)',
            r'blocked.*(?:country|territory)',
            r'451.*unavailable.*legal',
            r'geoblocking|geoblock|geo-restrict'
        ]
        
        geo_blocked = False
        for pattern in geo_patterns:
            if re.search(pattern, content, re.I):
                geo_blocked = True
                indicators.append(f"Pattern match: {pattern}")
        
        if response_code == 451:
            geo_blocked = True
            indicators.append("HTTP 451 Unavailable For Legal Reasons")
        
        return {
            "geo_blocked": geo_blocked,
            "cdn_detected": detected_cdn,
            "indicators": indicators,
            "response_code": response_code
        }


class WebsiteDNAGenerator:
    """Generate unique fingerprint for website identification."""
    
    def generate(self, html: str, headers: dict, tech_stack: list = None) -> dict:
        """Generate website DNA fingerprint."""
        # HTML structure fingerprint
        tag_counts = {}
        for tag in re.findall(r'<(\w+)', html):
            tag_counts[tag.lower()] = tag_counts.get(tag.lower(), 0) + 1
        
        # Header fingerprint
        header_sig = sorted([k.lower() for k in headers.keys()])
        
        # Generate hash
        dna_string = f"{sorted(tag_counts.items())}{header_sig}{tech_stack or []}"
        dna_hash = hashlib.sha256(dna_string.encode()).hexdigest()[:32]
        
        # Structural analysis
        structure = {
            "total_tags": sum(tag_counts.values()),
            "unique_tags": len(tag_counts),
            "top_tags": sorted(tag_counts.items(), key=lambda x: -x[1])[:10],
            "has_forms": tag_counts.get("form", 0) > 0,
            "has_scripts": tag_counts.get("script", 0) > 0,
            "script_count": tag_counts.get("script", 0),
        }
        
        return {
            "dna_hash": dna_hash,
            "structure": structure,
            "header_signature": header_sig[:15],
            "tech_signature": tech_stack[:10] if tech_stack else []
        }


class ComplianceChecker:
    """Quick GDPR, CCPA, PCI-DSS compliance audit."""
    
    CHECKS = {
        "gdpr": {
            "cookie_consent": r'cookie.*(?:consent|notice|banner|policy)',
            "privacy_policy": r'privacy.*policy|datenschutz',
            "data_subject_rights": r'(?:access|delete|port).*(?:data|rights)',
            "dpo_contact": r'data.*protection.*officer|dpo@',
        },
        "ccpa": {
            "do_not_sell": r'do.*not.*sell.*(?:personal|information)',
            "ca_privacy": r'california.*privacy|ccpa',
            "opt_out": r'opt.*out.*(?:sale|sharing)',
        },
        "pci_dss": {
            "secure_payment": r'(?:secure|encrypted).*payment',
            "https": r'^https://',
            "card_logos": r'visa|mastercard|amex|discover',
        }
    }
    
    def audit(self, html: str, url: str, headers: dict) -> dict:
        """Perform compliance audit."""
        results = {}
        
        for standard, checks in self.CHECKS.items():
            passed = 0
            details = []
            for check_name, pattern in checks.items():
                found = bool(re.search(pattern, html + url, re.I))
                details.append({"check": check_name, "passed": found})
                if found:
                    passed += 1
            
            results[standard] = {
                "score": int((passed / len(checks)) * 100),
                "checks_passed": passed,
                "total_checks": len(checks),
                "details": details
            }
        
        # Security headers check
        security_headers = ["strict-transport-security", "content-security-policy", "x-frame-options"]
        security_score = sum(1 for h in security_headers if h in [k.lower() for k in headers.keys()])
        
        return {
            "compliance": results,
            "security_headers_score": int((security_score / len(security_headers)) * 100),
            "overall_score": sum(r["score"] for r in results.values()) // len(results)
        }


class TimingAnalyzer:
    """Analyze response timing patterns for fingerprinting."""
    
    def analyze(self, url: str, samples: int = 5) -> dict:
        """Measure response timing patterns."""
        timings = []
        
        for _ in range(samples):
            try:
                start = time.time()
                resp = requests.head(url, timeout=10)
                elapsed = (time.time() - start) * 1000  # ms
                timings.append({
                    "latency_ms": round(elapsed, 2),
                    "status": resp.status_code
                })
            except:
                pass
        
        if not timings:
            return {"error": "No successful samples"}
        
        latencies = [t["latency_ms"] for t in timings]
        
        return {
            "samples": len(timings),
            "min_ms": min(latencies),
            "max_ms": max(latencies),
            "avg_ms": round(sum(latencies) / len(latencies), 2),
            "variance": round(max(latencies) - min(latencies), 2),
            "consistent": (max(latencies) - min(latencies)) < 100,
            "timings": timings
        }


class APIEndpointFuzzer:
    """Discover API endpoints from JavaScript analysis."""
    
    PATTERNS = [
        r'["\']/(api|rest|graphql|v[0-9]+)/[^"\']+["\']',
        r'fetch\s*\(\s*["\']([^"\']+)["\']',
        r'axios\.[a-z]+\s*\(\s*["\']([^"\']+)["\']',
        r'\.ajax\s*\(\s*{\s*url\s*:\s*["\']([^"\']+)["\']',
        r'endpoint[s]?\s*[=:]\s*["\']([^"\']+)["\']',
    ]
    
    def discover(self, js_content: str, base_url: str) -> dict:
        """Discover API endpoints from JS code."""
        endpoints = set()
        
        for pattern in self.PATTERNS:
            matches = re.findall(pattern, js_content, re.I)
            for match in matches:
                if isinstance(match, tuple):
                    match = match[0]
                if match.startswith('/') or match.startswith('http'):
                    endpoints.add(match)
        
        # Categorize
        categorized = {"rest": [], "graphql": [], "websocket": [], "other": []}
        for ep in endpoints:
            if "graphql" in ep.lower():
                categorized["graphql"].append(ep)
            elif "ws://" in ep or "wss://" in ep:
                categorized["websocket"].append(ep)
            elif "/api" in ep or "/v1" in ep or "/v2" in ep:
                categorized["rest"].append(ep)
            else:
                categorized["other"].append(ep)
        
        return {
            "total_found": len(endpoints),
            "endpoints": list(endpoints)[:50],
            "categorized": categorized
        }


class LinkGraphBuilder:
    """Build network graph of all internal and external links."""
    
    def build(self, html: str, base_url: str) -> dict:
        """Build link graph from HTML."""
        internal = set()
        external = set()
        parsed_base = urlparse(base_url)
        
        links = re.findall(r'href=["\']([^"\'#]+)["\']', html, re.I)
        
        for link in links:
            if link.startswith("javascript:") or link.startswith("mailto:"):
                continue
            
            full_url = urljoin(base_url, link)
            parsed = urlparse(full_url)
            
            if parsed.netloc == parsed_base.netloc:
                internal.add(parsed.path or "/")
            elif parsed.netloc:
                external.add(parsed.netloc)
        
        return {
            "internal_links": list(internal)[:100],
            "external_domains": list(external)[:50],
            "internal_count": len(internal),
            "external_count": len(external),
            "link_ratio": round(len(external) / max(len(internal), 1), 2)
        }


class SubdomainClusterer:
    """Cluster subdomains by similarity and purpose."""
    
    CATEGORIES = {
        "mail": ["mail", "smtp", "imap", "pop", "mx", "email"],
        "api": ["api", "rest", "graphql", "gateway", "ws"],
        "dev": ["dev", "staging", "test", "qa", "uat", "sandbox"],
        "cdn": ["cdn", "static", "assets", "media", "img", "images"],
        "admin": ["admin", "panel", "dashboard", "manage", "cms"],
        "auth": ["auth", "login", "sso", "oauth", "id", "identity"],
        "docs": ["docs", "help", "support", "wiki", "kb"],
        "shop": ["shop", "store", "cart", "checkout", "pay"],
    }
    
    def cluster(self, subdomains: list) -> dict:
        """Cluster subdomains by purpose."""
        clusters = {cat: [] for cat in self.CATEGORIES}
        clusters["other"] = []
        
        for sub in subdomains:
            categorized = False
            sub_lower = sub.lower()
            for category, keywords in self.CATEGORIES.items():
                if any(kw in sub_lower for kw in keywords):
                    clusters[category].append(sub)
                    categorized = True
                    break
            if not categorized:
                clusters["other"].append(sub)
        
        return {
            "clusters": {k: v for k, v in clusters.items() if v},
            "summary": {k: len(v) for k, v in clusters.items() if v},
            "total": len(subdomains)
        }


class WebsiteValueEstimator:
    """Estimate website metrics and value indicators."""
    
    def estimate(self, html: str, headers: dict, tech_stack: list = None) -> dict:
        """Estimate website value indicators."""
        indicators = {}
        
        # Content richness
        word_count = len(re.findall(r'\b\w+\b', re.sub(r'<[^>]+>', '', html)))
        indicators["content_words"] = word_count
        
        # Interactivity
        form_count = len(re.findall(r'<form', html, re.I))
        script_count = len(re.findall(r'<script', html, re.I))
        indicators["forms"] = form_count
        indicators["scripts"] = script_count
        
        # Social presence
        social = ["facebook", "twitter", "linkedin", "instagram", "youtube", "tiktok"]
        social_found = [s for s in social if s in html.lower()]
        indicators["social_links"] = social_found
        
        # Tech sophistication
        modern_tech = ["react", "vue", "angular", "next", "nuxt", "svelte"]
        tech_score = sum(1 for t in modern_tech if t in str(tech_stack).lower()) if tech_stack else 0
        indicators["tech_score"] = tech_score
        
        # Estimate complexity score
        complexity = min(100, (word_count // 100) + (form_count * 5) + (script_count * 2) + (tech_score * 10))
        
        return {
            "indicators": indicators,
            "complexity_score": complexity,
            "category": "enterprise" if complexity > 70 else "business" if complexity > 40 else "basic"
        }


class VulnerabilityPredictor:
    """Predict potential vulnerabilities from tech stack."""
    
    KNOWN_ISSUES = {
        "wordpress": ["CVE plugin vulns", "XML-RPC attacks", "user enumeration"],
        "drupal": ["Drupalgeddon variants", "serialization issues"],
        "joomla": ["SQL injection history", "component vulnerabilities"],
        "php": ["type juggling", "deserialization", "file inclusion"],
        "apache": ["path traversal", "mod_cgi issues"],
        "nginx": ["misconfig issues", "buffer overflow history"],
        "jquery": ["XSS in older versions", "prototype pollution"],
        "react": ["SSR XSS", "dangerouslySetInnerHTML misuse"],
    }
    
    def predict(self, tech_stack: list) -> dict:
        """Predict vulnerabilities based on tech stack."""
        predictions = []
        
        for tech in tech_stack:
            tech_lower = tech.lower().split()[0]
            if tech_lower in self.KNOWN_ISSUES:
                predictions.append({
                    "technology": tech,
                    "potential_issues": self.KNOWN_ISSUES[tech_lower],
                    "recommendation": f"Keep {tech} updated and review security advisories"
                })
        
        return {
            "predictions": predictions,
            "risk_technologies": len(predictions),
            "recommendation": "Regular security audits recommended" if predictions else "No high-risk technologies detected"
        }


class CookieConsentAnalyzer:
    """Analyze cookie consent banners and compliance."""
    
    def analyze(self, html: str) -> dict:
        """Analyze cookie consent implementation."""
        indicators = {
            "has_banner": False,
            "consent_types": [],
            "reject_option": False,
            "granular_control": False,
            "consent_managers": []
        }
        
        # Popular consent managers
        managers = {
            "cookiebot": r'cookiebot|consentmanager',
            "onetrust": r'onetrust|optanon',
            "trustarc": r'trustarc|consent\.trustarc',
            "quantcast": r'quantcast.*choice',
            "usercentrics": r'usercentrics',
            "iubenda": r'iubenda',
        }
        
        for name, pattern in managers.items():
            if re.search(pattern, html, re.I):
                indicators["consent_managers"].append(name)
                indicators["has_banner"] = True
        
        # Check for reject option
        if re.search(r'reject.*(?:all|cookies)|decline|ablehnen', html, re.I):
            indicators["reject_option"] = True
        
        # Check granular control
        if re.search(r'(?:necessary|functional|analytics|marketing).*(?:cookie|consent)', html, re.I):
            indicators["granular_control"] = True
        
        # Compliance score
        score = 0
        if indicators["has_banner"]: score += 30
        if indicators["reject_option"]: score += 30
        if indicators["granular_control"]: score += 40
        
        indicators["compliance_score"] = score
        
        return indicators


# Initialize v5.0 feature instances
crypto_scanner = CryptoAddressScanner()
media_scanner = MediaAssetScanner()
mobile_detector = MobileAppDetector()
email_harvester = EmailTemplateHarvester()
privacy_detector = PrivacyLeakDetector()
db_leak_detector = DatabaseLeakDetector()
js_deobfuscation = JSDeobfuscationAnalyzer()
brand_extractor = BrandAssetExtractor()
homoglyph_scanner = HomoglyphScanner()
ghost_finder = GhostAssetFinder()
honeypot_detector = HoneypotDetector()
geo_block_detector = GeoBlockDetector()
website_dna = WebsiteDNAGenerator()
compliance_checker = ComplianceChecker()
timing_analyzer = TimingAnalyzer()
api_fuzzer = APIEndpointFuzzer()
link_graph = LinkGraphBuilder()
subdomain_clusterer = SubdomainClusterer()
value_estimator = WebsiteValueEstimator()
vuln_predictor = VulnerabilityPredictor()
cookie_analyzer = CookieConsentAnalyzer()


# ============================================================================
# AEGIS v6.0 - SOCMINT & RANSOMWARE INTELLIGENCE
# ============================================================================

class SocialMediaIntel:
    """Find social media presence across 50+ platforms worldwide."""
    
    # Platform URL patterns - {username} will be replaced
    PLATFORMS = {
        # Major Global
        "twitter": {"url": "https://twitter.com/{q}", "icon": "fa-twitter"},
        "facebook": {"url": "https://facebook.com/{q}", "icon": "fa-facebook"},
        "instagram": {"url": "https://instagram.com/{q}", "icon": "fa-instagram"},
        "linkedin": {"url": "https://linkedin.com/company/{q}", "icon": "fa-linkedin"},
        "youtube": {"url": "https://youtube.com/@{q}", "icon": "fa-youtube"},
        "tiktok": {"url": "https://tiktok.com/@{q}", "icon": "fa-tiktok"},
        "pinterest": {"url": "https://pinterest.com/{q}", "icon": "fa-pinterest"},
        "reddit": {"url": "https://reddit.com/user/{q}", "icon": "fa-reddit"},
        "tumblr": {"url": "https://{q}.tumblr.com", "icon": "fa-tumblr"},
        
        # Developer/Tech
        "github": {"url": "https://github.com/{q}", "icon": "fa-github"},
        "gitlab": {"url": "https://gitlab.com/{q}", "icon": "fa-gitlab"},
        "bitbucket": {"url": "https://bitbucket.org/{q}", "icon": "fa-bitbucket"},
        "stackoverflow": {"url": "https://stackoverflow.com/users/{q}", "icon": "fa-stack-overflow"},
        "hackernews": {"url": "https://news.ycombinator.com/user?id={q}", "icon": "fa-y-combinator"},
        "dev_to": {"url": "https://dev.to/{q}", "icon": "fa-dev"},
        "medium": {"url": "https://medium.com/@{q}", "icon": "fa-medium"},
        "hashnode": {"url": "https://hashnode.com/@{q}", "icon": "fa-h"},
        "codepen": {"url": "https://codepen.io/{q}", "icon": "fa-codepen"},
        "dribbble": {"url": "https://dribbble.com/{q}", "icon": "fa-dribbble"},
        "behance": {"url": "https://behance.net/{q}", "icon": "fa-behance"},
        
        # Messaging/Community
        "telegram": {"url": "https://t.me/{q}", "icon": "fa-telegram"},
        "discord": {"url": "https://discord.com/users/{q}", "icon": "fa-discord"},
        "slack": {"url": "https://{q}.slack.com", "icon": "fa-slack"},
        "twitch": {"url": "https://twitch.tv/{q}", "icon": "fa-twitch"},
        
        # Regional Platforms
        "vk": {"url": "https://vk.com/{q}", "icon": "fa-vk"},
        "weibo": {"url": "https://weibo.com/{q}", "icon": "fa-weibo"},
        "qq": {"url": "https://user.qzone.qq.com/{q}", "icon": "fa-qq"},
        "line": {"url": "https://line.me/R/ti/p/{q}", "icon": "fa-line"},
        
        # Professional
        "angellist": {"url": "https://angel.co/u/{q}", "icon": "fa-angellist"},
        "crunchbase": {"url": "https://crunchbase.com/organization/{q}", "icon": "fa-c"},
        "producthunt": {"url": "https://producthunt.com/@{q}", "icon": "fa-product-hunt"},
        
        # Other
        "spotify": {"url": "https://open.spotify.com/user/{q}", "icon": "fa-spotify"},
        "soundcloud": {"url": "https://soundcloud.com/{q}", "icon": "fa-soundcloud"},
        "flickr": {"url": "https://flickr.com/people/{q}", "icon": "fa-flickr"},
        "500px": {"url": "https://500px.com/{q}", "icon": "fa-500px"},
        "mastodon": {"url": "https://mastodon.social/@{q}", "icon": "fa-mastodon"},
        "threads": {"url": "https://threads.net/@{q}", "icon": "fa-at"},
        "bluesky": {"url": "https://bsky.app/profile/{q}", "icon": "fa-cloud"},
        "keybase": {"url": "https://keybase.io/{q}", "icon": "fa-key"},
        "gravatar": {"url": "https://gravatar.com/{q}", "icon": "fa-g"},
        "about_me": {"url": "https://about.me/{q}", "icon": "fa-user"},
        "linktree": {"url": "https://linktr.ee/{q}", "icon": "fa-tree"},
        "patreon": {"url": "https://patreon.com/{q}", "icon": "fa-patreon"},
        "ko_fi": {"url": "https://ko-fi.com/{q}", "icon": "fa-coffee"},
        "buymeacoffee": {"url": "https://buymeacoffee.com/{q}", "icon": "fa-mug-hot"},
    }
    
    # Social link patterns to extract from HTML
    LINK_PATTERNS = [
        (r'(?:twitter|x)\.com/([a-zA-Z0-9_]+)', "twitter"),
        (r'facebook\.com/([a-zA-Z0-9.]+)', "facebook"),
        (r'instagram\.com/([a-zA-Z0-9_.]+)', "instagram"),
        (r'linkedin\.com/(?:in|company)/([a-zA-Z0-9-]+)', "linkedin"),
        (r'github\.com/([a-zA-Z0-9-]+)', "github"),
        (r'youtube\.com/(?:@|c/|channel/)([a-zA-Z0-9_-]+)', "youtube"),
        (r't\.me/([a-zA-Z0-9_]+)', "telegram"),
        (r'discord\.gg/([a-zA-Z0-9]+)', "discord"),
        (r'tiktok\.com/@([a-zA-Z0-9_.]+)', "tiktok"),
        (r'medium\.com/@([a-zA-Z0-9_]+)', "medium"),
        (r'reddit\.com/(?:r|u|user)/([a-zA-Z0-9_]+)', "reddit"),
    ]
    
    def find_profiles(self, query: str, check_exists: bool = False) -> dict:
        """Generate potential social media profile URLs."""
        # Clean query
        clean_query = re.sub(r'[^a-zA-Z0-9_-]', '', query.lower())
        
        profiles = []
        for platform, info in self.PLATFORMS.items():
            url = info["url"].replace("{q}", clean_query)
            profile = {
                "platform": platform,
                "url": url,
                "icon": info.get("icon", "fa-globe"),
                "exists": None
            }
            
            if check_exists:
                # Avoid SSRF by only probing public http/https URLs.
                if is_public_http_url(url):
                    try:
                        resp = requests.head(url, timeout=3, allow_redirects=True)
                        profile["exists"] = resp.status_code == 200
                    except Exception:
                        profile["exists"] = None
                else:
                    profile["exists"] = None
            
            profiles.append(profile)
        
        return {
            "query": query,
            "clean_query": clean_query,
            "total_platforms": len(profiles),
            "profiles": profiles
        }
    
    def extract_from_html(self, html: str) -> dict:
        """Extract social media links from HTML content."""
        found = {}
        
        for pattern, platform in self.LINK_PATTERNS:
            matches = re.findall(pattern, html, re.I)
            if matches:
                # Deduplicate
                unique = list(set(matches))
                if platform in found:
                    found[platform].extend(unique)
                else:
                    found[platform] = unique
        
        # Also extract generic social links
        social_links = re.findall(
            r'href=["\']([^"\']*(?:facebook|twitter|instagram|linkedin|github|youtube|tiktok)[^"\']*)["\']',
            html, re.I
        )
        
        return {
            "platforms_found": list(found.keys()),
            "profiles": found,
            "raw_links": list(set(social_links))[:20],
            "total_found": sum(len(v) for v in found.values())
        }
    
    def full_scan(self, query: str, html: str = "") -> dict:
        """Complete social media intelligence scan."""
        # Generate potential profiles
        potential = self.find_profiles(query, check_exists=False)
        
        # Extract from HTML if provided
        extracted = self.extract_from_html(html) if html else {"profiles": {}, "total_found": 0}
        
        return {
            "query": query,
            "potential_profiles": potential["profiles"][:30],  # Limit output
            "extracted_profiles": extracted["profiles"],
            "total_potential": potential["total_platforms"],
            "total_extracted": extracted["total_found"]
        }


class RansomwareMonitor:
    """Monitor ransomware groups and check victim lists via public APIs."""
    
    API_ENDPOINTS = {
        "ransomware_live": {
            "victims": "https://api.ransomware.live/victims",
            "groups": "https://api.ransomware.live/groups",
            "recent": "https://api.ransomware.live/recentvictims"
        },
        "ransomlook": {
            "groups": "https://www.ransomlook.io/api/groups",
            "recent": "https://www.ransomlook.io/api/recent"
        }
    }
    
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "AEGIS Security Scanner",
            "Accept": "application/json"
        })
        self._cache = {}
        self._cache_time = {}
    
    def _get_cached(self, key: str, url: str, ttl: int = 300) -> dict:
        """Get data with caching."""
        now = time.time()
        if key in self._cache and (now - self._cache_time.get(key, 0)) < ttl:
            return self._cache[key]
        
        try:
            resp = self.session.get(url, timeout=15)
            if resp.status_code == 200:
                data = resp.json()
                self._cache[key] = data
                self._cache_time[key] = now
                return data
        except Exception as e:
            return {"error": str(e)}
        
        return {}
    
    def check_victim(self, domain: str) -> dict:
        """Check if domain appears in ransomware victim lists."""
        results = {
            "domain": domain,
            "found": False,
            "matches": [],
            "sources_checked": []
        }
        
        # Clean domain
        clean_domain = domain.lower().replace("www.", "").split("/")[0]
        
        # Check ransomware.live
        victims = self._get_cached(
            "rl_victims",
            self.API_ENDPOINTS["ransomware_live"]["victims"]
        )
        results["sources_checked"].append("ransomware.live")
        
        if isinstance(victims, list):
            for victim in victims:
                victim_domain = str(victim.get("website", "") or victim.get("domain", "")).lower()
                if clean_domain in victim_domain or victim_domain in clean_domain:
                    results["found"] = True
                    results["matches"].append({
                        "source": "ransomware.live",
                        "group": victim.get("group_name", "Unknown"),
                        "date": victim.get("discovered", victim.get("date", "Unknown")),
                        "country": victim.get("country", "Unknown"),
                        "website": victim_domain
                    })
        
        return results
    
    def get_active_groups(self) -> dict:
        """Get list of active ransomware groups."""
        groups = []
        
        # From ransomware.live
        rl_groups = self._get_cached(
            "rl_groups",
            self.API_ENDPOINTS["ransomware_live"]["groups"]
        )
        
        if isinstance(rl_groups, list):
            for g in rl_groups[:50]:  # Limit
                groups.append({
                    "name": g.get("name", "Unknown"),
                    "url": g.get("url", ""),
                    "status": "active" if g.get("active") else "inactive",
                    "source": "ransomware.live"
                })
        
        # From ransomlook.io
        rsl_groups = self._get_cached(
            "rsl_groups", 
            self.API_ENDPOINTS["ransomlook"]["groups"]
        )
        
        if isinstance(rsl_groups, list):
            for g in rsl_groups[:50]:
                if isinstance(g, dict):
                    groups.append({
                        "name": g.get("name", str(g)),
                        "source": "ransomlook.io"
                    })
        
        return {
            "total_groups": len(groups),
            "groups": groups,
            "sources": ["ransomware.live", "ransomlook.io"]
        }
    
    def get_recent_victims(self, limit: int = 20) -> dict:
        """Get recent ransomware victims."""
        victims = []
        
        # From ransomware.live
        recent = self._get_cached(
            "rl_recent",
            self.API_ENDPOINTS["ransomware_live"]["recent"]
        )
        
        if isinstance(recent, list):
            for v in recent[:limit]:
                victims.append({
                    "name": v.get("victim", v.get("name", "Unknown")),
                    "group": v.get("group_name", v.get("group", "Unknown")),
                    "date": v.get("discovered", v.get("date", "Unknown")),
                    "country": v.get("country", ""),
                    "website": v.get("website", v.get("domain", "")),
                    "source": "ransomware.live"
                })
        
        return {
            "total": len(victims),
            "victims": victims[:limit],
            "retrieved_at": datetime.now().isoformat()
        }
    
    def full_scan(self, domain: str) -> dict:
        """Complete ransomware intelligence scan for domain."""
        victim_check = self.check_victim(domain)
        groups = self.get_active_groups()
        recent = self.get_recent_victims(10)
        
        return {
            "domain": domain,
            "victim_status": victim_check,
            "active_groups_count": groups["total_groups"],
            "recent_victims_sample": recent["victims"][:5],
            "threat_level": "critical" if victim_check["found"] else "unknown",
            "recommendation": "IMMEDIATE ACTION REQUIRED - Domain found in leak site!" if victim_check["found"] else "No matches found in current databases"
        }


# Initialize v6.0 feature instances
social_intel = SocialMediaIntel()
ransomware_monitor = RansomwareMonitor()


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

    # ============ ENHANCED MODULES (v3.0) ============
    
    # Extended OSINT Modules
    run_mod("hunter_io", "hunter_io" in selected_services and domain, hunter_io_lookup, domain)
    run_mod("censys", "censys" in selected_services and domain, censys_search, domain)
    run_mod("github_dorks", "github_dorks" in selected_services and domain, github_dork_search, domain)
    run_mod("fullhunt", "fullhunt" in selected_services and domain, fullhunt_lookup, domain)
    run_mod("binaryedge", "binaryedge" in selected_services and domain, binaryedge_lookup, domain)
    run_mod("builtwith", "builtwith" in selected_services and domain, builtwith_lookup, domain)
    
    # Enhanced Vulnerability Correlation
    if "enhanced_cve" in selected_services and results.get("tech"):
        run_mod("enhanced_cve", True, enhanced_cve_lookup, results.get("tech", {}).get("stack", []))
    
    # Certificate Monitoring
    run_mod("cert_monitor", "cert_monitor" in selected_services and domain, cert_expiry_monitor, domain)
    
    # Active Security Testing (requires explicit opt-in for semi/active modes)
    if mode in ["semi", "active"]:
        run_mod("auth_weakness", "auth_test" in selected_services, auth_weakness_scan, url_norm)
        run_mod("api_security", "api_security" in selected_services, api_security_scan, url_norm)
        run_mod("xxe_detection", "xxe_test" in selected_services, xxe_detection, url_norm)
        run_mod("ssrf_detection", "ssrf_test" in selected_services, ssrf_detection, url_norm)
        run_mod("open_redirect", "redirect_test" in selected_services, open_redirect_scan, url_norm)
        run_mod("header_injection", "header_test" in selected_services, header_injection_test, url_norm)
    
    # Credential Leak Checking for discovered emails
    if crawler_emails and "leakcheck" in selected_services:
        for email in crawler_emails[:5]:  # Limit to avoid rate limits
            email_key = f"leakcheck_{email.replace('@', '_at_').replace('.', '_')}"
            run_mod(email_key, True, leakcheck_lookup, email)
    
    # ============ INNOVATIVE ANALYSIS FEATURES (v4.0) ============
    
    # Entropy-based secret scanner (local, no API)
    run_mod("entropy_scan", "entropy_scan" in selected_services, entropy_scanner.scan_url, url_norm)
    
    # Recon wordlist generator (local, no API)
    run_mod("wordlist_gen", "wordlist_gen" in selected_services, wordlist_generator.generate_wordlist, url_norm)
    
    # Password policy detector (local, no API)
    run_mod("password_policy", "password_policy" in selected_services, password_detector.estimate_policy, url_norm)
    
    # Technology timeline via Archive.org (no API key needed)
    run_mod("tech_timeline", "tech_timeline" in selected_services and domain, tech_timeline.build_timeline, domain)
    
    # Attack surface mapping (post-processing of existing results)
    if "attack_map" in selected_services:
        # Need to run this after other modules have populated results
        pass  # Will be processed after summary
    
    # Report narrative generation (post-processing)
    if "report_narrative" in selected_services:
        # Will be processed after summary
        pass
    
    # ============ ADVANCED FEATURES v5.0 ============
    # Get HTML content for content-based scanners
    html_content = results.get("crawler", {}).get("html", "") or ""
    js_content = results.get("js_secrets", {}).get("raw_js", "") or ""
    response_headers = results.get("headers", {}).get("headers", {}) or {}
    tech_stack = results.get("tech", {}).get("stack", []) or []
    
    # Crypto Address Scanner
    if "crypto_scan" in selected_services:
        try:
            results["crypto_scan"] = crypto_scanner.scan(html_content + js_content)
        except Exception as e:
            results["crypto_scan"] = {"error": str(e)}
    
    # Privacy Leak Detector
    if "privacy_detect" in selected_services:
        try:
            results["privacy_detect"] = privacy_detector.scan(html_content, js_content)
        except Exception as e:
            results["privacy_detect"] = {"error": str(e)}
    
    # Database Leak Detector
    if "db_leak" in selected_services:
        try:
            results["db_leak"] = db_leak_detector.scan(html_content)
        except Exception as e:
            results["db_leak"] = {"error": str(e)}
    
    # JS Deobfuscation Analyzer
    if "js_deobfuscate" in selected_services:
        try:
            results["js_deobfuscate"] = js_deobfuscation.analyze(js_content)
        except Exception as e:
            results["js_deobfuscate"] = {"error": str(e)}
    
    # Homoglyph Scanner
    if "homoglyph_scan" in selected_services and domain:
        try:
            results["homoglyph_scan"] = homoglyph_scanner.scan(domain)
        except Exception as e:
            results["homoglyph_scan"] = {"error": str(e)}
    
    # Ghost Asset Finder
    if "ghost_finder" in selected_services:
        try:
            results["ghost_finder"] = ghost_finder.scan(url_norm)
        except Exception as e:
            results["ghost_finder"] = {"error": str(e)}
    
    # Honeypot Detector
    if "honeypot_detect" in selected_services:
        try:
            results["honeypot_detect"] = honeypot_detector.detect(response_headers, html_content)
        except Exception as e:
            results["honeypot_detect"] = {"error": str(e)}
    
    # Geo Block Detector
    if "geo_block" in selected_services:
        try:
            status_code = results.get("headers", {}).get("status_code", 200)
            results["geo_block"] = geo_block_detector.detect(response_headers, status_code, html_content)
        except Exception as e:
            results["geo_block"] = {"error": str(e)}
    
    # Compliance Checker
    if "compliance_check" in selected_services:
        try:
            results["compliance_check"] = compliance_checker.audit(html_content, url_norm, response_headers)
        except Exception as e:
            results["compliance_check"] = {"error": str(e)}
    
    # Vulnerability Predictor
    if "vuln_predict" in selected_services:
        try:
            results["vuln_predict"] = vuln_predictor.predict(tech_stack)
        except Exception as e:
            results["vuln_predict"] = {"error": str(e)}
    
    # Media Asset Scanner
    if "media_scan" in selected_services:
        try:
            results["media_scan"] = media_scanner.scan(html_content, url_norm)
        except Exception as e:
            results["media_scan"] = {"error": str(e)}
    
    # Mobile App Detector
    if "mobile_detect" in selected_services:
        try:
            results["mobile_detect"] = mobile_detector.scan(html_content, response_headers)
        except Exception as e:
            results["mobile_detect"] = {"error": str(e)}
    
    # Email Template Harvester
    if "email_harvest" in selected_services:
        try:
            results["email_harvest"] = email_harvester.scan(html_content, url_norm)
        except Exception as e:
            results["email_harvest"] = {"error": str(e)}
    
    # Brand Asset Extractor
    if "brand_extract" in selected_services:
        try:
            css_content = ""  # Could extract from stylesheets if needed
            results["brand_extract"] = brand_extractor.extract(html_content, css_content)
        except Exception as e:
            results["brand_extract"] = {"error": str(e)}
    
    # Website DNA Generator
    if "website_dna" in selected_services:
        try:
            results["website_dna"] = website_dna.generate(html_content, response_headers, tech_stack)
        except Exception as e:
            results["website_dna"] = {"error": str(e)}
    
    # Timing Analyzer
    if "timing_analysis" in selected_services:
        try:
            results["timing_analysis"] = timing_analyzer.analyze(url_norm, samples=3)
        except Exception as e:
            results["timing_analysis"] = {"error": str(e)}
    
    # API Endpoint Fuzzer
    if "api_fuzzer" in selected_services:
        try:
            results["api_fuzzer"] = api_fuzzer.discover(js_content, url_norm)
        except Exception as e:
            results["api_fuzzer"] = {"error": str(e)}
    
    # Link Graph Builder
    if "link_graph" in selected_services:
        try:
            results["link_graph"] = link_graph.build(html_content, url_norm)
        except Exception as e:
            results["link_graph"] = {"error": str(e)}
    
    # Subdomain Clusterer
    if "sub_cluster" in selected_services:
        try:
            subdomains = results.get("subdomain_scan", {}).get("found", [])
            results["sub_cluster"] = subdomain_clusterer.cluster(subdomains)
        except Exception as e:
            results["sub_cluster"] = {"error": str(e)}
    
    # Website Value Estimator
    if "site_value" in selected_services:
        try:
            results["site_value"] = value_estimator.estimate(html_content, response_headers, tech_stack)
        except Exception as e:
            results["site_value"] = {"error": str(e)}
    
    # Cookie Consent Analyzer
    if "cookie_consent" in selected_services:
        try:
            results["cookie_consent"] = cookie_analyzer.analyze(html_content)
        except Exception as e:
            results["cookie_consent"] = {"error": str(e)}
    
    # ============ v6.0 SOCMINT & RANSOMWARE INTEL ============
    
    # Social Media Intelligence - find profiles
    if "social_intel" in selected_services and domain:
        try:
            results["social_intel"] = social_intel.find_profiles(domain.split(".")[0])
        except Exception as e:
            results["social_intel"] = {"error": str(e)}
    
    # Social Media Extractor - extract from HTML
    if "social_extract" in selected_services:
        try:
            results["social_extract"] = social_intel.extract_from_html(html_content)
        except Exception as e:
            results["social_extract"] = {"error": str(e)}
    
    # Ransomware Victim Check
    if "ransomware_check" in selected_services and domain:
        try:
            results["ransomware_check"] = ransomware_monitor.check_victim(domain)
        except Exception as e:
            results["ransomware_check"] = {"error": str(e)}
    
    # Active Ransomware Groups
    if "ransom_groups" in selected_services:
        try:
            results["ransom_groups"] = ransomware_monitor.get_active_groups()
        except Exception as e:
            results["ransom_groups"] = {"error": str(e)}
    
    # Recent Ransomware Victims
    if "ransom_victims" in selected_services:
        try:
            results["ransom_victims"] = ransomware_monitor.get_recent_victims(20)
        except Exception as e:
            results["ransom_victims"] = {"error": str(e)}

    # ============ v6.1.0 ENHANCED ANALYSIS MODULES ============
    # These modules run enhanced local analysis without external APIs
    
    enhancement_services = {
        "security_posture", "attack_vectors", "smart_summary", "http_fingerprint",
        "input_validation", "csp_analysis", "recon_detection", "js_complexity",
        "session_analysis", "rate_limiting", "cache_analysis", "form_security", "meta_tags"
    }
    
    if ENHANCEMENTS_AVAILABLE and any(s in selected_services for s in enhancement_services):
        try:
            duration = time.perf_counter() - t0
            enhanced_results = run_enhanced_modules(results, url_norm, html_content, response_headers, duration)
            
            # Add selected enhancement results
            for key in enhancement_services:
                if key in selected_services and key in enhanced_results:
                    results[key] = enhanced_results[key]
        except Exception as e:
            logger.warning(f"Enhanced modules failed: {e}")

    summary = build_summary(results)
    try:
        summary["anomalies"] = compute_anomalies(url_norm, summary)
    except Exception:
        summary["anomalies"] = {"message": "Baseline unavailable."}
    
    # Apply MITRE ATT&CK mapping
    results["mitre_attack"] = apply_mitre_mapping(results)
    
    # AI-Enhanced Analysis (v3.0)
    if AI_ENABLED:
        try:
            # Smart risk scoring with ML factors
            smart_risk = ai_analyzer.smart_risk_scoring(results)
            summary["ai_risk_score"] = smart_risk.get("score", summary.get("risk_score", 0))
            summary["ai_risk_level"] = smart_risk.get("level", summary.get("risk_level", "unknown"))
            summary["risk_factors"] = smart_risk.get("factors", [])
            
            # AI executive summary
            summary["ai_summary"] = ai_analyzer.generate_executive_summary(results)
        except Exception as e:
            logger.warning(f"AI analysis failed: {e}")
            summary["ai_summary"] = ai_analyzer._fallback_summary(results)
    
    results["_summary"] = summary
    results["_meta"] = {
        "total_seconds": round(time.perf_counter() - t0, 3),
        "module_times": {k: v for k, v in module_times.items() if v},
        "scheduled_run": scheduled_run,
        "base_domain": domain,
        "scheme": parsed_url.scheme or "http",
        "aegis_version": AEGIS_VERSION,
        "ai_enabled": AI_ENABLED,
        "scan_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    }
    
    # ============ v4.0 POST-PROCESSING MODULES ============
    # These run after all other modules so they can analyze the complete results
    
    # Attack Surface Mapper - visualizes all discovered assets
    if "attack_map" in selected_services:
        try:
            results["attack_map"] = attack_surface_mapper.map_surface(results)
        except Exception as e:
            results["attack_map"] = {"error": str(e)}
    
    # Scan Diff Analyzer - compares with previous scan
    if "scan_diff" in selected_services:
        try:
            # Get previous scan from database
            with app.app_context():
                db = get_db()
                prev_row = db.execute(
                    "SELECT results FROM scans WHERE url LIKE ? ORDER BY id DESC LIMIT 1",
                    (f"%{domain}%",)
                ).fetchone()
                previous = json.loads(prev_row["results"]) if prev_row else None
            results["scan_diff"] = scan_diff_analyzer.analyze(results, previous)
        except Exception as e:
            results["scan_diff"] = {"error": str(e), "has_previous": False}
    
    # Report Narrative Generator - management-friendly summaries
    if "report_narrative" in selected_services:
        try:
            results["report_narrative"] = report_narrative_gen.generate_full_report(results)
        except Exception as e:
            results["report_narrative"] = {"error": str(e)}
    
    # Delta Alerts - check for significant changes
    if "delta_alerts" in selected_services:
        try:
            with app.app_context():
                db = get_db()
                results["delta_alerts"] = delta_alert_manager.check_for_changes(results, db)
        except Exception as e:
            results["delta_alerts"] = {"error": str(e), "alerts": []}
    
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
        pdf_available=(WeasyHTML is not None),
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
        pdf_available=(WeasyHTML is not None),
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
    if WeasyHTML is None:
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
    pdf = WeasyHTML(string=rendered_html).write_pdf()
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
    if report_format == "html" or WeasyHTML is None:
        resp = make_response(report_html)
        resp.headers["Content-Type"] = "text/html"
        resp.headers["Content-Disposition"] = "attachment; filename=report.html"
        return resp
    pdf = WeasyHTML(string=report_html).write_pdf()
    response = make_response(pdf)
    response.headers['Content-Type'] = 'application/pdf'
    response.headers['Content-Disposition'] = 'attachment; filename=report.pdf'
    return response

# ================================================================================
#                           REST API ENDPOINTS (v3.0)
# ================================================================================

@app.route("/api/v1/scan", methods=["POST"])
def api_scan():
    """REST API endpoint for programmatic scanning."""
    data = request.get_json() or {}
    url_to_scan = data.get("url")
    if not url_to_scan:
        return jsonify({"error": "URL is required"}), 400
    
    services = data.get("services", ["crawler", "tech", "headers", "sec_headers"])
    mode = data.get("mode", "defensive")
    
    try:
        results, normalized_url = run_scan(url_to_scan, services, mode)
        
        # Store in database
        db = get_db()
        cur = db.execute(
            "INSERT INTO scans(url, results, scan_date) VALUES(?,?,?)",
            (normalized_url, json.dumps(results), datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
        )
        db.commit()
        scan_id = cur.lastrowid
        
        return jsonify({
            "success": True,
            "scan_id": scan_id,
            "url": normalized_url,
            "summary": results.get("_summary", {}),
            "meta": results.get("_meta", {})
        })
    except Exception as e:
        logger.error(f"API scan failed: {e}")
        return jsonify({"error": str(e)}), 500


@app.route("/api/v1/scan/<int:scan_id>", methods=["GET"])
def api_get_scan(scan_id):
    """Get scan results by ID."""
    db = get_db()
    row = db.execute("SELECT * FROM scans WHERE id=?", (scan_id,)).fetchone()
    if not row:
        return jsonify({"error": "Scan not found"}), 404
    
    return jsonify({
        "id": row["id"],
        "url": row["url"],
        "scan_date": row["scan_date"],
        "results": json.loads(row["results"])
    })


@app.route("/api/v1/scans", methods=["GET"])
def api_list_scans():
    """List all scans with pagination."""
    page = request.args.get("page", 1, type=int)
    per_page = min(request.args.get("per_page", 20, type=int), 100)
    offset = (page - 1) * per_page
    
    db = get_db()
    total = db.execute("SELECT COUNT(*) as c FROM scans").fetchone()["c"]
    rows = db.execute(
        "SELECT id, url, scan_date FROM scans ORDER BY id DESC LIMIT ? OFFSET ?",
        (per_page, offset)
    ).fetchall()
    
    return jsonify({
        "total": total,
        "page": page,
        "per_page": per_page,
        "scans": [{"id": r["id"], "url": r["url"], "scan_date": r["scan_date"]} for r in rows]
    })


@app.route("/api/v1/export/splunk/<int:scan_id>", methods=["GET"])
def api_export_splunk(scan_id):
    """Export scan results in Splunk HEC format."""
    db = get_db()
    row = db.execute("SELECT url, results FROM scans WHERE id=?", (scan_id,)).fetchone()
    if not row:
        return jsonify({"error": "Scan not found"}), 404
    
    results = json.loads(row["results"])
    events = export_splunk_format(results, row["url"])
    return jsonify({"events": events})


@app.route("/api/v1/export/elastic/<int:scan_id>", methods=["GET"])
def api_export_elastic(scan_id):
    """Export scan results in Elasticsearch bulk format."""
    db = get_db()
    row = db.execute("SELECT url, results FROM scans WHERE id=?", (scan_id,)).fetchone()
    if not row:
        return jsonify({"error": "Scan not found"}), 404
    
    results = json.loads(row["results"])
    docs = export_elastic_format(results, row["url"])
    return jsonify({"documents": docs})


@app.route("/api/v1/compare/<int:old_id>/<int:new_id>", methods=["GET"])
def api_compare_scans(old_id, new_id):
    """Compare two scans for change detection."""
    db = get_db()
    changes = change_detection(old_id, new_id, db)
    return jsonify(changes)


@app.route("/api/v1/trends/<domain>", methods=["GET"])
def api_trend_analysis(domain):
    """Get security trend analysis for a domain."""
    db = get_db()
    limit = request.args.get("limit", 10, type=int)
    trends = trend_analysis(domain, db, limit)
    return jsonify(trends)


@app.route("/api/v1/asset-discovery", methods=["POST"])
def api_asset_discovery():
    """Discover assets from a seed domain."""
    data = request.get_json() or {}
    domain = data.get("domain")
    if not domain:
        return jsonify({"error": "Domain is required"}), 400
    
    assets = asset_discovery(domain)
    return jsonify(assets)


@app.route("/api/v1/health", methods=["GET"])
def api_health():
    """Health check endpoint."""
    return jsonify({
        "status": "healthy",
        "version": AEGIS_VERSION,
        "ai_enabled": AI_ENABLED,
        "features": {
            "openai": OPENAI_AVAILABLE,
            "anthropic": ANTHROPIC_AVAILABLE,
            "ml": ML_AVAILABLE,
            "plotly": PLOTLY_AVAILABLE,
            "censys": CENSYS_AVAILABLE,
        }
    })


@app.route("/api/v1/webhook/test", methods=["POST"])
def api_test_webhook():
    """Test webhook notifications."""
    data = request.get_json() or {}
    webhook_type = data.get("type", "discord")
    message = data.get("message", "AEGIS Test Notification")
    
    success = False
    if webhook_type == "discord":
        success = send_discord_notification(message)
    elif webhook_type == "teams":
        success = send_teams_notification(message)
    elif webhook_type == "telegram":
        success = send_telegram_notification(message)
    
    return jsonify({"success": success, "type": webhook_type})


# ---------------- Main ----------------
if __name__ == "__main__":
    with app.app_context():
        init_db()
    logger.info(f"🛡️ AEGIS v{AEGIS_VERSION} - Enterprise Threat Hunter")
    logger.info(f"   AI Features: {'Enabled' if AI_ENABLED else 'Disabled'}")
    # Bind to localhost to avoid Windows firewall prompt for public networks
    app.run(host="127.0.0.1", port=8080, debug=True)

