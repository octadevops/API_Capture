#!/usr/bin/env python3
"""
API Capture Framework - Web Dashboard
Serves captured data (endpoints, stocks, PDFs, pages) with an embedded
analysis modal. Reads the JSON export produced by app.py (default: most
recent file in api_captures/, or --file to pin one).

Usage: python server.py [--file api_captures/api_capture_xxx.json] [--port 5000]
"""

import argparse
import json
import os
import re
from collections import Counter
from datetime import datetime
from pathlib import Path

from flask import Flask, jsonify, render_template_string

app = Flask(__name__)

DATA_FILE = None
LIVE_FILE = None

CURRENT_JSON = None
CURRENT_MTIME = None


def load_data():
    """Load data from file, caching by mtime (supports live refresh)"""
    global CURRENT_JSON, CURRENT_MTIME
    target = LIVE_FILE or DATA_FILE
    if not target:
        return {}
    try:
        mtime = os.path.getmtime(target)
        if CURRENT_JSON is None or mtime != CURRENT_MTIME:
            with open(target, 'r', encoding='utf-8') as f:
                CURRENT_JSON = json.load(f)
            CURRENT_MTIME = mtime
    except Exception:
        return CURRENT_JSON or {}
    return CURRENT_JSON or {}


def to_float(value):
    """Safe float conversion for display"""
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def compute_analysis(data):
    """Compute structured analysis over captured data"""
    endpoints = data.get('endpoints', {})
    stocks = data.get('stocks', {})
    pdfs = data.get('pdfs', {})
    pages = data.get('pages_visited', [])
    news = data.get('news', {})
    stats = data.get('statistics', {})
    metadata = data.get('metadata', {})

    ep_list = []
    for key, ep in endpoints.items():
        parts = key.split(' ', 1)
        ep_list.append({
            'method': parts[0] if len(parts) > 1 else '?',
            'url': parts[1] if len(parts) > 1 else key,
            **ep
        })

    method_dist = Counter(e['method'] for e in ep_list)
    auth_count = sum(1 for e in ep_list if e.get('auth_required'))
    top_endpoints = sorted(ep_list, key=lambda e: e.get('call_count', 0), reverse=True)[:10]
    param_freq = Counter(p for e in ep_list for p in e.get('parameters', {}))
    top_params = param_freq.most_common(15)
    insecure = [e for e in ep_list if e['url'].startswith('http://')]

    suspicious_params = [p for p in param_freq if re.search(r'(key|token|secret|pass|cred|auth|session)', p, re.I)]
    sensitive_endpoints = [e for e in ep_list if e.get('auth_required')]

    stocks_list = list(stocks.values())
    gainers = sorted(
        [s for s in stocks_list if to_float(s.get('change')) is not None],
        key=lambda s: to_float(s.get('change')) or 0, reverse=True
    )[:5]
    losers = list(reversed(gainers))[:5]
    volume_leaders = sorted(
        [s for s in stocks_list if to_float(s.get('volume')) is not None],
        key=lambda s: to_float(s.get('volume')) or 0, reverse=True
    )[:5]
    prices = [to_float(s.get('price')) for s in stocks_list]
    prices = [p for p in prices if p is not None]
    avg_price = sum(prices) / len(prices) if prices else None

    news_list = list(news.values())
    pdf_sentiments = [p.get('sentiment') for p in pdfs.values() if p.get('sentiment')]
    all_sentiments = [n.get('sentiment') for n in news_list if n.get('sentiment')] + pdf_sentiments

    sent_dist = Counter(s.get('label', 'Neutral') for s in all_sentiments)
    sent_scores = [s.get('score') for s in all_sentiments if isinstance(s.get('score'), (int, float))]
    avg_sentiment = round(sum(sent_scores) / len(sent_scores), 3) if sent_scores else None
    market_mood = 'Bullish' if avg_sentiment is not None and avg_sentiment > 0.55 else \
                  ('Bearish' if avg_sentiment is not None and avg_sentiment < 0.45 else 'Neutral')

    positive_articles = sorted(
        [n for n in news_list if n.get('sentiment', {}).get('label') == 'Positive'],
        key=lambda n: n.get('sentiment', {}).get('score', 0), reverse=True
    )[:5]
    negative_articles = sorted(
        [n for n in news_list if n.get('sentiment', {}).get('label') == 'Negative'],
        key=lambda n: n.get('sentiment', {}).get('score', 0)
    )[:5]

    symbol_sentiment = {}
    for n in news_list:
        for sym in n.get('symbols', []):
            score = n.get('sentiment', {}).get('score')
            if not isinstance(score, (int, float)):
                continue
            agg = symbol_sentiment.setdefault(sym, {'articles': 0, 'total': 0.0})
            agg['articles'] += 1
            agg['total'] += score

    symbol_analysis = []
    for sym, agg in sorted(symbol_sentiment.items(), key=lambda x: x[1]['total'] / x[1]['articles'], reverse=True):
        stock = stocks.get(sym, {})
        symbol_analysis.append({
            'symbol': sym,
            'articles': agg['articles'],
            'avg_sentiment': round(agg['total'] / agg['articles'], 3),
            'price_change': stock.get('change'),
            'price': stock.get('price'),
        })

    # CSE doc type breakdown
    pdf_press = sum(1 for p in pdfs.values() if p.get('doc_type') == 'press_release')
    pdf_annual = sum(1 for p in pdfs.values() if p.get('doc_type') == 'annual_report')
    pdf_other = len(pdfs) - pdf_press - pdf_annual
    return {
        'generated_at': datetime.now().isoformat(),
        'target_url': metadata.get('target_url'),
        'capture_mode': metadata.get('capture_mode'),
        'summary': {
            'endpoints': len(ep_list),
            'stocks': len(stocks_list),
            'pdfs': len(pdfs),
            'pdf_press': pdf_press,
            'pdf_annual': pdf_annual,
            'pdf_other': pdf_other,
            'pages': len(pages),
            'news': len(news_list),
            'auth_required': auth_count,
            'public': len(ep_list) - auth_count,
            'total_parameters': stats.get('total_parameters', 0),
        },
        'method_distribution': dict(method_dist.most_common()),
        'top_endpoints': top_endpoints,
        'top_parameters': top_params,
        'insecure_http': insecure,
        'suspicious_parameters': suspicious_params,
        'sensitive_endpoints': sensitive_endpoints,
        'stock_analysis': {
            'total': len(stocks_list),
            'avg_price': round(avg_price, 2) if avg_price is not None else None,
            'gainers': gainers,
            'losers': losers,
            'volume_leaders': volume_leaders,
        },
        'market_sentiment': {
            'articles': len(news_list),
            'pdfs_analyzed': len(pdf_sentiments),
            'distribution': dict(sent_dist),
            'avg_score': avg_sentiment,
            'mood': market_mood,
            'engine': all_sentiments[0].get('engine', 'lexicon') if all_sentiments else 'n/a',
            'positive_articles': positive_articles,
            'negative_articles': negative_articles,
            'symbol_analysis': symbol_analysis,
        },
    }


@app.route('/api/data')
def api_data():
    return jsonify(load_data())


@app.route('/api/analysis')
def api_analysis():
    return jsonify(compute_analysis(load_data()))


@app.route('/')
def index():
    return render_template_string(INDEX_HTML)


INDEX_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>API Capture Dashboard</title>
<style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body {
        font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
        background: #0f172a; color: #e2e8f0; padding: 20px;
    }
    .header {
        background: linear-gradient(135deg, #6366f1 0%, #a855f7 100%);
        padding: 20px 30px; border-radius: 12px; margin-bottom: 20px;
        display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap;
    }
    .header h1 { font-size: 1.6em; }
    .header .meta { font-size: 0.85em; opacity: 0.9; margin-top: 4px; }
    .btn {
        background: #1e293b; color: #e2e8f0; border: 1px solid #475569;
        padding: 10px 18px; border-radius: 8px; cursor: pointer;
        font-size: 0.95em; transition: all 0.2s;
    }
    .btn:hover { background: #334155; border-color: #818cf8; }
    .btn.primary { background: #6366f1; border-color: #6366f1; color: white; }
    .btn.primary:hover { background: #4f46e5; }
    .cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 15px; margin-bottom: 20px; }
    .card {
        background: #1e293b; border: 1px solid #334155; border-radius: 10px;
        padding: 16px; text-align: center;
    }
    .card .num { font-size: 1.9em; font-weight: 700; color: #818cf8; }
    .card .label { font-size: 0.8em; color: #94a3b8; margin-top: 4px; }
    .tabs { display: flex; gap: 8px; margin-bottom: 15px; flex-wrap: wrap; }
    .tab {
        background: #1e293b; border: 1px solid #334155; color: #94a3b8;
        padding: 8px 16px; border-radius: 8px; cursor: pointer; font-size: 0.9em;
    }
    .tab.active { background: #6366f1; color: white; border-color: #6366f1; }
    .panel { display: none; }
    .panel.active { display: block; }
    table { width: 100%; border-collapse: collapse; background: #1e293b; border-radius: 10px; overflow: hidden; }
    th { background: #334155; color: #e2e8f0; padding: 12px 14px; text-align: left; font-size: 0.85em; }
    td { padding: 10px 14px; border-bottom: 1px solid #334155; font-size: 0.88em; }
    tr:hover td { background: #24324a; }
    tr.clickable { cursor: pointer; }
    .method { display: inline-block; padding: 3px 8px; border-radius: 5px; font-weight: 700; font-size: 0.78em; }
    .m-GET { background: #059669; color: white; }
    .m-POST { background: #d97706; color: white; }
    .m-PUT { background: #0284c7; color: white; }
    .m-DELETE { background: #dc2626; color: white; }
    .m-PATCH { background: #7c3aed; color: white; }
    .m-OTHER { background: #64748b; color: white; }
    .badge { display: inline-block; padding: 3px 8px; border-radius: 5px; font-size: 0.75em; font-weight: 600; }
    .b-auth { background: #fef3c7; color: #92400e; }
    .b-public { background: #d1fae5; color: #065f46; }
    .up { color: #34d399; }
    .down { color: #f87171; }
    .empty { color: #64748b; padding: 30px; text-align: center; }

    /* ===== Modal ===== */
    .modal-overlay {
        display: none; position: fixed; inset: 0; background: rgba(2, 6, 23, 0.85);
        z-index: 1000; overflow-y: auto; padding: 30px 15px;
    }
    .modal-overlay.open { display: block; }
    .modal {
        background: #1e293b; border: 1px solid #334155; border-radius: 14px;
        max-width: 1000px; margin: 0 auto; box-shadow: 0 25px 60px rgba(0,0,0,0.6);
    }
    .modal-head {
        display: flex; justify-content: space-between; align-items: center;
        padding: 18px 24px; border-bottom: 1px solid #334155;
        background: linear-gradient(135deg, #6366f1, #a855f7); border-radius: 14px 14px 0 0;
    }
    .modal-head h2 { font-size: 1.15em; }
    .modal-close { background: none; border: none; color: white; font-size: 1.6em; cursor: pointer; line-height: 1; }
    .modal-body { padding: 24px; max-height: 72vh; overflow-y: auto; }
    .section { margin-bottom: 26px; }
    .section h3 {
        color: #a5b4fc; font-size: 0.95em; text-transform: uppercase; letter-spacing: 0.05em;
        margin-bottom: 12px; padding-bottom: 6px; border-bottom: 1px solid #334155;
    }
    .bar-row { display: flex; align-items: center; margin-bottom: 6px; }
    .bar-label { width: 110px; font-size: 0.85em; color: #94a3b8; }
    .bar-track { flex: 1; background: #334155; border-radius: 6px; height: 16px; margin: 0 10px; overflow: hidden; }
    .bar-fill { height: 100%; background: linear-gradient(90deg, #6366f1, #a855f7); border-radius: 6px; }
    .bar-value { width: 60px; font-size: 0.85em; text-align: right; }
    .kv { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 10px; margin-bottom: 14px; }
    .kv-item { background: #0f172a; border: 1px solid #334155; border-radius: 8px; padding: 10px 14px; }
    .kv-item .k { font-size: 0.72em; color: #94a3b8; text-transform: uppercase; }
    .kv-item .v { font-size: 1.15em; font-weight: 600; margin-top: 3px; }
    .note { background: #0f172a; border-left: 3px solid #6366f1; padding: 10px 14px; border-radius: 0 8px 8px 0; font-size: 0.85em; margin-bottom: 8px; }
    pre { background: #0f172a; padding: 10px; border-radius: 8px; overflow-x: auto; font-size: 0.78em; max-height: 200px; }
    code { color: #93c5fd; }
    .loading { text-align: center; color: #94a3b8; padding: 40px; }
    .sent-badge { display: inline-block; padding: 3px 8px; border-radius: 5px; font-size: 0.75em; font-weight: 700; }
    .s-pos { background: #d1fae5; color: #065f46; }
    .s-neg { background: #fee2e2; color: #991b1b; }
    .s-neu { background: #e2e8f0; color: #475569; }
</style>
</head>
<body>

<div class="header">
    <div>
        <h1>API Capture Dashboard</h1>
        <div class="meta" id="meta">Loading data...</div>
    </div>
    <div>
        <button class="btn primary" onclick="openAnalysis()">Analyze Data</button>
        <button class="btn" onclick="refreshAll()">Refresh</button>
    </div>
</div>

<div class="cards" id="cards"></div>

<div class="tabs">
    <button class="tab active" onclick="switchTab('endpoints', this)">Endpoints</button>
    <button class="tab" onclick="switchTab('stocks', this)">Stocks</button>
    <button class="tab" onclick="switchTab('news', this)">News</button>
    <button class="tab" onclick="switchTab('pdfs', this)">PDFs</button>
    <button class="tab" onclick="switchTab('pages', this)">Pages</button>
</div>

<div class="panel active" id="panel-endpoints">
    <table>
        <thead><tr><th>#</th><th>Method</th><th>URL</th><th>Calls</th><th>Params</th><th>Auth</th></tr></thead>
        <tbody id="tbody-endpoints"></tbody>
    </table>
    <div class="empty" id="empty-endpoints">No endpoints captured</div>
</div>

<div class="panel" id="panel-stocks">
    <table>
        <thead><tr><th>Symbol</th><th>Company</th><th>Price</th><th>Change</th><th>Volume</th><th>Source</th></tr></thead>
        <tbody id="tbody-stocks"></tbody>
    </table>
    <div class="empty" id="empty-stocks">No stock data captured</div>
</div>

<div class="panel" id="panel-news">
    <table>
        <thead><tr><th>#</th><th>Source</th><th>Sentiment</th><th>Symbols</th><th>Title</th></tr></thead>
        <tbody id="tbody-news"></tbody>
    </table>
    <div class="empty" id="empty-news">No news articles captured</div>
</div>

<div class="panel" id="panel-pdfs">
    <table>
        <thead><tr><th>#</th><th>Type</th><th>File</th><th>Pages</th><th>Sentiment</th><th>Title / URL</th></tr></thead>
        <tbody id="tbody-pdfs"></tbody>
    </table>
    <div class="empty" id="empty-pdfs">No PDFs captured (use "capture press" or "capture annual" or "capture cse")</div>
</div>

<div class="panel" id="panel-pages">
    <table>
        <thead><tr><th>#</th><th>URL</th></tr></thead>
        <tbody id="tbody-pages"></tbody>
    </table>
    <div class="empty" id="empty-pages">No pages visited</div>
</div>

<!-- ===== Analysis Modal ===== -->
<div class="modal-overlay" id="analysis-modal">
    <div class="modal">
        <div class="modal-head">
            <h2>Data Analysis</h2>
            <button class="modal-close" onclick="closeModal('analysis-modal')">&times;</button>
        </div>
        <div class="modal-body" id="analysis-body">
            <div class="loading">Computing analysis...</div>
        </div>
    </div>
</div>

<!-- ===== Endpoint Detail Modal ===== -->
<div class="modal-overlay" id="detail-modal">
    <div class="modal">
        <div class="modal-head">
            <h2 id="detail-title">Endpoint Details</h2>
            <button class="modal-close" onclick="closeModal('detail-modal')">&times;</button>
        </div>
        <div class="modal-body" id="detail-body"></div>
    </div>
</div>

<!-- ===== News Detail Modal ===== -->
<div class="modal-overlay" id="news-modal">
    <div class="modal">
        <div class="modal-head">
            <h2>Article Details</h2>
            <button class="modal-close" onclick="closeModal('news-modal')">&times;</button>
        </div>
        <div class="modal-body" id="news-body"></div>
    </div>
</div>

<script>
let DATA = null;

function esc(s) {
    if (s === null || s === undefined) return '';
    return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

function fmt(v) {
    if (v === null || v === undefined || v === '') return '-';
    if (typeof v === 'number') {
        if (Number.isInteger(v)) return v.toLocaleString();
        return v.toFixed(2);
    }
    return v;
}

function methodClass(m) {
    const map = {GET:'m-GET', POST:'m-POST', PUT:'m-PUT', DELETE:'m-DELETE', PATCH:'m-PATCH'};
    return map[m] || 'm-OTHER';
}

function sentClass(label) {
    const map = {Positive:'s-pos', Negative:'s-neg', Neutral:'s-neu'};
    return map[label] || 's-neu';
}

async function fetchJson(url) {
    const r = await fetch(url);
    return r.json();
}

async function refreshAll() {
    try {
        DATA = await fetchJson('/api/data');
        const analysis = await fetchJson('/api/analysis');
        renderAll(analysis);
    } catch (e) {
        document.getElementById('meta').textContent = 'Failed to load data: ' + e.message;
    }
}

function renderAll(analysis) {
    const meta = analysis.target_url ? 'Target: ' + analysis.target_url + ' | ' : '';
    document.getElementById('meta').textContent = meta + 'Generated: ' + analysis.generated_at;

    const s = analysis.summary;
    document.getElementById('cards').innerHTML = [
        {n: s.endpoints, l: 'Endpoints'},
        {n: s.stocks, l: 'Stocks'},
        {n: s.news, l: 'News Articles'},
        {n: s.pdfs, l: 'PDFs'},
        {n: s.pdf_press ?? 0, l: 'Press Releases'},
        {n: s.pdf_annual ?? 0, l: 'Annual Reports'},
        {n: s.pages, l: 'Pages'},
        {n: s.auth_required, l: 'Auth Required'}
    ].map(c => `<div class="card"><div class="num">${c.n}</div><div class="label">${c.l}</div></div>`).join('');

    renderEndpoints(analysis);
    renderStocks(analysis);
    renderNews(analysis);
    renderPdfs();
    renderPages();
}

function renderNews(analysis) {
    const news = Object.values(DATA.news || {});
    const tbody = document.getElementById('tbody-news');
    const empty = document.getElementById('empty-news');
    empty.style.display = news.length ? 'none' : 'block';
    tbody.innerHTML = news.map((n, i) => {
        const sent = n.sentiment || {};
        return `<tr class="clickable" onclick="openNews(${i})">
            <td>${i+1}</td>
            <td>${esc(n.source || '-')}</td>
            <td><span class="sent-badge ${sentClass(sent.label)}">${esc(sent.label || 'Neutral')}</span></td>
            <td>${esc((n.symbols || []).join(', ') || '-')}</td>
            <td>${esc((n.title || '').slice(0, 70))}</td>
        </tr>`;
    }).join('');
    window._news = news;
}

function renderEndpoints(analysis) {
    const eps = Object.entries(DATA.endpoints || {});
    const tbody = document.getElementById('tbody-endpoints');
    const empty = document.getElementById('empty-endpoints');
    empty.style.display = eps.length ? 'none' : 'block';
    tbody.innerHTML = eps.map(([key, ep], i) => {
        const parts = key.split(' ');
        const method = parts[0], url = parts.slice(1).join(' ');
        const auth = ep.auth_required ? '<span class="badge b-auth">AUTH</span>' : '<span class="badge b-public">PUBLIC</span>';
        return `<tr class="clickable" onclick="openDetail(${i})">
            <td>${i+1}</td>
            <td><span class="method ${methodClass(method)}">${esc(method)}</span></td>
            <td>${esc(url)}</td>
            <td>${ep.call_count}</td>
            <td>${Object.keys(ep.parameters || {}).length}</td>
            <td>${auth}</td>
        </tr>`;
    }).join('');
    window._eps = eps;
}

function renderStocks(analysis) {
    const stocks = Object.values(DATA.stocks || {});
    const tbody = document.getElementById('tbody-stocks');
    const empty = document.getElementById('empty-stocks');
    empty.style.display = stocks.length ? 'none' : 'block';
    tbody.innerHTML = stocks.map(s => {
        const chg = s.change;
        const chgCls = (typeof chg === 'number') ? (chg >= 0 ? 'up' : 'down') : '';
        return `<tr>
            <td><b>${esc(s.symbol)}</b></td>
            <td>${esc(s.company || '-')}</td>
            <td>${fmt(s.price)}</td>
            <td class="${chgCls}">${fmt(s.change)}</td>
            <td>${fmt(s.volume)}</td>
            <td style="font-size:0.75em;color:#94a3b8">${esc(s.source_url || '-')}</td>
        </tr>`;
    }).join('');
}

function renderPdfs() {
    const pdfs = Object.values(DATA.pdfs || {});
    const tbody = document.getElementById('tbody-pdfs');
    const empty = document.getElementById('empty-pdfs');
    empty.style.display = pdfs.length ? 'none' : 'block';
    tbody.innerHTML = pdfs.map((p, i) => {
        const dtype = p.doc_type || 'other';
        const badge = dtype === 'press_release' ? '<span class="badge b-auth">PRESS</span>' : (dtype === 'annual_report' ? '<span class="badge b-public">ANNUAL</span>' : '<span class="badge">OTHER</span>');
        const sent = p.sentiment ? `<span class="sent-badge ${sentClass(p.sentiment.label)}">${esc(p.sentiment.label)}</span>` : '-';
        return `<tr>
        <td>${i+1}</td>
        <td>${badge}</td>
        <td>${esc(p.filepath.split('/').pop() || p.filepath)}</td>
        <td>${p.page_count}</td>
        <td>${sent}</td>
        <td style="font-size:0.70em;color:#94a3b8">${esc((p.title||'').slice(0,45))}<br>${esc(p.url.slice(0,60))}</td>
    </tr>`;
    }).join('');
}

function renderPages() {
    const pages = DATA.pages_visited || [];
    const tbody = document.getElementById('tbody-pages');
    const empty = document.getElementById('empty-pages');
    empty.style.display = pages.length ? 'none' : 'block';
    tbody.innerHTML = pages.map((p, i) => `<tr><td>${i+1}</td><td>${esc(p)}</td></tr>`).join('');
}

function switchTab(name, btn) {
    document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
    document.querySelectorAll('.panel').forEach(p => p.classList.remove('active'));
    btn.classList.add('active');
    document.getElementById('panel-' + name).classList.add('active');
}

function openModal(id) { document.getElementById(id).classList.add('open'); }
function closeModal(id) { document.getElementById(id).classList.remove('open'); }

async function openAnalysis() {
    openModal('analysis-modal');
    const body = document.getElementById('analysis-body');
    body.innerHTML = '<div class="loading">Computing analysis...</div>';
    try {
        const a = await fetchJson('/api/analysis');
        body.innerHTML = buildAnalysisHTML(a);
    } catch (e) {
        body.innerHTML = '<div class="empty">Analysis failed: ' + esc(e.message) + '</div>';
    }
}

function buildAnalysisHTML(a) {
    let html = '';

    html += '<div class="section"><h3>Summary</h3><div class="kv">';
    const s = a.summary;
    const items = [
        ['Endpoints', s.endpoints], ['Stocks', s.stocks], ['PDFs', s.pdfs],
        ['Pages Crawled', s.pages], ['Auth Required', s.auth_required],
        ['Public', s.public], ['Total Parameters', s.total_parameters],
        ['Avg Stock Price', a.stock_analysis.avg_price ?? '-']
    ];
    items.forEach(([k, v]) => { html += `<div class="kv-item"><div class="k">${k}</div><div class="v">${fmt(v)}</div></div>`; });
    html += '</div></div>';

    html += '<div class="section"><h3>HTTP Method Distribution</h3>';
    Object.entries(a.method_distribution).forEach(([m, c]) => {
        const pct = s.endpoints ? Math.round(c / s.endpoints * 100) : 0;
        html += `<div class="bar-row"><div class="bar-label">${esc(m)}</div>
            <div class="bar-track"><div class="bar-fill" style="width:${pct}%"></div></div>
            <div class="bar-value">${c}</div></div>`;
    });
    html += '</div>';

    if (a.top_endpoints.length) {
        html += '<div class="section"><h3>Top Endpoints by Call Count</h3>';
        a.top_endpoints.forEach((e, i) => {
            html += `<div class="note"><b>${i+1}.</b> <span class="method ${methodClass(e.method)}">${esc(e.method)}</span> ` +
                `<code>${esc(e.url)}</code> — ${e.call_count} calls${e.auth_required ? ' (AUTH)' : ''}</div>`;
        });
        html += '</div>';
    }

    if (a.top_parameters.length) {
        html += '<div class="section"><h3>Most Used Parameters</h3>';
        a.top_parameters.forEach(([p, c]) => {
            html += `<div class="bar-row"><div class="bar-label">${esc(p)}</div>
                <div class="bar-track"><div class="bar-fill" style="width:${c}%"></div></div>
                <div class="bar-value">${c}</div></div>`;
        });
        html += '</div>';
    }

    html += '<div class="section"><h3>Stock Analysis</h3>';
    const sa = a.stock_analysis;
    if (sa.total) {
        html += `<div class="kv">${[
            ['Symbols Tracked', sa.total], ['Average Price', sa.avg_price ?? '-']
        ].map(([k, v]) => `<div class="kv-item"><div class="k">${k}</div><div class="v">${fmt(v)}</div></div>`).join('')}</div>`;
        if (sa.gainers.length) {
            html += '<h3 style="margin-top:10px">Top Gainers</h3>';
            sa.gainers.forEach(g => { html += `<div class="note"><b>${esc(g.symbol)}</b> <span class="up">+${fmt(g.change)}</span> @ ${fmt(g.price)}</div>`; });
        }
        if (sa.losers.length) {
            html += '<h3 style="margin-top:10px">Top Losers</h3>';
            sa.losers.forEach(g => { html += `<div class="note"><b>${esc(g.symbol)}</b> <span class="down">${fmt(g.change)}</span> @ ${fmt(g.price)}</div>`; });
        }
        if (sa.volume_leaders.length) {
            html += '<h3 style="margin-top:10px">Volume Leaders</h3>';
            sa.volume_leaders.forEach(g => { html += `<div class="note"><b>${esc(g.symbol)}</b> ${fmt(g.volume)} shares @ ${fmt(g.price)}</div>`; });
        }
    } else {
        html += '<div class="empty">No stock data in this capture</div>';
    }
    html += '</div>';

    html += '<div class="section"><h3>Market Sentiment</h3>';
    const ms = a.market_sentiment;
    if (ms.articles || ms.pdfs_analyzed) {
        html += `<div class="kv">${[
            ['Articles', ms.articles], ['PDFs Analyzed', ms.pdfs_analyzed],
            ['Avg Score', ms.avg_score ?? '-'], ['Market Mood', ms.mood],
            ['Engine', ms.engine]
        ].map(([k, v]) => `<div class="kv-item"><div class="k">${k}</div><div class="v">${fmt(v)}</div></div>`).join('')}</div>`;
        const dist = ms.distribution || {};
        const distTotal = ms.articles + ms.pdfs_analyzed || 1;
        ['Positive', 'Neutral', 'Negative'].forEach(label => {
            const c = dist[label] || 0;
            const pct = Math.round(c / distTotal * 100);
            html += `<div class="bar-row"><div class="bar-label">${label}</div>
                <div class="bar-track"><div class="bar-fill" style="width:${pct}%"></div></div>
                <div class="bar-value">${c}</div></div>`;
        });
        if (ms.symbol_analysis && ms.symbol_analysis.length) {
            html += '<h3 style="margin-top:10px">News Sentiment vs Price</h3>';
            html += '<table><thead><tr><th>Symbol</th><th>Articles</th><th>Avg Sentiment</th><th>Price</th><th>Change</th></tr></thead><tbody>';
            ms.symbol_analysis.forEach(sa => {
                const chgCls = (typeof sa.price_change === 'number') ? (sa.price_change >= 0 ? 'up' : 'down') : '';
                html += `<tr><td><b>${esc(sa.symbol)}</b></td><td>${sa.articles}</td>
                    <td><span class="sent-badge ${sentClass(sa.avg_sentiment > 0.55 ? 'Positive' : (sa.avg_sentiment < 0.45 ? 'Negative' : 'Neutral'))}">${sa.avg_sentiment}</span></td>
                    <td>${fmt(sa.price)}</td><td class="${chgCls}">${fmt(sa.price_change)}</td></tr>`;
            });
            html += '</tbody></table>';
        }
        if (ms.positive_articles.length) {
            html += '<h3 style="margin-top:10px">Most Positive</h3>';
            ms.positive_articles.forEach(n => {
                html += `<div class="note"><span class="sent-badge s-pos">POS</span> ${esc(n.title || '')} — ${fmt(n.sentiment && n.sentiment.score)}</div>`;
            });
        }
        if (ms.negative_articles.length) {
            html += '<h3 style="margin-top:10px">Most Negative</h3>';
            ms.negative_articles.forEach(n => {
                html += `<div class="note"><span class="sent-badge s-neg">NEG</span> ${esc(n.title || '')} — ${fmt(n.sentiment && n.sentiment.score)}</div>`;
            });
        }
    } else {
        html += '<div class="empty">No news/PDF content captured. Use "capture news" then "analyze".</div>';
    }
    html += '</div>';

    html += '<div class="section"><h3>Security Observations</h3>';
    let obs = 0;
    if (a.insecure_http.length) {
        obs++;
        html += `<div class="note"><b>${a.insecure_http.length}</b> endpoint(s) use plain HTTP (no TLS)</div>`;
    }
    if (a.suspicious_parameters.length) {
        obs++;
        html += `<div class="note"><b>${a.suspicious_parameters.length}</b> suspicious parameter name(s): ` +
            a.suspicious_parameters.map(p => `<code>${esc(p)}</code>`).join(', ') + `</div>`;
    }
    if (a.sensitive_endpoints.length) {
        obs++;
        html += `<div class="note"><b>${a.sensitive_endpoints.length}</b> endpoint(s) detected with auth headers/cookies</div>`;
    }
    if (!obs) html += '<div class="note">No immediate security flags detected</div>';
    html += '</div>';

    return html;
}

function openDetail(idx) {
    const [key, ep] = window._eps[idx];
    const parts = key.split(' ');
    const method = parts[0], url = parts.slice(1).join(' ');
    document.getElementById('detail-title').textContent = method + ' ' + url;
    let html = '<div class="section"><h3>Overview</h3><div class="kv">';
    html += `<div class="kv-item"><div class="k">Calls</div><div class="v">${ep.call_count}</div></div>`;
    html += `<div class="kv-item"><div class="k">Auth</div><div class="v">${ep.auth_required ? 'Yes' : 'No'}</div></div>`;
    html += `<div class="kv-item"><div class="k">First Seen</div><div class="v" style="font-size:0.9em">${esc(ep.first_seen)}</div></div>`;
    html += `<div class="kv-item"><div class="k">Last Seen</div><div class="v" style="font-size:0.9em">${esc(ep.last_seen)}</div></div>`;
    html += '</div></div>';

    if (ep.parameters && Object.keys(ep.parameters).length) {
        html += '<div class="section"><h3>Parameters</h3>';
        Object.entries(ep.parameters).forEach(([name, d]) => {
            html += `<div class="note"><b>${esc(name)}</b> (${esc(d.type)})` +
                (d.examples && d.examples.length ? ` — examples: ${d.examples.slice(0,3).map(e => esc(JSON.stringify(e))).join(', ')}` : '') +
                `</div>`;
        });
        html += '</div>';
    }

    if (ep.headers && Object.keys(ep.headers).length) {
        html += '<div class="section"><h3>Headers</h3><pre>' + esc(JSON.stringify(ep.headers, null, 2)) + '</pre></div>';
    }

    if (ep.request_examples && ep.request_examples.length) {
        html += '<div class="section"><h3>Request Examples</h3>';
        ep.request_examples.slice(0, 3).forEach(ex => {
            html += `<pre>${esc(JSON.stringify(ex, null, 2))}</pre>`;
        });
        html += '</div>';
    }

    if (ep.response_examples && ep.response_examples.length) {
        html += '<div class="section"><h3>Response Examples</h3>';
        ep.response_examples.slice(0, 3).forEach(ex => {
            html += `<div class="note">Status <b>${ex.status_code}</b> @ ${esc(ex.timestamp)}</div>`;
        });
        html += '</div>';
    }

    document.getElementById('detail-body').innerHTML = html;
    openModal('detail-modal');
}

function openNews(idx) {
    const n = window._news[idx];
    const sent = n.sentiment || {};
    let html = '<div class="section"><h3>Overview</h3><div class="kv">';
    html += `<div class="kv-item"><div class="k">Source</div><div class="v">${esc(n.source || '-')}</div></div>`;
    html += `<div class="kv-item"><div class="k">Sentiment</div><div class="v"><span class="sent-badge ${sentClass(sent.label)}">${esc(sent.label || 'Neutral')} (${fmt(sent.score)})</span></div></div>`;
    html += `<div class="kv-item"><div class="k">Published</div><div class="v" style="font-size:0.9em">${esc(n.published || 'Unknown')}</div></div>`;
    html += `<div class="kv-item"><div class="k">Symbols</div><div class="v">${esc((n.symbols || []).join(', ') || 'None')}</div></div>`;
    html += '</div></div>';
    html += '<div class="section"><h3>Title</h3><div class="note"><b>' + esc(n.title || '') + '</b></div></div>';
    html += '<div class="section"><h3>Content</h3><pre style="max-height:400px">' + esc(n.text || '') + '</pre></div>';
    html += '<div class="section"><h3>Source URL</h3><div class="note">' + esc(n.url || '') + '</div></div>';
    document.getElementById('news-body').innerHTML = html;
    openModal('news-modal');
}

document.addEventListener('keydown', e => {
    if (e.key === 'Escape') {
        closeModal('analysis-modal');
        closeModal('detail-modal');
        closeModal('news-modal');
    }
});

refreshAll();
</script>
</body>
</html>
"""


def main():
    parser = argparse.ArgumentParser(description='API Capture Dashboard')
    parser.add_argument('--file', help='JSON capture file to serve')
    parser.add_argument('--port', type=int, default=5000)
    args = parser.parse_args()

    global DATA_FILE, LIVE_FILE

    if args.file:
        DATA_FILE = args.file
    else:
        captures_dir = Path('api_captures')
        files = sorted(captures_dir.glob('api_capture_*.json'), key=lambda p: p.stat().st_mtime, reverse=True)
        if files:
            DATA_FILE = str(files[0])
        else:
            print("[!] No capture files found in api_captures/. Use --file to specify one.")
            return 1

    LIVE_FILE = os.path.join('api_captures', '_live.json') if os.path.exists(os.path.join('api_captures', '_live.json')) else None

    print(f"[*] Serving: {LIVE_FILE or DATA_FILE}")
    print(f"[*] Dashboard: http://127.0.0.1:{args.port}")
    app.run(host='127.0.0.1', port=args.port)


if __name__ == '__main__':
    main()