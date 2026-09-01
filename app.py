#!/usr/bin/env python3
"""
API Capture Framework - Interactive Console Application
Metasploit-like framework for API endpoint discovery and security analysis

Author: Security Development Team
Version: 1.0.0
"""

import json
import time
import logging
import argparse
import cmd
import sys
import os
import shlex
import subprocess
import webbrowser
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple
from urllib.parse import urlparse, parse_qs, urlencode, urljoin
import hashlib
import re
from colorama import init, Fore, Back, Style

# Initialize colorama for cross-platform colored output
init(autoreset=True)

try:
    from selenium import webdriver
    from selenium.webdriver.common.by import By
    from selenium.webdriver.support.ui import WebDriverWait
    from selenium.webdriver.support import expected_conditions as EC
    from selenium.webdriver.chrome.options import Options
    from selenium.common.exceptions import WebDriverException, TimeoutException
    SELENIUM_AVAILABLE = True
except ImportError:
    SELENIUM_AVAILABLE = False

try:
    import requests
    from requests.packages.urllib3.exceptions import InsecureRequestWarning
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False

try:
    from pypdf import PdfReader
    PDF_AVAILABLE = True
except ImportError:
    PDF_AVAILABLE = False

try:
    import trafilatura
    TRAFILATURA_AVAILABLE = True
except ImportError:
    TRAFILATURA_AVAILABLE = False

try:
    from transformers import pipeline
    TRANSFORMERS_AVAILABLE = True
except ImportError:
    TRANSFORMERS_AVAILABLE = False

# --- Optional crawling engines: Firecrawl + Apify + Crawl4AI ---
try:
    from firecrawl import FirecrawlApp
    FIRECRAWL_AVAILABLE = True
except ImportError:
    FirecrawlApp = None
    FIRECRAWL_AVAILABLE = False

try:
    from apify_client import ApifyClient
    APIFY_AVAILABLE = True
except ImportError:
    ApifyClient = None
    APIFY_AVAILABLE = False

try:
    from crawl4ai import AsyncWebCrawler  # type: ignore
    CRAWL4AI_AVAILABLE = True
except ImportError:
    AsyncWebCrawler = None
    CRAWL4AI_AVAILABLE = False

# CSE target URLs (requested by user)
CSE_PRESS_RELEASES_URL = "https://www.cse.lk/news-events/press-releases"
CSE_ANNUAL_REPORTS_URL = "https://www.cse.lk/about-us/corporate-profile/annual-reports"
CSE_PRESS_API = "https://www.cse.lk/api/news/web?top=false&type=CN"
CSE_CDN_BASE = "https://cdn.cse.lk/"


FINANCIAL_CRAWLERS = {
    'yfinance': {'name': 'yfinance', 'type': 'Financial Data', 'description': 'Yahoo Finance data scraper',
                 'install': 'pip install yfinance', 'features': ['stock data', 'historical', 'fundamentals']},
    'alpha_vantage': {'name': 'Alpha Vantage', 'type': 'API', 'description': 'Free stock API',
                      'install': 'pip install alpha_vantage', 'features': ['real-time', 'historical', 'technical indicators']},
    'stocknews': {'name': 'StockNews', 'type': 'News Scraper', 'description': 'Stock news aggregation',
                  'install': 'pip install stocknews', 'features': ['news scraping', 'sentiment', 'aggregation']},
    'finviz': {'name': 'FinViz', 'type': 'Screeners', 'description': 'Stock screeners and data',
               'install': 'pip install finviz', 'features': ['screener', 'news', 'charts']},
    'investpy': {'name': 'InvestPy', 'type': 'Financial Data', 'description': 'Investing.com data scraper',
                 'install': 'pip install investpy', 'features': ['stocks', 'bonds', 'commodities']},
    'ta': {'name': 'Technical Analysis', 'type': 'Indicators', 'description': 'Technical analysis library',
           'install': 'pip install ta', 'features': ['indicators', 'patterns', 'signals']},
}

AI_CRAWLERS = {
    'scrapy': {'name': 'Scrapy', 'type': 'Framework', 'description': 'Powerful web scraping framework',
               'install': 'pip install scrapy', 'features': ['asynchronous', 'middleware', 'pipelines', 'extensible']},
    'crawl4ai': {'name': 'Crawl4AI', 'type': 'AI-Powered', 'description': 'AI-powered web crawler with LLM integration',
                 'install': 'pip install crawl4ai', 'features': ['AI extraction', 'LLM integration', 'automatic parsing']},
    'firecrawl': {'name': 'Firecrawl', 'type': 'AI-Powered', 'description': 'AI web scraping API',
                  'install': 'pip install firecrawl-py', 'features': ['AI extraction', 'API', 'scalable']},
    'apify': {'name': 'Apify', 'type': 'AI-Powered', 'description': 'Apify cloud crawling platform (website-content-crawler)',
              'install': 'pip install apify-client', 'features': ['cloud', 'actors', 'proxy', 'scalable']},
    'trafilatura': {'name': 'Trafilatura', 'type': 'Content Extraction', 'description': 'Extract main content from web pages',
                    'install': 'pip install trafilatura', 'features': ['content extraction', 'metadata', 'fast']},
    'newspaper3k': {'name': 'Newspaper3k', 'type': 'News Scraper', 'description': 'Article scraping and curation',
                    'install': 'pip install newspaper3k', 'features': ['article extraction', 'NLP', 'multilingual']},
    'autoscraper': {'name': 'AutoScraper', 'type': 'AI-Powered', 'description': 'Smart web scraping with auto-pattern detection',
                    'install': 'pip install autoscraper', 'features': ['auto-pattern', 'minimal setup', 'smart extraction']},
    'playwright': {'name': 'Playwright', 'type': 'Browser Automation', 'description': 'Modern browser automation',
                   'install': 'pip install playwright', 'features': ['multi-browser', 'auto-wait', 'network interception']},
}

CSE_ENGINES = {
    'firecrawl': {'name': 'Firecrawl', 'available': lambda: FIRECRAWL_AVAILABLE, 'env_key': 'FIRECRAWL_API_KEY'},
    'apify': {'name': 'Apify', 'available': lambda: APIFY_AVAILABLE, 'env_key': 'APIFY_TOKEN'},
    'crawl4ai': {'name': 'Crawl4AI', 'available': lambda: CRAWL4AI_AVAILABLE, 'env_key': None},
    'selenium': {'name': 'Selenium', 'available': lambda: SELENIUM_AVAILABLE, 'env_key': None},
    'requests': {'name': 'Requests/API', 'available': lambda: REQUESTS_AVAILABLE, 'env_key': None},
}

# Known annual-report PDFs as fallback (discovered 2025-08-10 via selenium probe)
CSE_ANNUAL_REPORTS_FALLBACK = [
    ("2025", "https://cdn.cse.lk/pdf/annual-reports/Annual-Report-2025.pdf"),
    ("2024", "https://cdn.cse.lk/pdf/annual-reports/Annual-Report-2024.pdf"),
    ("2023", "https://cdn.cse.lk/pdf/annual-reports/Annual-Report-2023.pdf"),
    ("2022", "https://cdn.cse.lk/pdf/annual-reports/Annual-Report-2022.pdf"),
    ("2021", "https://cdn.cse.lk/pdf/annual-reports/Annual-Report-2021.pdf"),
    ("2020", "https://cdn.cse.lk/pdf/annual-reports/Annual-Report-2020.pdf"),
    ("2019", "https://cdn.cse.lk/pdf/annual-reports/CSE_Annual_Report_2019.pdf"),
    ("2018", "https://cdn.cse.lk/pdf/CSE_Annual_Report_2018.pdf"),
    ("2017", "https://cdn.cse.lk/pdf/CSE_Annual_Report_2017.pdf"),
    ("2016", "https://cdn.cse.lk/pdf/CSE_Annual_Report_2016.pdf"),
    ("2015", "https://cdn.cse.lk/pdf/CSE_Annual_Report_2015.pdf"),
    ("2014", "https://cdn.cse.lk/pdf/CSE_Annual_Report_2014.pdf"),
    ("2013", "https://cdn.cse.lk/pdf/CSE_Annual_Report_2013.pdf"),
    ("2012", "https://cdn.cse.lk/pdf/CSE_Annual_Report_2012.pdf"),
    ("2011", "https://cdn.cse.lk/pdf/CSE_Annual_Report_2011.pdf"),
    ("2010", "https://cdn.cse.lk/pdf/CSE_Annual_Report_2010.pdf"),
]

SENTIMENT_MODELS = {
    'finbert': 'ProsusAI/finbert',
    'finbert_tone': 'yiyanghkust/finbert-tone',
    'finbert_fls': 'yiyanghkust/finbert-fls',
    'financial_phrasebank': 'ahmedrachid/FinancialBERT-Sentiment-Analysis',
    'stockbert': 'peterkros/stockbert',
    'stock_news': 'mrm8488/stock-news-distilbert-roberta',
    'market_sentiment': 'nickmuchi/finbert-classification',
    'sec_bert': 'nlpaueb/sec-bert-base',
    'sinhala_tamil': 'xlm-roberta-base',
    'multilingual_bert': 'bert-base-multilingual-uncased',
    'indic_bert': 'ai4bharat/indic-bert',
    'emerging_markets': 'gtfintechlab/FinBERT',
    'finbert_esg': 'yiyanghkust/finbert-esg',
}

CSE_RECOMMENDED_MODELS = {
    'primary_sentiment': 'ProsusAI/finbert',
    'phrase_sentiment': 'ahmedrachid/FinancialBERT-Sentiment-Analysis',
    'stock_prediction': 'peterkros/stockbert',
    'sinhala_tamil': 'xlm-roberta-base',
    'esg_analysis': 'yiyanghkust/finbert-esg',
    'forward_looking': 'yiyanghkust/finbert-fls',
}

FIN_POSITIVE = {
    'gain', 'gains', 'gained', 'profit', 'profits', 'profitable', 'earnings', 'beat', 'beats',
    'upbeat', 'growth', 'grow', 'growing', 'rise', 'rises', 'rose', 'rising', 'rally', 'rallying',
    'surge', 'surges', 'surged', 'jump', 'jumps', 'jumped', 'increase', 'increases', 'increased',
    'boost', 'boosts', 'boosted', 'strong', 'stronger', 'strengthen', 'recover', 'recovery',
    'rebound', 'record', 'high', 'higher', 'highest', 'outperform', 'outperformed', 'upgrade',
    'upgraded', 'bullish', 'buy', 'positive', 'good', 'improve', 'improved', 'improvement',
    'dividend', 'dividends', 'expansion', 'expands', 'launch', 'new', 'win', 'wins', 'won',
    'award', 'awarded', 'success', 'successful', 'optimistic', 'outlook', 'momentum', 'resilient',
    'solid', 'robust', 'healthy', 'impressive', 'exceed', 'exceeded', 'above', 'target',
}

FIN_NEGATIVE = {
    'loss', 'losses', 'lost', 'decline', 'declines', 'declined', 'drop', 'drops', 'dropped',
    'fall', 'falls', 'fell', 'falling', 'slump', 'slumps', 'slumped', 'plunge', 'plunges',
    'plunged', 'tumble', 'tumbles', 'tumbled', 'slide', 'slides', 'slid', 'weaken', 'weakened',
    'weak', 'weaker', 'weakness', 'downgrade', 'downgraded', 'sell', 'bearish', 'negative',
    'poor', 'bad', 'worse', 'worst', 'cut', 'cuts', 'slashed', 'miss', 'misses', 'missed',
    'below', 'underperform', 'underperformed', 'risk', 'risks', 'uncertainty', 'concern',
    'concerns', 'worried', 'worry', 'fear', 'fears', 'crisis', 'bankrupt', 'bankruptcy',
    'default', 'defaults', 'debt', 'liability', 'lawsuit', 'fraud', 'penalty', 'penalized',
    'investigation', 'probe', 'shortfall', 'shed', 'sheds', 'erode', 'erodes', 'eroded',
    'pressure', 'pressured', 'struggle', 'struggles', 'struggled', 'stagnant', 'halt', 'halts',
    'halted', 'suspend', 'suspended',
}


STOCK_URL_PATTERNS = [
    r'/equit', r'/quote', r'/stock', r'/share', r'/price', r'/market',
    r'/ticker', r'/company', r'/listed', r'/security', r'/instrument',
    r'price-list', r'market-data', r'trade-summary', r'/data\.json'
]

STOCK_SYMBOL_RE = re.compile(r'(?:symbol|ticker|code)[=:/]([A-Z]{2,6})', re.IGNORECASE)

STOCK_COLUMN_ALIASES = {
    'symbol': ['symbol', 'ticker', 'code', 'security', 'scrip', 'company code'],
    'company': ['company', 'name', 'security name', 'company name', 'issuer'],
    'price': ['price', 'last price', 'last traded', 'last traded price', 'last', 'close',
              'closing price', 'ltp', 'ltdp', 'market price'],
    'change': ['change', 'chg', '+/-', 'price change', 'change %', 'change%', 'diff'],
    'volume': ['volume', 'vol', 'turnover', 'traded volume', 'no. of shares', 'shares traded', 'qty'],
    'high': ['high', 'day high', '52w high', 'high price'],
    'low': ['low', 'day low', '52w low', 'low price'],
    'open': ['open', 'opening price'],
    'previous_close': ['previous close', 'prev close', 'previous', 'prev'],
}

STOCK_VALUE_KEYS = ['price', 'last', 'last_price', 'ltp', 'ltdp', 'close', 'current_price',
                    'volume', 'vol', 'turnover', 'change', 'high', 'low', 'open']


class Colors:
    """Color scheme for the console application"""
    PROMPT = Fore.GREEN + Style.BRIGHT
    INFO = Fore.CYAN
    SUCCESS = Fore.GREEN
    WARNING = Fore.YELLOW
    ERROR = Fore.RED
    CRITICAL = Fore.RED + Style.BRIGHT
    HEADER = Fore.MAGENTA + Style.BRIGHT
    BANNER = Fore.CYAN + Style.BRIGHT
    PARAM = Fore.YELLOW
    VALUE = Fore.WHITE
    METHOD_GET = Fore.GREEN
    METHOD_POST = Fore.YELLOW
    METHOD_PUT = Fore.BLUE
    METHOD_DELETE = Fore.RED
    METHOD_OTHER = Fore.MAGENTA
    RESET = Style.RESET_ALL


class SentimentAnalyzer:
    """Financial sentiment analysis engine.
    Uses FinBERT (ProsusAI/finbert) via transformers when available,
    falls back to a financial lexicon scorer."""
    
    def __init__(self):
        self.engine = 'lexicon'
        self._pipe = None
        if TRANSFORMERS_AVAILABLE:
            try:
                self._pipe = pipeline('sentiment-analysis', model=CSE_RECOMMENDED_MODELS['primary_sentiment'])
                self.engine = 'finbert'
            except Exception:
                self._pipe = None
    
    def analyze(self, text: str) -> Dict:
        """Analyze text sentiment -> {'label', 'score', 'engine'}"""
        text = (text or '').strip()
        if len(text) < 20:
            return {'label': 'Neutral', 'score': 0.5, 'engine': self.engine}
        
        if self._pipe:
            try:
                result = self._pipe(text[:512])[0]
                label = str(result.get('label', ''))
                if label.lower() in ('positive', 'negative'):
                    return {'label': label.capitalize(), 'score': round(float(result.get('score', 0.5)), 4), 'engine': 'finbert'}
            except Exception:
                pass
        
        words = re.findall(r"[a-z']+", text.lower())
        pos = sum(1 for w in words if w in FIN_POSITIVE)
        neg = sum(1 for w in words if w in FIN_NEGATIVE)
        total = pos + neg
        
        if total == 0:
            return {'label': 'Neutral', 'score': 0.5, 'engine': 'lexicon'}
        
        ratio = pos / total
        label = 'Positive' if ratio >= 0.6 else ('Negative' if ratio <= 0.4 else 'Neutral')
        return {'label': label, 'score': round(ratio, 4), 'engine': 'lexicon'}


class NewsCrawler:
    """AI-assisted crawler for Sri Lankan financial news sources"""
    
    def __init__(self):
        self.sources = {
            'daily_ft': ('https://www.ft.lk/', 'Daily FT'),
            'daily_mirror': ('https://www.dailymirror.lk/', 'Daily Mirror'),
            'lbo': ('https://www.lankabusinessonline.com/', 'LBO'),
            'adaderana': ('https://adaderana.lk/business/', 'Ada Derana'),
            'cse_official': ('https://www.cse.lk/', 'CSE Official'),
        }
        self.headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
        self.sentiment = SentimentAnalyzer()
    
    def crawl(self, store, max_articles: int = 40, source_filter: str = None) -> int:
        """Crawl news sources, extract articles, run sentiment analysis"""
        if not (TRAFILATURA_AVAILABLE and REQUESTS_AVAILABLE):
            print(f"{Colors.ERROR}[-] trafilatura and requests are required for news crawling{Colors.RESET}")
            return 0
        
        selected = {k: v for k, v in self.sources.items()
                    if not source_filter or source_filter == k}
        
        total = 0
        for key, (source_url, source_name) in selected.items():
            print(f"{Colors.INFO}[*] Crawling {source_name} ({source_url}){Colors.RESET}")
            try:
                resp = requests.get(source_url, timeout=25, headers=self.headers, verify=False)
                if resp.status_code != 200:
                    print(f"{Colors.WARNING}[!] {source_name}: HTTP {resp.status_code}{Colors.RESET}")
                    continue
                
                links = self._get_article_links(resp.text, source_url, store)
                collected = 0
                
                for link in links:
                    if total >= max_articles:
                        break
                    try:
                        article = self._fetch_article(link, key, source_name, store)
                        if article:
                            store.add_news(article)
                            total += 1
                            collected += 1
                            print(f"{Colors.SUCCESS}[+] {source_name}: {article['title'][:70]}{Colors.RESET}")
                    except Exception:
                        continue
                
                if not collected:
                    print(f"{Colors.WARNING}[!] {source_name}: no articles extracted{Colors.RESET}")
            except Exception as e:
                print(f"{Colors.ERROR}[-] {source_name} failed: {e}{Colors.RESET}")
                continue
        
        print(f"{Colors.SUCCESS}[+] News crawl complete: {total} articles captured, "
              f"sentiment engine: {self.sentiment.engine}{Colors.RESET}")
        return total
    
    def _get_article_links(self, html: str, base_url: str, store) -> List[str]:
        """Extract article links from a news listing page"""
        links = []
        base_domain = urlparse(base_url).netloc
        pattern = re.compile(r'<a[^>]+href=["\']([^"\']+)["\']', re.IGNORECASE)
        junk_segments = ('all', 'privacy', 'newsletter', 'email-disclaimer', 'mobile-apps',
                         'about', 'about-us', 'contact', 'contact-us', 'terms', 'terms-of-use',
                         'conditions', 'login', 'register', 'search', 'sitemap', 'faq',
                         'careers', 'advertising', 'subscription', 'cookies', 'cookie-policy',
                         'policy', 'team', 'mission', 'advertise', 'subscribe')
        
        try:
            for href in pattern.findall(html):
                href = href.strip()
                if href.startswith(('javascript:', 'mailto:', 'tel:', '#')):
                    continue
                
                parsed = urlparse(href)
                if not parsed.netloc:
                    href = urljoin(base_url, href)
                    parsed = urlparse(href)
                
                if parsed.netloc != base_domain and not parsed.netloc.endswith('.' + base_domain):
                    continue
                if any(skip in href.lower() for skip in ('.pdf', '/tag/', '/category/', '/author/', '/print', '?amp')):
                    continue
                if parsed.path in ('/', ''):
                    continue
                
                segments = [s for s in parsed.path.split('/') if s]
                if any(seg.lower() in junk_segments or any(seg.lower().startswith(j + '-') for j in junk_segments) for seg in segments):
                    continue
                if len(segments) == 1 and not re.search(r'\d', parsed.path) and len(segments[0]) <= 20:
                    continue
                
                links.append(href.split('#')[0].rstrip('/'))
        except Exception:
            pass
        return list(dict.fromkeys(links))[:40]
    
    def _fetch_article(self, url: str, source_key: str, source_name: str, store) -> Optional[Dict]:
        """Fetch and analyze a single article"""
        resp = requests.get(url, timeout=25, headers=self.headers, verify=False)
        if resp.status_code != 200:
            return None
        
        text = trafilatura.extract(resp.text, url=url, include_comments=False, output_format='txt') or ''
        if len(text) < 80:
            return None
        
        title = url
        date = None
        try:
            meta = trafilatura.extract_metadata(resp.text, url=url)
            if meta:
                title = meta.title or title
                date = meta.date
        except Exception:
            pass
        
        full_text = (title + '. ' + text)[:5000]
        return {
            'url': url,
            'source': source_name,
            'source_key': source_key,
            'title': title[:200],
            'published': date,
            'text': text[:5000],
            'sentiment': self.sentiment.analyze(full_text[:2000]),
            'symbols': self._detect_symbols(full_text, store),
            'captured_at': datetime.now().isoformat(),
        }
    
    def _detect_symbols(self, text: str, store) -> List[str]:
        """Detect CSE symbols mentioned in an article"""
        found = set()
        text_upper = text.upper()
        
        for sym in store.stock_records:
            if re.search(rf'\b{re.escape(sym)}\b', text_upper):
                found.add(sym)
        
        for match in re.finditer(r'\b([A-Z]{2,6})\.N\d{4}\b', text_upper):
            found.add(match.group(1))
        
        return sorted(found)


# ==================== CSE PDF / Document Helpers ====================

class CSEPDFProcessor:
    """Download a PDF and extract full text + structured data + sentiment"""

    def __init__(self, sentiment: Optional[SentimentAnalyzer] = None):
        self.sentiment = sentiment or SentimentAnalyzer()
        self.headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}

    def download_and_extract(self, pdf_url: str, dest_dir: str, doc_type: str = "press_release",
                             metadata: Optional[Dict] = None, store: Any = None) -> Optional[Dict]:
        """Download PDF, extract text (all pages), run sentiment, store via APIStore.add_pdf.
        Returns the pdf record dict or None on failure."""
        if not REQUESTS_AVAILABLE:
            print(f"{Colors.ERROR}[-] requests required for PDF download{Colors.RESET}")
            return None
        metadata = metadata or {}
        os.makedirs(dest_dir, exist_ok=True)
        # sanitize filename
        parsed = urlparse(pdf_url)
        raw_name = os.path.basename(parsed.path) or f"doc_{abs(hash(pdf_url))}.pdf"
        # prefix with doc_type / date for uniqueness
        safe_name = re.sub(r'[^A-Za-z0-9._-]', '_', raw_name)
        if doc_type == "annual_report" and metadata.get("year"):
            safe_name = f"{metadata['year']}_{safe_name}"
        elif doc_type == "press_release" and metadata.get("id"):
            safe_name = f"{metadata['id'][:8]}_{safe_name}"
        filepath = os.path.join(dest_dir, safe_name)

        # skip if already downloaded and store has it
        if os.path.exists(filepath) and os.path.getsize(filepath) > 1024:
            # still try to extract if not already in store
            pass
        else:
            try:
                resp = requests.get(pdf_url, timeout=60, headers=self.headers, verify=False)
                if resp.status_code != 200:
                    print(f"{Colors.WARNING}[!] PDF HTTP {resp.status_code}: {pdf_url[:90]}{Colors.RESET}")
                    return None
                ctype = resp.headers.get('Content-Type', '')
                if 'pdf' not in ctype.lower() and not resp.content.startswith(b'%PDF'):
                    # fallback: check if url is redirect to pdf
                    if len(resp.content) < 500:
                        print(f"{Colors.WARNING}[!] Not a PDF (ctype {ctype}): {pdf_url[:80]}{Colors.RESET}")
                        return None
                with open(filepath, 'wb') as f:
                    f.write(resp.content)
                print(f"{Colors.SUCCESS}[+] Downloaded [{doc_type}] {safe_name} ({len(resp.content)//1024} KB){Colors.RESET}")
            except Exception as e:
                print(f"{Colors.ERROR}[-] PDF download failed {pdf_url[:80]}: {e}{Colors.RESET}")
                return None

        text_full = ""
        text_preview = ""
        page_count = 0
        tables_text = ""
        financial_entities: Dict[str, Any] = {}

        if PDF_AVAILABLE:
            try:
                reader = PdfReader(filepath)
                page_count = len(reader.pages)
                parts = []
                for i, page in enumerate(reader.pages):
                    try:
                        txt = page.extract_text() or ""
                        parts.append(txt)
                    except Exception:
                        continue
                text_full = "\n".join(parts).strip()
                text_preview = text_full[:3000]
                # structured extractions
                financial_entities = self._extract_financial_entities(text_full)
                # quick table-like detection: lines with many numbers
                if len(text_full) > 100:
                    snippet = text_full[:8000]
                    financial_entities['snippet'] = snippet[:2000]
                print(f"{Colors.SUCCESS}[+] Extracted {page_count} pages, {len(text_full)} chars from {safe_name}{Colors.RESET}")
            except Exception as e:
                print(f"{Colors.WARNING}[!] PDF text extraction failed {safe_name}: {e}{Colors.RESET}")
                text_preview = metadata.get('title', '') or ""
        else:
            text_preview = metadata.get('title', '') or ""
            print(f"{Colors.WARNING}[!] pypdf not available, skipping text extraction for {safe_name}{Colors.RESET}")

        # sentiment on full text (first 5000 chars)
        sentiment_result = self.sentiment.analyze((text_full or text_preview or metadata.get('title',''))[:4000])
        # detect symbols in pdf text
        symbols = []
        if store is not None:
            try:
                # reuse NewsCrawler symbol detection logic
                dummy = NewsCrawler()
                symbols = dummy._detect_symbols(text_full[:5000], store)
            except Exception:
                pass

        # Build record
        record = {
            'url': pdf_url,
            'filepath': filepath,
            'page_count': page_count,
            'text_preview': text_preview[:5000],
            'text_full': text_full[:30000],  # cap for JSON size
            'captured_at': datetime.now().isoformat(),
            'doc_type': doc_type,
            'title': metadata.get('title', raw_name),
            'publishedDate': metadata.get('publishedDate'),
            'year': metadata.get('year'),
            'month': metadata.get('month'),
            'id': metadata.get('id'),
            'sentiment': sentiment_result,
            'symbols': symbols,
            'financial_entities': financial_entities,
            'source_url': metadata.get('source_url'),
        }

        if store is not None:
            store.add_pdf(pdf_url, filepath, text_preview, page_count, extra=record)
            # also register as visited page for stats
            if pdf_url not in store.pages_visited:
                store.pages_visited.append(pdf_url)

        return record

    def _extract_financial_entities(self, text: str) -> Dict[str, Any]:
        """Lightweight financial KPI extraction from PDF text"""
        if not text:
            return {}
        entities: Dict[str, Any] = {}
        # Dates
        dates = re.findall(r'\b(?:20\d{2}[-/]\d{1,2}[-/]\d{1,2}|\d{1,2}[-/]\d{1,2}[-/]20\d{2}|January|February|March|April|May|June|July|August|September|October|November|December)\b[^.]{0,30}', text, re.I)
        if dates:
            entities['dates'] = dates[:5]
        # LKR amounts
        lkr = re.findall(r'LKR\s*[\d,]+(?:\.\d+)?\s*(?:Bn|Mn|billion|million)?', text, re.I)
        if lkr:
            entities['lkr_amounts'] = lkr[:10]
        # Revenue / Profit lines
        for kw in ['Revenue', 'Profit', 'Loss', 'Dividend', 'EPS', 'Assets', 'Liabilities', 'Equity', 'Turnover', 'Market Cap', 'ASPI', 'S&P SL20']:
            m = re.search(rf'{kw}[^\n]{{0,80}}', text, re.I)
            if m:
                entities[kw.lower().replace(' ', '_').replace('&','and')] = m.group(0).strip()[:200]
        # Year detection
        years = re.findall(r'\b(20[0-2]\d)\b', text)
        if years:
            c = {}
            for y in years:
                c[y] = c.get(y, 0) + 1
            entities['year_mentions'] = dict(sorted(c.items(), key=lambda x: -x[1])[:5])
        # Table count heuristic
        table_lines = [l for l in text.splitlines() if re.search(r'\d[\d,]*\s+\d[\d,]*', l)]
        if table_lines:
            entities['table_rows_detected'] = len(table_lines)
        return entities


class CSEEngine:
    """Unified multi-engine fetcher for CSE pages (Firecrawl, Apify, Crawl4AI, Selenium, Requests)"""

    def __init__(self):
        self.headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
        self.sentiment = SentimentAnalyzer()

    # -- Firecrawl --
    def fetch_via_firecrawl(self, url: str) -> Optional[str]:
        if not FIRECRAWL_AVAILABLE:
            return None
        api_key = os.environ.get('FIRECRAWL_API_KEY') or os.environ.get('FIRECRAWL_API_TOKEN')
        if not api_key:
            print(f"{Colors.WARNING}[!] Firecrawl: FIRECRAWL_API_KEY not set, skipping{Colors.RESET}")
            return None
        try:
            app = FirecrawlApp(api_key=api_key)
            print(f"{Colors.INFO}[*] Firecrawl scraping: {url}{Colors.RESET}")
            result = app.scrape_url(url, params={'formats': ['markdown', 'html']})
            # SDK returns dict or object
            if isinstance(result, dict):
                return result.get('markdown') or result.get('html') or result.get('content') or json.dumps(result)[:10000]
            return getattr(result, 'markdown', None) or getattr(result, 'html', None) or str(result)[:10000]
        except Exception as e:
            print(f"{Colors.WARNING}[!] Firecrawl failed: {e}{Colors.RESET}")
            return None

    # -- Apify --
    def fetch_via_apify(self, url: str) -> Optional[str]:
        if not APIFY_AVAILABLE:
            return None
        token = os.environ.get('APIFY_TOKEN') or os.environ.get('APIFY_API_TOKEN')
        if not token:
            print(f"{Colors.WARNING}[!] Apify: APIFY_TOKEN not set, skipping{Colors.RESET}")
            return None
        try:
            client = ApifyClient(token)
            print(f"{Colors.INFO}[*] Apify crawling: {url}{Colors.RESET}")
            run_input = {
                "startUrls": [{"url": url}],
                "maxCrawlPages": 1,
                "crawlerType": "cheerio",
                "includeUrlGlobs": [],
                "excludeUrlGlobs": [],
            }
            # Use website-content-crawler actor
            run = client.actor("apify/website-content-crawler").call(run_input=run_input)
            dataset_id = run.get('defaultDatasetId')
            if not dataset_id:
                return None
            items = list(client.dataset(dataset_id).iterate_items())
            if items:
                return items[0].get('markdown') or items[0].get('html') or items[0].get('text') or json.dumps(items[0])[:10000]
            return None
        except Exception as e:
            print(f"{Colors.WARNING}[!] Apify failed: {e}{Colors.RESET}")
            return None

    # -- Crawl4AI --
    def fetch_via_crawl4ai(self, url: str) -> Optional[str]:
        if not CRAWL4AI_AVAILABLE:
            return None
        try:
            import asyncio

            async def _crawl():
                async with AsyncWebCrawler(verbose=False) as crawler:  # type: ignore
                    result = await crawler.arun(url=url)
                    return getattr(result, 'markdown', None) or getattr(result, 'html', None) or getattr(result, 'cleaned_html', None) or getattr(result, 'content', None)

            print(f"{Colors.INFO}[*] Crawl4AI crawling: {url}{Colors.RESET}")
            try:
                loop = asyncio.get_event_loop()
                if loop.is_closed():
                    raise RuntimeError
                html = loop.run_until_complete(_crawl())
            except RuntimeError:
                html = asyncio.run(_crawl())
            return html[:20000] if html else None
        except Exception as e:
            print(f"{Colors.WARNING}[!] Crawl4AI failed: {e}{Colors.RESET}")
            return None

    # -- Selenium fallback --
    def fetch_via_selenium(self, url: str, wait: int = 7) -> Optional[str]:
        if not SELENIUM_AVAILABLE:
            return None
        try:
            from selenium.webdriver.chrome.options import Options
            opts = Options()
            opts.add_argument('--headless=new')
            opts.add_argument('--no-sandbox')
            opts.add_argument('--disable-dev-shm-usage')
            opts.add_argument('--ignore-certificate-errors')
            driver = webdriver.Chrome(options=opts)
            try:
                print(f"{Colors.INFO}[*] Selenium crawling: {url}{Colors.RESET}")
                driver.get(url)
                time.sleep(wait)
                # scroll to trigger lazy load
                driver.execute_script("window.scrollTo(0, document.body.scrollHeight);")
                time.sleep(1.5)
                html = driver.page_source
                return html
            finally:
                driver.quit()
        except Exception as e:
            print(f"{Colors.WARNING}[!] Selenium failed: {e}{Colors.RESET}")
            return None

    def fetch_with_fallback(self, url: str, order: Optional[List[str]] = None) -> Tuple[Optional[str], str]:
        """Try engines in order; returns (html, engine_name)"""
        if order is None:
            order = ['firecrawl', 'apify', 'crawl4ai', 'selenium', 'requests']
        for eng in order:
            html = None
            if eng == 'firecrawl':
                html = self.fetch_via_firecrawl(url)
            elif eng == 'apify':
                html = self.fetch_via_apify(url)
            elif eng == 'crawl4ai':
                html = self.fetch_via_crawl4ai(url)
            elif eng == 'selenium':
                html = self.fetch_via_selenium(url)
            elif eng == 'requests':
                try:
                    print(f"{Colors.INFO}[*] Requests fetching: {url}{Colors.RESET}")
                    r = requests.get(url, timeout=25, headers=self.headers, verify=False)
                    if r.status_code == 200:
                        html = r.text
                except Exception as e:
                    print(f"{Colors.WARNING}[!] Requests failed: {e}{Colors.RESET}")
            if html and len(html) > 500:
                print(f"{Colors.SUCCESS}[+] Fetched via {eng}: {len(html)} chars{Colors.RESET}")
                return html, eng
        return None, "none"


class CSEPressReleasesCrawler:
    """Crawl ALL CSE press releases (via API + fallback) and download PDFs with extraction"""

    def __init__(self):
        self.engine = CSEEngine()
        self.pdf_proc = CSEPDFProcessor()
        self.headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}

    def crawl(self, store, download_pdfs: bool = True, max_items: int = 0,
              engine_order: Optional[List[str]] = None, pdf_dir: str = "api_captures/pdfs/press_releases") -> int:
        """Fetch all press releases from CSE API, optionally download PDFs.
        engine_order: priority for HTML fallback crawl (if API fails).
        Returns number of press releases discovered."""
        print(f"{Colors.HEADER}=== CSE Press Releases — Reading ALL Releases ==={Colors.RESET}")
        print(f"{Colors.INFO}[*] Engine priority: Firecrawl -> Apify -> Crawl4AI -> Selenium -> Requests/API{Colors.RESET}")
        releases = []
        # Primary: direct API (fastest, complete, no JS needed)
        api_releases = self._fetch_via_api(store)
        if api_releases:
            releases = api_releases
            print(f"{Colors.SUCCESS}[+] API discovered {len(releases)} press releases (all months){Colors.RESET}")
        else:
            print(f"{Colors.WARNING}[!] API fetch failed, falling back to HTML engines for {CSE_PRESS_RELEASES_URL}{Colors.RESET}")
            html, used = self.engine.fetch_with_fallback(CSE_PRESS_RELEASES_URL, order=engine_order)
            if html:
                releases = self._parse_html_releases(html, CSE_PRESS_RELEASES_URL)
                print(f"{Colors.SUCCESS}[+] HTML ({used}) discovered {len(releases)} releases{Colors.RESET}")

        if not releases:
            print(f"{Colors.ERROR}[-] No press releases found{Colors.RESET}")
            return 0

        if max_items and max_items > 0:
            releases = releases[:max_items]

        # Download PDFs
        count_pdfs = 0
        for idx, rel in enumerate(releases, 1):
            print(f"{Colors.INFO}[*] ({idx}/{len(releases)}) {rel.get('title','')[:75]} | {rel.get('publishedDate','')} {Colors.RESET}")
            # mark page visited for stats
            if CSE_PRESS_RELEASES_URL not in store.pages_visited:
                store.pages_visited.append(CSE_PRESS_RELEASES_URL)
            # dedup: add as news article as well for sentiment cross-analysis
            try:
                news_rec = {
                    'url': rel.get('pdf_url') or CSE_PRESS_RELEASES_URL,
                    'source': 'CSE Press Releases',
                    'source_key': 'cse_press',
                    'title': rel.get('title','')[:200],
                    'published': rel.get('publishedDate'),
                    'text': rel.get('shortDescription','') or rel.get('title',''),
                    'sentiment': self.pdf_proc.sentiment.analyze((rel.get('title','') + ' ' + rel.get('shortDescription',''))[:2000]),
                    'symbols': [],
                    'captured_at': datetime.now().isoformat(),
                    'pdf_url': rel.get('pdf_url'),
                    'id': rel.get('id'),
                    'year': rel.get('year'),
                    'month': rel.get('month'),
                }
                store.add_news(news_rec)
            except Exception:
                pass

            if download_pdfs and rel.get('pdf_url'):
                meta = {
                    'title': rel.get('title'),
                    'publishedDate': rel.get('publishedDate'),
                    'year': rel.get('year'),
                    'month': rel.get('month'),
                    'id': rel.get('id'),
                    'source_url': CSE_PRESS_RELEASES_URL,
                }
                rec = self.pdf_proc.download_and_extract(rel['pdf_url'], pdf_dir, doc_type="press_release", metadata=meta, store=store)
                if rec:
                    count_pdfs += 1
            # also count press page visits for lively UI stats (simulate visiting each release)
            store.pages_visited.append(rel.get('pdf_url') or f"{CSE_PRESS_RELEASES_URL}#{rel.get('id','')}")

        print(f"{Colors.SUCCESS}[+] Press releases crawl complete: {len(releases)} releases, {count_pdfs} PDFs downloaded & extracted{Colors.RESET}")
        print(f"{Colors.INFO}[*] PDFs saved under {pdf_dir}{Colors.RESET}")
        return len(releases)

    def _fetch_via_api(self, store) -> List[Dict]:
        """Hit CSE API directly – mirrors browser probe – returns flattened list"""
        if not REQUESTS_AVAILABLE:
            return []
        try:
            r = requests.get(CSE_PRESS_API, timeout=30, headers=self.headers, verify=False)
            if r.status_code != 200:
                print(f"{Colors.WARNING}[!] Press API HTTP {r.status_code}{Colors.RESET}")
                return []
            data = r.json()
            releases: List[Dict] = []
            for month_key in sorted(data.keys()):
                items = data.get(month_key, [])
                for item in items:
                    loc = item.get('localization', {})
                    pdf_path = None
                    # prefer en, fallback to any
                    for lang in ['en', 'si', 'ta']:
                        if lang in loc and loc[lang].get('pdf'):
                            pdf_path = loc[lang]['pdf']
                            break
                    if not pdf_path and loc:
                        for v in loc.values():
                            if v.get('pdf'):
                                pdf_path = v['pdf']
                                break
                    pdf_url = None
                    if pdf_path:
                        if pdf_path.startswith('http'):
                            pdf_url = pdf_path
                        else:
                            pdf_url = urljoin(CSE_CDN_BASE, pdf_path)
                        # cdn variant is more reliable (www.cse.lk often 404 for pdf)
                        if 'www.cse.lk/cms-internal' in pdf_url:
                            pdf_url = pdf_url.replace('https://www.cse.lk/', CSE_CDN_BASE).replace('http://www.cse.lk/', CSE_CDN_BASE)
                    releases.append({
                        'id': item.get('id'),
                        'title': item.get('title'),
                        'shortDescription': item.get('shortDescription'),
                        'publishedDate': item.get('publishedDate'),
                        'year': item.get('year'),
                        'month': item.get('month'),
                        'type': item.get('type'),
                        'source': item.get('source'),
                        'pdf_url': pdf_url,
                        'raw': item,
                    })
            # sort by date desc
            releases.sort(key=lambda x: x.get('publishedDate') or '', reverse=True)
            return releases
        except Exception as e:
            print(f"{Colors.ERROR}[-] Press API fetch failed: {e}{Colors.RESET}")
            return []

    def _parse_html_releases(self, html: str, base_url: str) -> List[Dict]:
        """Fallback HTML parser if API unavailable – looks for pdf links & titles"""
        releases = []
        try:
            # look for pdf links
            pdfs = re.findall(r'href=["\']([^"\']*\.pdf[^"\']*)["\']', html, re.I)
            # look for titles via Next.js data or simple anchors
            titles = re.findall(r'<a[^>]+href[^>]*>([^<]{10,120})</a>', html)
            for i, pdf in enumerate(pdfs):
                pdf_url = urljoin(base_url, pdf)
                title = titles[i] if i < len(titles) else os.path.basename(pdf)
                releases.append({'id': f'html-{i}', 'title': title.strip(), 'pdf_url': pdf_url, 'publishedDate': None})
        except Exception:
            pass
        return releases


class CSEAnnualReportsCrawler:
    """Crawl ALL CSE annual reports and download PDFs with extraction"""

    def __init__(self):
        self.engine = CSEEngine()
        self.pdf_proc = CSEPDFProcessor()
        self.headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}

    def crawl(self, store, download_pdfs: bool = True,
              engine_order: Optional[List[str]] = None, pdf_dir: str = "api_captures/pdfs/annual_reports") -> int:
        print(f"{Colors.HEADER}=== CSE Annual Reports — Reading ALL Reports ==={Colors.RESET}")
        print(f"{Colors.INFO}[*] Engine priority: Firecrawl -> Apify -> Crawl4AI -> Selenium -> Requests{Colors.RESET}")
        reports: List[Tuple[str, str]] = []  # (year, pdf_url)

        # Try HTML fetch with engine fallback to discover current list
        html_discovered: List[Tuple[str, str]] = []
        html, used = self.engine.fetch_with_fallback(CSE_ANNUAL_REPORTS_URL, order=engine_order)
        if html:
            html_discovered = self._parse_html_reports(html, CSE_ANNUAL_REPORTS_URL)
            print(f"{Colors.INFO}[*] HTML ({used}) discovered {len(html_discovered)} annual report links{Colors.RESET}")
            store.pages_visited.append(CSE_ANNUAL_REPORTS_URL)

        # Merge with fallback static list (ensures completeness even if HTML partial)
        merged: Dict[str, str] = {y: u for y, u in CSE_ANNUAL_REPORTS_FALLBACK}
        for y, u in html_discovered:
            if y not in merged:
                merged[y] = u
            else:
                # prefer cdn.cse.lk html-discovered if it looks fresher
                if 'cdn.cse.lk' in u:
                    merged[y] = u
        reports = sorted(merged.items(), key=lambda x: x[0], reverse=True)

        print(f"{Colors.SUCCESS}[+] Total annual reports to process: {len(reports)} (2010-2025){Colors.RESET}")
        for y, u in reports:
            print(f"  - {y}: {u}")

        if download_pdfs:
            count = 0
            for year, pdf_url in reports:
                print(f"{Colors.INFO}[*] Downloading Annual Report {year}{Colors.RESET}")
                meta = {'title': f'CSE Annual Report {year}', 'year': year, 'publishedDate': f'{year}-12-31', 'source_url': CSE_ANNUAL_REPORTS_URL}
                rec = self.pdf_proc.download_and_extract(pdf_url, pdf_dir, doc_type="annual_report", metadata=meta, store=store)
                if rec:
                    count += 1
                # also add a news-like stub for cross-analysis
                try:
                    store.add_news({
                        'url': pdf_url,
                        'source': 'CSE Annual Reports',
                        'source_key': 'cse_annual',
                        'title': f'CSE Annual Report {year}',
                        'published': f'{year}-12-31',
                        'text': f'CSE Annual Report {year} PDF document.',
                        'sentiment': self.pdf_proc.sentiment.analyze(f'CSE Annual Report {year} financial performance'),
                        'symbols': [],
                        'captured_at': datetime.now().isoformat(),
                        'year': year,
                    })
                except Exception:
                    pass
            print(f"{Colors.SUCCESS}[+] Annual reports crawl complete: {count}/{len(reports)} PDFs downloaded & extracted{Colors.RESET}")

        return len(reports)

    def _parse_html_reports(self, html: str, base_url: str) -> List[Tuple[str, str]]:
        out: List[Tuple[str, str]] = []
        try:
            # direct pdf regex
            pdfs = re.findall(r'https?://[^\s"\']+\.pdf', html, re.I)
            # filter to annual reports
            for pdf in pdfs:
                if 'annual' in pdf.lower():
                    # infer year
                    m = re.search(r'20[0-2]\d', pdf)
                    year = m.group(0) if m else 'unknown'
                    out.append((year, pdf))
            # also look for href relative
            hrefs = re.findall(r'href=["\']([^"\']*annual[^"\']*\.pdf)["\']', html, re.I)
            for h in hrefs:
                full = urljoin(base_url, h)
                m = re.search(r'20[0-2]\d', h)
                year = m.group(0) if m else 'unknown'
                if full not in [u for _, u in out]:
                    out.append((year, full))
        except Exception:
            pass
        # dedup by url
        seen = set()
        dedup: List[Tuple[str, str]] = []
        for y, u in out:
            if u not in seen:
                seen.add(u)
                dedup.append((y, u))
        return dedup


class APIEndpoint:
    """Class representing a single API endpoint"""
    
    def __init__(self, method: str, url: str):
        self.method = method.upper()
        self.url = url
        self.parameters = {}
        self.headers = {}
        self.request_examples = []
        self.response_examples = []
        self.first_seen = datetime.now().isoformat()
        self.last_seen = datetime.now().isoformat()
        self.call_count = 0
        self.auth_required = False
        self.notes = []
        
    def add_request(self, headers: Dict, params: Dict, body: Any):
        """Add a request example"""
        self.call_count += 1
        self.last_seen = datetime.now().isoformat()
        
        # Update headers
        if headers:
            for key, value in headers.items():
                if key.lower() not in ['cookie', 'authorization', 'user-agent']:
                    self.headers[key] = value
                if key.lower() in ['authorization', 'cookie', 'x-auth-token']:
                    self.auth_required = True
        
        # Update parameters
        if params:
            for key, value in params.items():
                if key not in self.parameters:
                    self.parameters[key] = {
                        'type': self._infer_type(value),
                        'examples': [value],
                        'required': True
                    }
                else:
                    if value not in self.parameters[key]['examples']:
                        self.parameters[key]['examples'].append(value)
        
        # Add request example
        if len(self.request_examples) < 10:
            self.request_examples.append({
                'timestamp': datetime.now().isoformat(),
                'headers': self._sanitize_headers(headers),
                'params': params,
                'body': body
            })
    
    def add_response(self, status_code: int, headers: Dict, body: Any):
        """Add a response example"""
        if len(self.response_examples) < 10:
            self.response_examples.append({
                'timestamp': datetime.now().isoformat(),
                'status_code': status_code,
                'headers': headers,
                'body': body
            })
    
    def _infer_type(self, value: Any) -> str:
        """Infer parameter type"""
        if isinstance(value, bool):
            return 'boolean'
        elif isinstance(value, int):
            return 'integer'
        elif isinstance(value, float):
            return 'float'
        elif isinstance(value, dict):
            return 'object'
        elif isinstance(value, list):
            return 'array'
        else:
            try:
                datetime.fromisoformat(str(value))
                return 'date'
            except:
                return 'string'
    
    def _sanitize_headers(self, headers: Dict) -> Dict:
        """Sanitize sensitive headers"""
        sensitive = ['authorization', 'cookie', 'x-auth-token', 'api-key', 'x-api-key']
        sanitized = {}
        for key, value in headers.items():
            if key.lower() in sensitive:
                sanitized[key] = '[REDACTED]'
            else:
                sanitized[key] = value
        return sanitized
    
    def to_dict(self) -> Dict:
        """Convert to dictionary for JSON serialization"""
        return {
            'method': self.method,
            'url': self.url,
            'parameters': self.parameters,
            'headers': self.headers,
            'request_examples': self.request_examples,
            'response_examples': self.response_examples,
            'first_seen': self.first_seen,
            'last_seen': self.last_seen,
            'call_count': self.call_count,
            'auth_required': self.auth_required,
            'notes': self.notes
        }


class APIStore:
    """Store for managing captured API endpoints"""
    
    def __init__(self):
        self.endpoints = {}
        self.pdfs = {}
        self.pages_visited = []
        self.stock_records = {}
        self.news_records = {}
        self.session_info = {
            'start_time': datetime.now().isoformat(),
            'target_url': None,
            'capture_mode': None
        }
    
    def add_news(self, record: Dict):
        """Add or merge a news article (keyed by URL)"""
        url = record.get('url', '')
        if not url:
            return
        if url in self.news_records:
            self.news_records[url].update(record)
        else:
            self.news_records[url] = record
    
    def add_stock_record(self, record: Dict):
        """Add or merge a stock record (keyed by symbol)"""
        symbol = str(record.get('symbol', '')).upper().strip()
        if not symbol:
            return
        
        if symbol in self.stock_records:
            existing = self.stock_records[symbol]
            for key, value in record.items():
                if value not in (None, ''):
                    existing[key] = value
        else:
            self.stock_records[symbol] = record
    
    def add_pdf(self, url: str, filepath: str, text_preview: str = "", page_count: int = 0, extra: Optional[Dict] = None):
        """Add a captured PDF document (now supports CSE doc_type, sentiment, full text, financial_entities)"""
        base = {
            'url': url,
            'filepath': filepath,
            'page_count': page_count,
            'text_preview': text_preview[:5000] if text_preview else "",
            'captured_at': datetime.now().isoformat()
        }
        if extra:
            # merge extra, but protect url/filepath/page_count if provided
            for k, v in extra.items():
                if k not in ('url',):
                    base[k] = v
            # ensure text_preview from extra not truncated further
            if 'text_preview' in extra and extra['text_preview']:
                base['text_preview'] = extra['text_preview'][:5000]
        if url not in self.pdfs:
            self.pdfs[url] = base
        else:
            self.pdfs[url].update(base)
    
    def add_endpoint(self, endpoint: APIEndpoint):
        """Add or update endpoint"""
        key = f"{endpoint.method} {endpoint.url}"
        if key in self.endpoints:
            # Merge data
            existing = self.endpoints[key]
            existing.call_count += endpoint.call_count
            existing.last_seen = endpoint.last_seen
            existing.request_examples.extend(endpoint.request_examples)
            existing.response_examples.extend(endpoint.response_examples)
            existing.parameters.update(endpoint.parameters)
            existing.headers.update(endpoint.headers)
            existing.auth_required = existing.auth_required or endpoint.auth_required
            existing.notes.extend(endpoint.notes)
        else:
            self.endpoints[key] = endpoint
    
    def search(self, query: str) -> List[APIEndpoint]:
        """Search endpoints by URL, method, or parameter"""
        results = []
        query_lower = query.lower()
        
        for key, endpoint in self.endpoints.items():
            if (query_lower in endpoint.url.lower() or
                query_lower in endpoint.method.lower() or
                any(query_lower in param.lower() for param in endpoint.parameters.keys())):
                results.append(endpoint)
        
        return results
    
    def filter_by_method(self, method: str) -> List[APIEndpoint]:
        """Filter endpoints by HTTP method"""
        return [ep for ep in self.endpoints.values() if ep.method.upper() == method.upper()]
    
    def filter_by_auth(self, auth_required: bool = True) -> List[APIEndpoint]:
        """Filter endpoints by authentication requirement"""
        return [ep for ep in self.endpoints.values() if ep.auth_required == auth_required]
    
    def get_statistics(self) -> Dict:
        """Get capture statistics"""
        methods = {}
        auth_count = 0
        total_params = 0
        
        for endpoint in self.endpoints.values():
            method = endpoint.method
            methods[method] = methods.get(method, 0) + 1
            
            if endpoint.auth_required:
                auth_count += 1
            
            total_params += len(endpoint.parameters)
        
        # CSE doc type breakdown
        press_pdfs = sum(1 for p in self.pdfs.values() if p.get('doc_type') == 'press_release')
        annual_pdfs = sum(1 for p in self.pdfs.values() if p.get('doc_type') == 'annual_report')
        return {
            'total_endpoints': len(self.endpoints),
            'methods': methods,
            'auth_required': auth_count,
            'total_parameters': total_params,
            'average_params_per_endpoint': total_params / len(self.endpoints) if self.endpoints else 0,
            'total_stocks': len(self.stock_records),
            'total_pdfs': len(self.pdfs),
            'press_release_pdfs': press_pdfs,
            'annual_report_pdfs': annual_pdfs,
            'total_pages': len(self.pages_visited),
            'total_news': len(self.news_records)
        }
    
    def save_to_file(self, filename: str = None):
        """Save endpoints to JSON file"""
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"api_capture_{timestamp}.json"
        
        data = {
            'metadata': self.session_info,
            'statistics': self.get_statistics(),
            'pages_visited': self.pages_visited,
            'endpoints': {key: ep.to_dict() for key, ep in self.endpoints.items()},
            'pdfs': self.pdfs,
            'stocks': self.stock_records,
            'news': self.news_records
        }
        
        with open(filename, 'w') as f:
            json.dump(data, f, indent=2, default=str)
        
        return filename
    
    def load_from_file(self, filename: str):
        """Load endpoints from JSON file"""
        with open(filename, 'r') as f:
            data = json.load(f)
        
        self.session_info = data.get('metadata', {})
        self.pages_visited = data.get('pages_visited', [])
        self.pdfs = data.get('pdfs', {})
        self.stock_records = data.get('stocks', {})
        self.news_records = data.get('news', {})
        
        for key, ep_data in data.get('endpoints', {}).items():
            method, url = key.split(' ', 1)
            endpoint = APIEndpoint(method, url)
            endpoint.parameters = ep_data.get('parameters', {})
            endpoint.headers = ep_data.get('headers', {})
            endpoint.request_examples = ep_data.get('request_examples', [])
            endpoint.response_examples = ep_data.get('response_examples', [])
            endpoint.first_seen = ep_data.get('first_seen')
            endpoint.last_seen = ep_data.get('last_seen')
            endpoint.call_count = ep_data.get('call_count', 0)
            endpoint.auth_required = ep_data.get('auth_required', False)
            endpoint.notes = ep_data.get('notes', [])
            self.endpoints[key] = endpoint


class BrowserCapture:
    """Browser-based API capture using Selenium"""
    
    def __init__(self, headless: bool = False):
        if not SELENIUM_AVAILABLE:
            raise ImportError("Selenium not installed. Install with: pip install selenium")
        
        self.headless = headless
        self.driver = None
        self.intercept_requests = True
        self.current_url = None
        self.target_domain = None
        self.pdf_dir = "api_captures/pdfs"
    
    def start(self):
        """Start the browser"""
        os.makedirs(self.pdf_dir, exist_ok=True)
        
        chrome_options = Options()
        if self.headless:
            chrome_options.add_argument('--headless')
        
        chrome_options.add_argument('--no-sandbox')
        chrome_options.add_argument('--disable-dev-shm-usage')
        chrome_options.add_argument('--ignore-certificate-errors')
        chrome_options.add_argument('--disable-web-security')
        chrome_options.add_argument('--disable-blink-features=AutomationControlled')
        chrome_options.add_experimental_option("excludeSwitches", ["enable-automation"])
        chrome_options.add_experimental_option('useAutomationExtension', False)
        
        # Enable performance logging
        chrome_options.set_capability('goog:loggingPrefs', {'performance': 'ALL'})
        
        try:
            self.driver = webdriver.Chrome(options=chrome_options)
            return True
        except WebDriverException as e:
            print(f"{Colors.ERROR}[-] Failed to start browser: {e}")
            return False
    
    def navigate(self, url: str) -> bool:
        """Navigate to URL"""
        try:
            if not url.startswith(('http://', 'https://')):
                url = 'https://' + url
            
            self.current_url = url
            self.target_domain = urlparse(url).netloc
            
            print(f"{Colors.INFO}[*] Navigating to {url}")
            self.driver.get(url)
            time.sleep(2)
            return True
        except Exception as e:
            print(f"{Colors.ERROR}[-] Navigation failed: {e}")
            return False
    
    def crawl_site(self, store: APIStore, max_pages: int = 0):
        """Crawl the entire site, prioritizing stock-related pages.
        max_pages=0 means unlimited."""
        print(f"{Colors.INFO}[*] Starting smart AI-style crawl...")
        print(f"{Colors.WARNING}[!] Prioritizing stock data pages under {self.target_domain}{Colors.RESET}")
        
        visited = set()
        candidates = {self.current_url: 1000}
        page_count = 0
        
        while candidates:
            url = max(candidates, key=candidates.get)
            del candidates[url]
            
            if url in visited:
                continue
            if max_pages > 0 and page_count >= max_pages:
                print(f"{Colors.WARNING}[!] Reached max pages limit ({max_pages}){Colors.RESET}")
                break
            
            visited.add(url)
            page_count += 1
            store.pages_visited.append(url)
            print(f"{Colors.INFO}[*] ({page_count}) Visiting: {url}{Colors.RESET}")
            
            try:
                self.driver.get(url)
                time.sleep(1.5)
                self._drain_logs(store)
                self._extract_stock_data(url, store)
                links = self._discover_links()
                
                for link in links:
                    parsed = urlparse(link)
                    if parsed.netloc != self.target_domain:
                        continue
                    clean = link.split('#')[0]
                    if clean in visited or clean in candidates:
                        continue
                    if clean.endswith('.pdf'):
                        self._download_pdf(clean, store)
                    elif parsed.scheme in ('http', 'https'):
                        candidates[clean] = self._score_link(clean)
            except Exception as e:
                print(f"{Colors.ERROR}[-] Failed on {url}: {e}{Colors.RESET}")
                continue
        
        print(f"{Colors.SUCCESS}[+] Crawl complete: {page_count} pages visited, "
              f"{len(store.endpoints)} endpoints, {len(store.stock_records)} stocks, "
              f"{len(store.pdfs)} PDFs captured{Colors.RESET}")
    
    def _score_link(self, url: str) -> int:
        """Score a URL by stock-data relevance (AI-style prioritization)"""
        score = 5
        url_lower = url.lower()
        
        for pattern in STOCK_URL_PATTERNS:
            if re.search(pattern, url_lower):
                score += 40
                break
        
        symbol_match = STOCK_SYMBOL_RE.search(url)
        if symbol_match:
            score += 25
        
        parsed = urlparse(url)
        depth = len([s for s in parsed.path.split('/') if s])
        score -= depth * 2
        
        return score
    
    def _extract_stock_data(self, url: str, store: APIStore):
        """Extract structured stock records from tables and JSON endpoints"""
        if url.lower().endswith('.json') and REQUESTS_AVAILABLE:
            try:
                resp = requests.get(url, timeout=20, verify=False)
                if resp.status_code == 200:
                    self._parse_json_stocks(resp.json(), url, store)
            except Exception:
                pass
        
        try:
            tables = self.driver.find_elements(By.TAG_NAME, 'table')
            for table in tables:
                rows = table.find_elements(By.TAG_NAME, 'tr')
                if len(rows) < 2:
                    continue
                
                header_cells = rows[0].find_elements(By.TAG_NAME, 'th')
                if not header_cells:
                    header_cells = rows[0].find_elements(By.TAG_NAME, 'td')
                
                headers = [cell.text.strip().lower() for cell in header_cells]
                col_map = self._map_stock_columns(headers)
                if not col_map:
                    continue
                
                for row in rows[1:]:
                    cells = [cell.text.strip() for cell in row.find_elements(By.TAG_NAME, 'td')]
                    if len(cells) < len(headers):
                        continue
                    self._record_stock_row(cells, headers, col_map, url, store)
        except Exception:
            pass
    
    def _map_stock_columns(self, headers: List[str]) -> Dict:
        """Map table headers to known stock fields"""
        col_map = {}
        for idx, header in enumerate(headers):
            for field, aliases in STOCK_COLUMN_ALIASES.items():
                if header in aliases and field not in col_map:
                    col_map[field] = idx
                    break
        return col_map if 'symbol' in col_map else {}
    
    def _record_stock_row(self, cells: List[str], headers: List[str], col_map: Dict, url: str, store: APIStore):
        """Record a stock row from an HTML table"""
        symbol = cells[col_map['symbol']].upper()
        if not symbol or symbol in ('SYMBOL', 'TICKER', 'CODE', '') or len(symbol) > 10:
            return
        if not re.match(r'^[A-Z0-9.\-]{2,10}$', symbol):
            return
        
        record = {'symbol': symbol, 'source_url': url, 'captured_at': datetime.now().isoformat()}
        
        for field, idx in col_map.items():
            if field == 'symbol' or idx >= len(cells):
                continue
            value = cells[idx].replace(',', '').replace('Rs.', '').replace('Rs', '').strip()
            if not value or value in ('-', '—', 'N/A'):
                continue
            if field == 'company':
                record['company'] = value
            else:
                try:
                    record[field] = float(value)
                except ValueError:
                    record[field] = value
        
        store.add_stock_record(record)
    
    def _parse_json_stocks(self, data: Any, url: str, store: APIStore):
        """Recursively extract stock records from JSON payloads"""
        found = 0
        
        def walk(node):
            nonlocal found
            if isinstance(node, dict):
                symbol = None
                for key in ('symbol', 'ticker', 'code', 'stockSymbol', 'instrument'):
                    if key in node:
                        symbol = str(node[key])
                        break
                if symbol and re.match(r'^[A-Z0-9.\-]{2,10}$', symbol.upper()):
                    record = {
                        'symbol': symbol.upper(),
                        'source_url': url,
                        'captured_at': datetime.now().isoformat()
                    }
                    for key in STOCK_VALUE_KEYS:
                        if key in node and isinstance(node[key], (int, float)):
                            record[key] = node[key]
                    if len(record) > 3:
                        store.add_stock_record(record)
                        found += 1
                for value in node.values():
                    walk(value)
            elif isinstance(node, list):
                for item in node:
                    walk(item)
        
        walk(data)
        if found:
            print(f"{Colors.SUCCESS}[+] Extracted {found} stock records from {url}{Colors.RESET}")
    
    def _drain_logs(self, store: APIStore):
        """Process accumulated performance logs"""
        processed_logs = set()
        
        try:
            logs = self.driver.get_log('performance')
            
            for entry in logs:
                if entry['timestamp'] in processed_logs:
                    continue
                processed_logs.add(entry['timestamp'])
                
                try:
                    message = json.loads(entry['message'])
                    method = message.get('message', {}).get('method', '')
                    
                    if method == 'Network.requestWillBeSent':
                        request = message['message']['params']['request']
                        self._process_request(request, store)
                    
                    elif method == 'Network.responseReceived':
                        response = message['message']['params']['response']
                        self._process_response(response, store)
                
                except Exception:
                    continue
        except Exception:
            pass
    
    def _discover_links(self) -> List[str]:
        """Extract all links from current page"""
        links = []
        try:
            anchors = self.driver.find_elements(By.TAG_NAME, 'a')
            for anchor in anchors:
                try:
                    href = anchor.get_attribute('href')
                    if href:
                        links.append(href)
                except Exception:
                    continue
        except Exception:
            pass
        return list(dict.fromkeys(links))
    
    def _download_pdf(self, url: str, store: APIStore):
        """Download a PDF and extract its text content"""
        if not REQUESTS_AVAILABLE:
            print(f"{Colors.WARNING}[!] requests not available, skipping PDF: {url}{Colors.RESET}")
            return
        
        try:
            parsed = urlparse(url)
            filename = os.path.basename(parsed.path) or f"document_{abs(hash(url))}.pdf"
            filepath = os.path.join(self.pdf_dir, filename)
            
            resp = requests.get(url, timeout=30, verify=False)
            if resp.status_code != 200 or 'pdf' not in resp.headers.get('Content-Type', '').lower():
                return
            
            with open(filepath, 'wb') as f:
                f.write(resp.content)
            
            text_preview = ""
            page_count = 0
            
            if PDF_AVAILABLE:
                try:
                    reader = PdfReader(filepath)
                    page_count = len(reader.pages)
                    text_parts = []
                    for page in reader.pages[:5]:
                        text_parts.append(page.extract_text() or "")
                    text_preview = " ".join(text_parts).strip()
                    print(f"{Colors.SUCCESS}[+] PDF captured: {filename} ({page_count} pages){Colors.RESET}")
                except Exception as e:
                    print(f"{Colors.WARNING}[!] PDF saved but text extraction failed: {e}{Colors.RESET}")
            else:
                print(f"{Colors.SUCCESS}[+] PDF saved (text extraction unavailable): {filename}{Colors.RESET}")
            
            store.add_pdf(url, filepath, text_preview, page_count)
            
        except Exception as e:
            print(f"{Colors.ERROR}[-] PDF download failed {url}: {e}{Colors.RESET}")
    
    def _process_request(self, request: Dict, store: APIStore):
        """Process network request"""
        url = request.get('url', '')
        method = request.get('method', 'GET')
        headers = request.get('headers', {})
        post_data = request.get('postData')
        
        # Skip non-API requests (static files, etc.)
        if self._should_skip_url(url):
            return
        
        # Parse URL
        parsed_url = urlparse(url)
        base_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}"
        params = parse_qs(parsed_url.query)
        
        # Parse body
        body = None
        if post_data:
            try:
                body = json.loads(post_data)
            except:
                body = post_data
        
        # Create endpoint
        endpoint = APIEndpoint(method, base_url)
        endpoint.add_request(headers, params, body)
        store.add_endpoint(endpoint)
    
    def _process_response(self, response: Dict, store: APIStore):
        """Process network response"""
        url = response.get('url', '')
        status = response.get('status')
        headers = response.get('headers', {})
        
        parsed_url = urlparse(url)
        base_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}"
        
        # Find matching endpoint
        for key, endpoint in store.endpoints.items():
            if endpoint.url == base_url and status:
                endpoint.add_response(status, headers, None)
                break
    
    def _should_skip_url(self, url: str) -> bool:
        """Determine if URL should be skipped"""
        skip_patterns = [
            r'\.(css|js|png|jpg|jpeg|gif|ico|svg|woff|woff2|ttf|eot)$',
            r'google-analytics',
            r'googletagmanager',
            r'hotjar',
            r'analytics',
        ]
        
        for pattern in skip_patterns:
            if re.search(pattern, url, re.IGNORECASE):
                return True
        
        return False
    
    def close(self):
        """Close browser"""
        if self.driver:
            self.driver.quit()


class ManualCapture:
    """Manual API endpoint entry"""
    
    @staticmethod
    def add_endpoint_manually(store: APIStore):
        """Interactively add endpoint manually"""
        print(f"\n{Colors.HEADER}=== Manual Endpoint Entry ==={Colors.RESET}")
        
        # Get method
        method = input(f"{Colors.PROMPT}api-capture > {Colors.RESET}HTTP Method (GET/POST/PUT/DELETE/PATCH): ").upper()
        if method not in ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS', 'HEAD']:
            print(f"{Colors.ERROR}[-] Invalid method")
            return None
        
        # Get URL
        url = input(f"{Colors.PROMPT}api-capture > {Colors.RESET}Endpoint URL: ")
        if not url:
            print(f"{Colors.ERROR}[-] URL is required")
            return None
        
        endpoint = APIEndpoint(method, url)
        
        # Add parameters
        print(f"\n{Colors.INFO}[*] Add parameters (leave empty to skip) {Colors.RESET}")
        while True:
            param_name = input(f"{Colors.PROMPT}api-capture > {Colors.RESET}Parameter name (or 'done'): ")
            if param_name.lower() == 'done' or not param_name:
                break
            
            param_value = input(f"{Colors.PROMPT}api-capture > {Colors.RESET}Parameter value: ")
            param_type = input(f"{Colors.PROMPT}api-capture > {Colors.RESET}Parameter type (string/integer/boolean/object/array): ")
            
            if not param_type:
                param_type = 'string'
            
            endpoint.parameters[param_name] = {
                'type': param_type,
                'examples': [param_value],
                'required': True
            }
        
        # Add headers
        print(f"\n{Colors.INFO}[*] Add headers (leave empty to skip) {Colors.RESET}")
        headers = {}
        while True:
            header_name = input(f"{Colors.PROMPT}api-capture > {Colors.RESET}Header name (or 'done'): ")
            if header_name.lower() == 'done' or not header_name:
                break
            
            header_value = input(f"{Colors.PROMPT}api-capture > {Colors.RESET}Header value: ")
            headers[header_name] = header_value
        
        # Add request example
        endpoint.add_request(headers, {}, None)
        
        # Add note
        note = input(f"{Colors.PROMPT}api-capture > {Colors.RESET}Add note (optional): ")
        if note:
            endpoint.notes.append(note)
        
        store.add_endpoint(endpoint)
        print(f"{Colors.SUCCESS}[+] Endpoint added successfully{Colors.RESET}")
        return endpoint


class APICaptureConsole(cmd.Cmd):
    """Interactive console for API capture framework"""
    
    intro = f"""
{Colors.BANNER}
╔═══════════════════════════════════════════════════════════════╗
║                                                               ║
║     █████╗ ██████╗ ██╗     ██████╗ █████╗ ██████╗ ████████╗  ║
║    ██╔══██╗██╔══██╗██║    ██╔════╝██╔══██╗██╔══██╗██╔═════╝  ║
║    ███████║██████╔╝██║    ██║     ███████║██████╔╝███████╗    ║
║    ██╔══██║██╔═══╝ ██║    ██║     ██╔══██║██╔═══╝ ╚════██║    ║
║    ██║  ██║██║     ██████╗╚██████╗██║  ██║██║     ███████║    ║
║    ╚═╝  ╚═╝╚═╝     ╚═════╝ ╚═════╝╚═╝  ╚═╝╚═╝     ╚══════╝    ║
║                                                               ║
║              API Capture Framework v1.0.0                     ║
║         API Security Assessment & Discovery Tool              ║
║                                                               ║
╚═══════════════════════════════════════════════════════════════╝
{Colors.RESET}
{Colors.INFO}[*] Type 'help' for available commands{Colors.RESET}
{Colors.INFO}[*] Type 'banner' to show this banner again{Colors.RESET}
"""
    
    prompt = f"{Colors.PROMPT}api-capture > {Colors.RESET}"
    
    def __init__(self):
        super().__init__()
        self.store = APIStore()
        self.browser = None
        self.current_url = None
        self.max_pages = 0
        self.output_dir = "api_captures"
        self.headless = False
        self.setup_output_dir()
    
    def setup_output_dir(self):
        """Setup output directory"""
        Path(self.output_dir).mkdir(exist_ok=True)
    
    # ==================== Basic Commands ====================
    
    def do_banner(self, arg):
        """Show banner"""
        print(self.intro)
    
    def do_clear(self, arg):
        """Clear the screen"""
        os.system('cls' if os.name == 'nt' else 'clear')
    
    def do_exit(self, arg):
        """Exit the framework"""
        print(f"\n{Colors.INFO}[*] Thank you for using API Capture Framework{Colors.RESET}")
        if self.browser:
            self.browser.close()
        return True
    
    def do_quit(self, arg):
        """Exit the framework"""
        return self.do_exit(arg)
    
    # ==================== Configuration Commands ====================
    
    def do_set(self, arg):
        """Set configuration options
        Usage: set <option> <value>
        Options: URL, MAXPAGES, OUTPUT, HEADLESS"""
        args = shlex.split(arg)
        
        if len(args) < 2:
            print(f"{Colors.ERROR}[-] Usage: set <option> <value>{Colors.RESET}")
            return
        
        option = args[0].upper()
        value = args[1]
        
        if option == 'URL':
            self.current_url = value
            self.store.session_info['target_url'] = value
            print(f"{Colors.SUCCESS}[+] URL set to: {value}{Colors.RESET}")
        
        elif option in ('MAXPAGES', 'DURATION'):
            try:
                self.max_pages = int(value)
                limit_text = "unlimited" if self.max_pages == 0 else f"{self.max_pages} pages"
                print(f"{Colors.SUCCESS}[+] Max pages to crawl set to: {limit_text}{Colors.RESET}")
            except ValueError:
                print(f"{Colors.ERROR}[-] Invalid value (use 0 for unlimited){Colors.RESET}")
        
        elif option == 'OUTPUT':
            self.output_dir = value
            self.setup_output_dir()
            print(f"{Colors.SUCCESS}[+] Output directory set to: {value}{Colors.RESET}")
        
        elif option == 'HEADLESS':
            if value.lower() in ['true', '1', 'yes']:
                self.headless = True
                print(f"{Colors.SUCCESS}[+] Headless mode enabled{Colors.RESET}")
            else:
                self.headless = False
                print(f"{Colors.SUCCESS}[+] Headless mode disabled{Colors.RESET}")
        
        else:
            print(f"{Colors.ERROR}[-] Unknown option: {option}{Colors.RESET}")
    
    def do_show(self, arg):
        """Show configuration or captured data
        Usage: show options | show endpoints | show stats | show pdfs | show pages"""
        arg = arg.lower().strip()
        
        if arg == 'options' or not arg:
            self._show_options()
        elif arg == 'endpoints':
            self._show_endpoints()
        elif arg == 'stats':
            self._show_statistics()
        elif arg == 'pdfs':
            self._show_pdfs()
        elif arg == 'pages':
            self._show_pages()
        elif arg == 'stocks':
            self._show_stocks()
        elif arg == 'news':
            self._show_news()
        else:
            print(f"{Colors.ERROR}[-] Unknown show option: {arg}{Colors.RESET}")
    
    def _show_options(self):
        """Show current configuration"""
        print(f"\n{Colors.HEADER}=== Current Configuration ==={Colors.RESET}")
        print(f"{Colors.PARAM}{'Option':<20} {'Value':<30} {'Description'}{Colors.RESET}")
        print("-" * 70)
        print(f"{'URL':<20} {str(self.current_url):<30} Target URL")
        print(f"{'MAXPAGES':<20} {str(self.max_pages):<30} Max pages to crawl (0 = unlimited)")
        print(f"{'OUTPUT':<20} {str(self.output_dir):<30} Output directory")
        print(f"{'HEADLESS':<20} {str(self.headless):<30} Headless browser mode")
        print()
    
    def _show_pdfs(self):
        """Show captured PDF documents (now with doc_type breakdown)"""
        if not self.store.pdfs:
            print(f"{Colors.WARNING}[!] No PDFs captured yet (use 'capture press' or 'capture annual' or 'capture cse'){Colors.RESET}")
            return

        stats = self.store.get_statistics()
        press = stats.get('press_release_pdfs', 0)
        annual = stats.get('annual_report_pdfs', 0)
        other = len(self.store.pdfs) - press - annual

        print(f"\n{Colors.HEADER}=== Captured PDFs ({len(self.store.pdfs)}) : Press={press} | Annual={annual} | Other={other} ==={Colors.RESET}")
        print(f"{Colors.PARAM}{'ID':<5} {'Type':<13} {'Pages':<7} {'File':<32} {'Sent':<9} {'Title/URL'}{Colors.RESET}")
        print("-" * 130)

        for i, (url, pdf) in enumerate(self.store.pdfs.items(), 1):
            filename = os.path.basename(pdf['filepath'])[:32]
            dtype = pdf.get('doc_type', 'other')[:13]
            sent = pdf.get('sentiment', {}).get('label', '-')[:9]
            title = (pdf.get('title') or url)[:55]
            # color type
            if dtype == 'press_release':
                tcol = Colors.INFO
            elif dtype == 'annual_report':
                tcol = Colors.SUCCESS
            else:
                tcol = Colors.WARNING
            print(f"{i:<5} {tcol}{dtype:<13}{Colors.RESET} {str(pdf['page_count']):<7} {filename:<32} {sent:<9} {title}")

        print(f"\n{Colors.INFO}Use 'pdfinfo <id>' for full extracted text + sentiment + financial entities{Colors.RESET}")
        print(f"{Colors.INFO}Docs dirs: api_captures/pdfs/press_releases/  api_captures/pdfs/annual_reports/{Colors.RESET}")
        print()
    
    def _show_pages(self):
        """Show visited pages"""
        if not self.store.pages_visited:
            print(f"{Colors.WARNING}[!] No pages visited yet{Colors.RESET}")
            return
        
        print(f"\n{Colors.HEADER}=== Visited Pages ({len(self.store.pages_visited)}) ==={Colors.RESET}")
        for i, url in enumerate(self.store.pages_visited, 1):
            print(f"  {i}. {url}")
        print()
    
    def _show_stocks(self):
        """Show captured stock records"""
        if not self.store.stock_records:
            print(f"{Colors.WARNING}[!] No stock records captured yet{Colors.RESET}")
            return
        
        records = sorted(self.store.stock_records.values(),
                         key=lambda r: r.get('change', 0) if isinstance(r.get('change'), (int, float)) else 0,
                         reverse=True)
        
        print(f"\n{Colors.HEADER}=== Captured Stocks ({len(records)}) ==={Colors.RESET}")
        print(f"{Colors.PARAM}{'Symbol':<10} {'Price':<12} {'Change':<10} {'Volume':<14} {'Company'}{Colors.RESET}")
        print("-" * 100)
        
        for record in records:
            price = f"{record['price']:.2f}" if isinstance(record.get('price'), (int, float)) else str(record.get('price', '-'))
            change = f"{record['change']:.2f}" if isinstance(record.get('change'), (int, float)) else str(record.get('change', '-'))
            volume = f"{record['volume']:,}" if isinstance(record.get('volume'), (int, float)) else str(record.get('volume', '-'))
            company = record.get('company', '-')[:45]
            print(f"{record['symbol']:<10} {price:<12} {change:<10} {volume:<14} {company}")
        
        print(f"\n{Colors.INFO}Use 'stockinfo <symbol>' for full record details{Colors.RESET}")
        print()
    
    def do_stockinfo(self, arg):
        """Show full details for a stock symbol
        Usage: stockinfo <symbol>"""
        if not arg.strip():
            print(f"{Colors.ERROR}[-] Usage: stockinfo <symbol>{Colors.RESET}")
            return
        
        symbol = arg.strip().upper()
        record = self.store.stock_records.get(symbol)
        
        if not record:
            print(f"{Colors.ERROR}[-] Stock not found: {symbol} (use 'show stocks' to list){Colors.RESET}")
            return
        
        print(f"\n{Colors.HEADER}=== Stock: {symbol} ==={Colors.RESET}")
        for key, value in record.items():
            if isinstance(value, float):
                print(f"{Colors.PARAM}{key.title():<20}{Colors.RESET} {value:,.2f}")
            else:
                print(f"{Colors.PARAM}{key.title():<20}{Colors.RESET} {value}")
        print()
    
    def _show_news(self):
        """Show captured news articles"""
        if not self.store.news_records:
            print(f"{Colors.WARNING}[!] No news articles captured yet (use 'capture news'){Colors.RESET}")
            return
        
        records = sorted(self.store.news_records.values(), key=lambda r: r.get('captured_at', ''), reverse=True)
        
        print(f"\n{Colors.HEADER}=== Captured News ({len(records)}) ==={Colors.RESET}")
        print(f"{Colors.PARAM}{'ID':<5} {'Source':<15} {'Sentiment':<10} {'Title'}{Colors.RESET}")
        print("-" * 100)
        
        for i, record in enumerate(records, 1):
            sent = record.get('sentiment', {})
            label = sent.get('label', 'Neutral')
            sent_color = Colors.SUCCESS if label == 'Positive' else (Colors.ERROR if label == 'Negative' else Colors.WARNING)
            symbols = f" [{', '.join(record.get('symbols', []))}]" if record.get('symbols') else ""
            print(f"{i:<5} {record.get('source', '-'):<15} {sent_color}{label:<10}{Colors.RESET} "
                  f"{record.get('title', '')[:65]}{symbols}")
        
        print(f"\n{Colors.INFO}Use 'newsinfo <id>' for article details and 'analyze' for market analysis{Colors.RESET}")
        print()
    
    def do_newsinfo(self, arg):
        """Show full article details with sentiment analysis
        Usage: newsinfo <news_id>"""
        if not arg or not arg.strip().isdigit():
            print(f"{Colors.ERROR}[-] Usage: newsinfo <news_id>{Colors.RESET}")
            return
        
        idx = int(arg) - 1
        records = list(self.store.news_records.values())
        
        if not (0 <= idx < len(records)):
            print(f"{Colors.ERROR}[-] Invalid news ID{Colors.RESET}")
            return
        
        record = records[idx]
        sent = record.get('sentiment', {})
        
        print(f"\n{Colors.HEADER}=== Article ==={Colors.RESET}")
        print(f"{Colors.PARAM}Title:{Colors.RESET} {record.get('title', '')}")
        print(f"{Colors.PARAM}Source:{Colors.RESET} {record.get('source', '-')}")
        print(f"{Colors.PARAM}Published:{Colors.RESET} {record.get('published', 'Unknown')}")
        print(f"{Colors.PARAM}URL:{Colors.RESET} {record.get('url', '')}")
        print(f"{Colors.PARAM}Symbols:{Colors.RESET} {', '.join(record.get('symbols', [])) or 'None detected'}")
        print(f"{Colors.PARAM}Sentiment:{Colors.RESET} {sent.get('label', 'Neutral')} "
              f"(score {sent.get('score', 0):.3f}, engine: {sent.get('engine', 'lexicon')})")
        print(f"\n{Colors.PARAM}Content:{Colors.RESET}")
        print(record.get('text', '')[:2000])
        print()
    
    def do_models(self, arg):
        """Show available AI models and crawlers catalog
        Usage: models"""
        print(f"\n{Colors.HEADER}=== CSE Recommended Models (in order of preference) ==={Colors.RESET}")
        for key, model in CSE_RECOMMENDED_MODELS.items():
            print(f"  {Colors.PARAM}{key:<20}{Colors.RESET} {model}")
        
        print(f"\n{Colors.HEADER}=== Financial Sentiment Models ==={Colors.RESET}")
        for key, model in SENTIMENT_MODELS.items():
            print(f"  {Colors.PARAM}{key:<20}{Colors.RESET} {model}")
        
        print(f"\n{Colors.HEADER}=== Financial Data Crawlers ==={Colors.RESET}")
        for key, crawler in FINANCIAL_CRAWLERS.items():
            print(f"  {Colors.PARAM}{key:<15}{Colors.RESET} {crawler['description']} ({crawler['install']})")
        
        print(f"\n{Colors.HEADER}=== AI-Powered Crawlers ==={Colors.RESET}")
        for key, crawler in AI_CRAWLERS.items():
            print(f"  {Colors.PARAM}{key:<15}{Colors.RESET} {crawler['description']}")
        
        engine = SentimentAnalyzer().engine
        print(f"\n{Colors.INFO}[*] Current sentiment engine: {engine}{Colors.RESET}")
        if engine == 'lexicon':
            print(f"{Colors.INFO}[*] Enable FinBERT with: pip install transformers{Colors.RESET}")

        print(f"\n{Colors.HEADER}=== CSE Crawling Engines (Firecrawl + Apify + Crawl4AI) ==={Colors.RESET}")
        for key, cfg in CSE_ENGINES.items():
            avail = cfg['available']()
            env = cfg['env_key']
            status = f"{Colors.SUCCESS}available{Colors.RESET}" if avail else f"{Colors.ERROR}not installed{Colors.RESET}"
            env_status = ""
            if env:
                env_status = f" | env {env}={'set' if os.environ.get(env) else 'MISSING (fallback ok)'}"
            print(f"  {Colors.PARAM}{key:<12}{Colors.RESET} {status}{env_status} | {AI_CRAWLERS.get(key, {}).get('description','')}")
        print(f"{Colors.INFO}[*] CSE press releases : {CSE_PRESS_RELEASES_URL}{Colors.RESET}")
        print(f"{Colors.INFO}[*] CSE annual reports : {CSE_ANNUAL_REPORTS_URL} ({len(CSE_ANNUAL_REPORTS_FALLBACK)} known 2010-2025){Colors.RESET}")
        print(f"{Colors.INFO}[*] CSE API            : {CSE_PRESS_API}{Colors.RESET}")
        print(f"{Colors.INFO}[*] Engine order env   : CSE_ENGINE_ORDER (comma list, e.g. firecrawl,apify,crawl4ai,selenium,requests){Colors.RESET}")
        print()
    
    def do_analyze(self, arg):
        """Run comprehensive market analysis: sentiment over news/PDFs,
        stock correlations, and endpoint insights
        Usage: analyze"""
        print(f"\n{Colors.HEADER}=== Market Analysis ==={Colors.RESET}")
        analyzer = SentimentAnalyzer()
        
        pdf_sentiments = []
        analyzed_pdfs = 0
        for url, pdf in self.store.pdfs.items():
            if not pdf.get('sentiment'):
                pdf['sentiment'] = analyzer.analyze(pdf.get('text_preview', ''))
                analyzed_pdfs += 1
            if pdf.get('sentiment'):
                pdf_sentiments.append(pdf['sentiment'])
        
        news_list = list(self.store.news_records.values())
        
        print(f"{Colors.PARAM}Sentiment Engine:{Colors.RESET} {analyzer.engine}")
        print(f"{Colors.PARAM}Articles Analyzed:{Colors.RESET} {len(news_list)}")
        print(f"{Colors.PARAM}PDFs Analyzed:{Colors.RESET} {len(pdf_sentiments)}"
              + (f" ({analyzed_pdfs} newly analyzed)" if analyzed_pdfs else ""))
        
        # Sentiment distribution
        dist = {'Positive': 0, 'Negative': 0, 'Neutral': 0}
        scores = []
        for sent in [n.get('sentiment', {}) for n in news_list] + pdf_sentiments:
            label = sent.get('label', 'Neutral')
            if label in dist:
                dist[label] += 1
            if sent.get('score') is not None:
                scores.append(sent['score'])
        
        if sum(dist.values()):
            print(f"\n{Colors.PARAM}Sentiment Distribution:{Colors.RESET}")
            for label, count in dist.items():
                color = Colors.SUCCESS if label == 'Positive' else (Colors.ERROR if label == 'Negative' else Colors.WARNING)
                pct = count / sum(dist.values()) * 100
                print(f"  {color}{label:<10}{Colors.RESET} {count:>4} ({pct:>5.1f}%)")
            avg = sum(scores) / len(scores) if scores else None
            if avg is not None:
                market = 'Bullish' if avg > 0.55 else ('Bearish' if avg < 0.45 else 'Neutral')
                print(f"\n  {Colors.PARAM}Average sentiment score:{Colors.RESET} {avg:.3f} -> {Colors.HEADER}{market} market{Colors.RESET}")
        
        # Symbol-level correlation
        symbol_scores = {}
        for news in news_list:
            for sym in news.get('symbols', []):
                sent = news.get('sentiment', {})
                score = sent.get('score')
                if score is None:
                    continue
                if sym not in symbol_scores:
                    symbol_scores[sym] = {'articles': 0, 'total': 0.0}
                symbol_scores[sym]['articles'] += 1
                symbol_scores[sym]['total'] += score
        
        if symbol_scores:
            print(f"\n{Colors.PARAM}News Sentiment vs Stock Price:{Colors.RESET}")
            print(f"  {'Symbol':<10} {'Articles':<10} {'Avg Sentiment':<16} {'Price Change'}")
            print("  " + "-" * 60)
            for sym, agg in sorted(symbol_scores.items(), key=lambda x: x[1]['total'] / x[1]['articles']):
                avg_sent = agg['total'] / agg['articles']
                stock = self.store.stock_records.get(sym)
                change = stock.get('change') if stock else None
                change_str = f"{change:+.2f}" if isinstance(change, (int, float)) else "n/a"
                sent_color = Colors.SUCCESS if avg_sent > 0.55 else (Colors.ERROR if avg_sent < 0.45 else Colors.WARNING)
                print(f"  {sym:<10} {agg['articles']:<10} {sent_color}{avg_sent:.3f}{Colors.RESET:<10} {change_str}")
        
        # Top articles
        scored = [(n, n.get('sentiment', {}).get('score', 0)) for n in news_list
                  if n.get('sentiment', {}).get('label') in ('Positive', 'Negative')]
        if scored:
            top = sorted(scored, key=lambda x: x[1], reverse=True)[:3]
            bottom = sorted(scored, key=lambda x: x[1])[:3]
            print(f"\n{Colors.PARAM}Most Positive Articles:{Colors.RESET}")
            for news, score in top:
                print(f"  {Colors.SUCCESS}[+] {news.get('title', '')[:70]}{Colors.RESET}")
            print(f"\n{Colors.PARAM}Most Negative Articles:{Colors.RESET}")
            for news, score in bottom:
                print(f"  {Colors.ERROR}[-] {news.get('title', '')[:70]}{Colors.RESET}")
        
        if not news_list and not pdf_sentiments:
            print(f"{Colors.WARNING}[!] No news or PDF content to analyze. Use 'capture news' first.{Colors.RESET}")
        
        print(f"\n{Colors.INFO}[*] Run 'save' to persist sentiment analysis with your data{Colors.RESET}")
    
    def do_pdfinfo(self, arg):
        """Show extracted text from a captured PDF
        Usage: pdfinfo <pdf_id>"""
        if not arg or not arg.strip().isdigit():
            print(f"{Colors.ERROR}[-] Usage: pdfinfo <pdf_id>{Colors.RESET}")
            return
        
        idx = int(arg) - 1
        pdfs = list(self.store.pdfs.values())
        
        if not (0 <= idx < len(pdfs)):
            print(f"{Colors.ERROR}[-] Invalid PDF ID{Colors.RESET}")
            return
        
        pdf = pdfs[idx]
        print(f"\n{Colors.HEADER}=== PDF Info ({idx+1}/{len(pdfs)}) ==={Colors.RESET}")
        print(f"{Colors.PARAM}URL:{Colors.RESET} {pdf['url']}")
        print(f"{Colors.PARAM}File:{Colors.RESET} {pdf['filepath']}")
        print(f"{Colors.PARAM}Type:{Colors.RESET} {pdf.get('doc_type','other')}")
        print(f"{Colors.PARAM}Title:{Colors.RESET} {pdf.get('title','-')}")
        print(f"{Colors.PARAM}Year:{Colors.RESET} {pdf.get('year','-')}  Published: {pdf.get('publishedDate','-')}")
        print(f"{Colors.PARAM}Pages:{Colors.RESET} {pdf['page_count']}")
        print(f"{Colors.PARAM}Captured:{Colors.RESET} {pdf['captured_at']}")
        sent = pdf.get('sentiment') or {}
        if sent:
            print(f"{Colors.PARAM}Sentiment:{Colors.RESET} {sent.get('label','-')} (score {sent.get('score',0):.3f}, engine {sent.get('engine','')})")
        if pdf.get('symbols'):
            print(f"{Colors.PARAM}Symbols:{Colors.RESET} {', '.join(pdf.get('symbols',[]))}")
        if pdf.get('financial_entities'):
            print(f"\n{Colors.PARAM}Financial Entities:{Colors.RESET}")
            for k, v in pdf['financial_entities'].items():
                if isinstance(v, list):
                    print(f"  {k}: {', '.join(str(x)[:80] for x in v[:5])}")
                elif isinstance(v, dict):
                    print(f"  {k}: {json.dumps(v)[:200]}")
                else:
                    print(f"  {k}: {str(v)[:200]}")
        # full text if available
        full = pdf.get('text_full') or pdf.get('text_preview') or ""
        if full:
            print(f"\n{Colors.PARAM}Extracted Text ({len(full)} chars, showing first 4000):{Colors.RESET}")
            print(full[:4000])
            if len(full) > 4000:
                print(f"{Colors.WARNING}... truncated, full text in JSON export ({len(full)} chars){Colors.RESET}")
        else:
            print(f"{Colors.WARNING}[!] No text extracted from this PDF{Colors.RESET}")
        print()
    
    def _show_endpoints(self, endpoints=None):
        """Show captured endpoints"""
        if endpoints is None:
            endpoints = list(self.store.endpoints.values())
        
        if not endpoints:
            print(f"{Colors.WARNING}[!] No endpoints captured yet{Colors.RESET}")
            return
        
        print(f"\n{Colors.HEADER}=== Captured Endpoints ({len(endpoints)}) ==={Colors.RESET}")
        print(f"{Colors.PARAM}{'ID':<5} {'Method':<10} {'URL':<50} {'Calls':<8} {'Auth'}{Colors.RESET}")
        print("-" * 90)
        
        for i, endpoint in enumerate(endpoints, 1):
            method_color = self._get_method_color(endpoint.method)
            auth_marker = "✓" if endpoint.auth_required else "✗"
            
            print(f"{i:<5} {method_color}{endpoint.method:<10}{Colors.RESET} "
                  f"{endpoint.url[:50]:<50} {endpoint.call_count:<8} {auth_marker}")
        print()
    
    def _show_statistics(self):
        """Show capture statistics (now with CSE breakdown)"""
        stats = self.store.get_statistics()
        
        print(f"\n{Colors.HEADER}=== Capture Statistics ==={Colors.RESET}")
        print(f"Total Endpoints: {stats['total_endpoints']}")
        print(f"Total Parameters: {stats['total_parameters']}")
        print(f"Average Params/Endpoint: {stats['average_params_per_endpoint']:.2f}")
        print(f"Auth Required Endpoints: {stats['auth_required']}")
        print(f"Total PDFs: {stats['total_pdfs']}  (Press Releases: {stats.get('press_release_pdfs',0)} | Annual Reports: {stats.get('annual_report_pdfs',0)})")
        print(f"Total News: {stats['total_news']} | Stocks: {stats['total_stocks']} | Pages: {stats['total_pages']}")
        
        if stats['methods']:
            print(f"\n{Colors.PARAM}HTTP Methods Distribution:{Colors.RESET}")
            for method, count in stats['methods'].items():
                method_color = self._get_method_color(method)
                print(f"  {method_color}{method}: {count}{Colors.RESET}")
        print()
    
    def _get_method_color(self, method):
        """Get color for HTTP method"""
        method_colors = {
            'GET': Colors.METHOD_GET,
            'POST': Colors.METHOD_POST,
            'PUT': Colors.METHOD_PUT,
            'DELETE': Colors.METHOD_DELETE
        }
        return method_colors.get(method, Colors.METHOD_OTHER)
    
    # ==================== Capture Commands ====================
    
    def do_capture(self, arg):
        """Start capture
        Usage: capture browser | capture stocks | capture news | capture manual | capture press | capture annual | capture cse [all|press|annual]"""
        args = shlex.split(arg)
        
        if not args:
            print(f"{Colors.ERROR}[-] Usage: capture <browser|stocks|news|manual|press|annual|cse>{Colors.RESET}")
            print(f"{Colors.INFO}    capture press   - All CSE press releases (Firecrawl/Apify/Crawl4AI + API) + download PDFs & extract data{Colors.RESET}")
            print(f"{Colors.INFO}    capture annual  - All CSE annual reports (2010-2025) + download PDFs & extract data{Colors.RESET}")
            print(f"{Colors.INFO}    capture cse     - Both press releases AND annual reports (recommended){Colors.RESET}")
            return
        
        mode = args[0].lower()
        sub = args[1].lower() if len(args) > 1 else "all"
        
        if mode in ('browser', 'stocks'):
            self._capture_browser()
        elif mode == 'news':
            self._capture_news()
        elif mode == 'manual':
            ManualCapture.add_endpoint_manually(self.store)
        elif mode in ('press', 'press_releases', 'press-releases', 'releases'):
            self._capture_press_releases()
        elif mode in ('annual', 'annual_reports', 'annual-reports', 'reports'):
            self._capture_annual_reports()
        elif mode in ('cse', 'cse_all'):
            if sub in ('press',):
                self._capture_press_releases()
            elif sub in ('annual', 'reports'):
                self._capture_annual_reports()
            else:
                # both – press first then annual
                print(f"{Colors.HEADER}=== CSE Full Capture: Press Releases + Annual Reports ==={Colors.RESET}")
                self._capture_press_releases()
                self._capture_annual_reports()
                self.store.session_info['capture_mode'] = 'cse_full'
                print(f"{Colors.SUCCESS}[+] CSE full capture done. Use 'show pdfs', 'show news', 'analyze', 'save'.{Colors.RESET}")
        else:
            print(f"{Colors.ERROR}[-] Unknown capture mode: {mode}{Colors.RESET}")

    def _capture_press_releases(self, max_items: int = 0):
        """Capture ALL CSE press releases (via unified multi-engine + API fallback)"""
        # engine order: Firecrawl -> Apify -> Crawl4AI -> Selenium -> Requests
        # Will auto-fallback to direct API which is fastest; engines used if API fails or for HTML validation
        crawler = CSEPressReleasesCrawler()
        engine_order = None  # default priority
        # honor env override if user sets CSE_ENGINE_ORDER=...
        env_order = os.environ.get('CSE_ENGINE_ORDER')
        if env_order:
            engine_order = [e.strip().lower() for e in env_order.split(',') if e.strip()]
        count = crawler.crawl(self.store, download_pdfs=True, max_items=max_items, engine_order=engine_order)
        self.store.session_info['capture_mode'] = 'cse_press'
        self.store.session_info['target_url'] = CSE_PRESS_RELEASES_URL
        if count:
            print(f"{Colors.INFO}[*] Press releases: {count} releases processed. Use 'show pdfs', 'show news', 'analyze' for details.{Colors.RESET}")

    def _capture_annual_reports(self):
        """Capture ALL CSE annual reports (2010-2025) with multi-engine fallback"""
        crawler = CSEAnnualReportsCrawler()
        env_order = os.environ.get('CSE_ENGINE_ORDER')
        engine_order = [e.strip().lower() for e in env_order.split(',')] if env_order else None
        count = crawler.crawl(self.store, download_pdfs=True, engine_order=engine_order)
        self.store.session_info['capture_mode'] = 'cse_annual'
        self.store.session_info['target_url'] = CSE_ANNUAL_REPORTS_URL
        if count:
            print(f"{Colors.INFO}[*] Annual reports: {count} reports processed. Use 'show pdfs' and 'pdfinfo <id>' to inspect.{Colors.RESET}")

    def _capture_news(self):
        """Capture financial news with sentiment analysis"""
        crawler = NewsCrawler()
        crawler.crawl(self.store)
        self.store.session_info['capture_mode'] = 'news'
        print(f"{Colors.INFO}[*] Use 'analyze' for full market analysis, 'show news' to list articles{Colors.RESET}")
    
    def _capture_browser(self):
        """Capture using browser"""
        if not self.current_url:
            print(f"{Colors.ERROR}[-] URL not set. Use 'set URL <url>' first{Colors.RESET}")
            return
        
        if not SELENIUM_AVAILABLE:
            print(f"{Colors.ERROR}[-] Selenium not installed. Install with: pip install selenium{Colors.RESET}")
            return
        
        # Start browser
        if not self.browser:
            self.browser = BrowserCapture(headless=self.headless)
            if not self.browser.start():
                print(f"{Colors.ERROR}[-] Failed to start browser{Colors.RESET}")
                self.browser = None
                return
        
        # Navigate to URL
        if not self.browser.navigate(self.current_url):
            print(f"{Colors.ERROR}[-] Failed to navigate to URL{Colors.RESET}")
            return
        
        # Crawl entire site (unlimited pages)
        self.browser.crawl_site(self.store, self.max_pages)
        
        # Update session info
        self.store.session_info['capture_mode'] = 'browser'
    
    # ==================== Analysis Commands ====================
    
    def do_search(self, arg):
        """Search endpoints
        Usage: search <query>"""
        if not arg:
            print(f"{Colors.ERROR}[-] Usage: search <query>{Colors.RESET}")
            return
        
        results = self.store.search(arg)
        
        if results:
            print(f"{Colors.SUCCESS}[+] Found {len(results)} matching endpoints:{Colors.RESET}")
            self._show_endpoints(results)
        else:
            print(f"{Colors.WARNING}[!] No endpoints found matching '{arg}'{Colors.RESET}")
    
    def do_filter(self, arg):
        """Filter endpoints by criteria
        Usage: filter method <METHOD> | filter auth <true|false>"""
        args = shlex.split(arg)
        
        if len(args) < 2:
            print(f"{Colors.ERROR}[-] Usage: filter <method|auth> <value>{Colors.RESET}")
            return
        
        filter_type = args[0].lower()
        filter_value = args[1]
        
        if filter_type == 'method':
            results = self.store.filter_by_method(filter_value)
            print(f"{Colors.SUCCESS}[+] Endpoints with method {filter_value.upper()}:{Colors.RESET}")
            self._show_endpoints(results)
        
        elif filter_type == 'auth':
            auth_required = filter_value.lower() in ['true', '1', 'yes']
            results = self.store.filter_by_auth(auth_required)
            auth_text = "requiring auth" if auth_required else "not requiring auth"
            print(f"{Colors.SUCCESS}[+] Endpoints {auth_text}:{Colors.RESET}")
            self._show_endpoints(results)
        
        else:
            print(f"{Colors.ERROR}[-] Unknown filter type: {filter_type}{Colors.RESET}")
    
    def do_info(self, arg):
        """Show detailed information about an endpoint
        Usage: info <endpoint_id> | info <method> <url>"""
        args = shlex.split(arg)
        
        if not args:
            print(f"{Colors.ERROR}[-] Usage: info <endpoint_id> or info <method> <url>{Colors.RESET}")
            return
        
        endpoint = None
        
        # Try to get by ID
        if args[0].isdigit():
            idx = int(args[0]) - 1
            if 0 <= idx < len(self.store.endpoints):
                endpoint = list(self.store.endpoints.values())[idx]
        else:
            # Try to get by method and URL
            if len(args) >= 2:
                key = f"{args[0].upper()} {args[1]}"
                endpoint = self.store.endpoints.get(key)
        
        if endpoint:
            self._show_endpoint_details(endpoint)
        else:
            print(f"{Colors.ERROR}[-] Endpoint not found{Colors.RESET}")
    
    def _show_endpoint_details(self, endpoint):
        """Show detailed endpoint information"""
        print(f"\n{Colors.HEADER}=== Endpoint Details ==={Colors.RESET}")
        print(f"{Colors.PARAM}Method:{Colors.RESET} {endpoint.method}")
        print(f"{Colors.PARAM}URL:{Colors.RESET} {endpoint.url}")
        print(f"{Colors.PARAM}Calls:{Colors.RESET} {endpoint.call_count}")
        print(f"{Colors.PARAM}First Seen:{Colors.RESET} {endpoint.first_seen}")
        print(f"{Colors.PARAM}Last Seen:{Colors.RESET} {endpoint.last_seen}")
        print(f"{Colors.PARAM}Auth Required:{Colors.RESET} {'Yes' if endpoint.auth_required else 'No'}")
        
        if endpoint.parameters:
            print(f"\n{Colors.PARAM}Parameters:{Colors.RESET}")
            for name, details in endpoint.parameters.items():
                print(f"  {Colors.VALUE}• {name}{Colors.RESET} ({details['type']})")
                if details.get('examples'):
                    print(f"    Examples: {', '.join(str(e) for e in details['examples'][:3])}")
        
        if endpoint.headers:
            print(f"\n{Colors.PARAM}Headers:{Colors.RESET}")
            for key, value in endpoint.headers.items():
                print(f"  {Colors.VALUE}• {key}:{Colors.RESET} {value}")
        
        if endpoint.request_examples:
            print(f"\n{Colors.PARAM}Request Examples ({len(endpoint.request_examples)}):{Colors.RESET}")
            for i, example in enumerate(endpoint.request_examples[:3], 1):
                print(f"  Example {i}:")
                if example.get('params'):
                    print(f"    Params: {json.dumps(example['params'], indent=4)[:200]}")
                if example.get('body'):
                    print(f"    Body: {json.dumps(example['body'], indent=4)[:200]}")
        
        if endpoint.response_examples:
            print(f"\n{Colors.PARAM}Response Examples ({len(endpoint.response_examples)}):{Colors.RESET}")
            for i, example in enumerate(endpoint.response_examples[:3], 1):
                print(f"  Example {i}: Status {example['status_code']}")
        
        if endpoint.notes:
            print(f"\n{Colors.PARAM}Notes:{Colors.RESET}")
            for note in endpoint.notes:
                print(f"  • {note}")
        print()
    
    # ==================== Web Dashboard ====================
    
    def do_ui(self, arg):
        """Launch web dashboard with embedded analysis modal
        Usage: ui [port]"""
        port = int(arg.strip()) if arg.strip().isdigit() else 5000
        
        live_file = str(Path(self.output_dir) / '_live.json')
        self.store.save_to_file(live_file)
        print(f"{Colors.SUCCESS}[+] Live data saved to: {live_file}{Colors.RESET}")
        
        server_path = Path(__file__).resolve().parent / 'server.py'
        if not server_path.exists():
            print(f"{Colors.ERROR}[-] server.py not found next to app.py{Colors.RESET}")
            return
        
        creation_flags = subprocess.CREATE_NEW_CONSOLE if os.name == 'nt' else 0
        subprocess.Popen(
            [sys.executable, str(server_path), '--file', live_file, '--port', str(port)],
            creationflags=creation_flags
        )
        
        time.sleep(2)
        webbrowser.open(f'http://127.0.0.1:{port}')
        print(f"{Colors.SUCCESS}[+] Dashboard opened at http://127.0.0.1:{port}{Colors.RESET}")
        print(f"{Colors.INFO}[*] Press Ctrl+C in the server window to stop it{Colors.RESET}")
    
    # ==================== Export Commands ====================
    
    def do_save(self, arg):
        """Save captured endpoints to file
        Usage: save [filename]"""
        args = shlex.split(arg)
        filename = args[0] if args else None
        
        if filename and not filename.endswith('.json'):
            filename += '.json'
        
        # Save to output directory
        if filename:
            filepath = Path(self.output_dir) / filename
        else:
            filepath = Path(self.output_dir) / f"api_capture_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        
        saved_file = self.store.save_to_file(str(filepath))
        print(f"{Colors.SUCCESS}[+] Endpoints saved to: {saved_file}{Colors.RESET}")
    
    def do_load(self, arg):
        """Load endpoints from file
        Usage: load <filename>"""
        args = shlex.split(arg)
        
        if not args:
            print(f"{Colors.ERROR}[-] Usage: load <filename>{Colors.RESET}")
            return
        
        filename = args[0]
        
        if not Path(filename).exists():
            print(f"{Colors.ERROR}[-] File not found: {filename}{Colors.RESET}")
            return
        
        try:
            self.store.load_from_file(filename)
            print(f"{Colors.SUCCESS}[+] Loaded {len(self.store.endpoints)} endpoints from {filename}{Colors.RESET}")
        except Exception as e:
            print(f"{Colors.ERROR}[-] Failed to load file: {e}{Colors.RESET}")
    
    def do_report(self, arg):
        """Generate HTML report
        Usage: report [filename]"""
        args = shlex.split(arg)
        filename = args[0] if args else f"api_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
        
        if not filename.endswith('.html'):
            filename += '.html'
        
        filepath = Path(self.output_dir) / filename
        self._generate_html_report(str(filepath))
        print(f"{Colors.SUCCESS}[+] Report generated: {filepath}{Colors.RESET}")
    
    def _generate_html_report(self, filepath):
        """Generate HTML report"""
        stats = self.store.get_statistics()
        
        # Build endpoint rows
        endpoint_rows = ""
        for i, (key, endpoint) in enumerate(self.store.endpoints.items(), 1):
            params_list = ", ".join(endpoint.parameters.keys()) if endpoint.parameters else "None"
            auth_badge = '<span class="badge badge-warning">Auth Required</span>' if endpoint.auth_required else '<span class="badge badge-success">Public</span>'
            
            endpoint_rows += f"""
            <tr>
                <td>{i}</td>
                <td><span class="method method-{endpoint.method.lower()}">{endpoint.method}</span></td>
                <td>{endpoint.url}</td>
                <td>{endpoint.call_count}</td>
                <td>{params_list}</td>
                <td>{auth_badge}</td>
            </tr>"""
        
        # Build method statistics
        method_stats = ""
        for method, count in stats['methods'].items():
            method_stats += f"<div class='stat-box'><h3>{method}</h3><p>{count} endpoints</p></div>"
        
        html = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>API Capture Report</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            padding: 20px;
            color: #333;
        }
        
        .container {
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            border-radius: 10px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.2);
            overflow: hidden;
        }
        
        .header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 30px;
            text-align: center;
        }
        
        .header h1 {
            font-size: 2.5em;
            margin-bottom: 10px;
        }
        
        .header p {
            font-size: 1.1em;
            opacity: 0.9;
        }
        
        .stats {
            display: flex;
            justify-content: space-around;
            padding: 30px;
            background: #f8f9fa;
            flex-wrap: wrap;
        }
        
        .stat-box {
            text-align: center;
            padding: 20px;
            background: white;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            min-width: 150px;
            margin: 10px;
        }
        
        .stat-box h3 {
            color: #667eea;
            font-size: 2em;
            margin-bottom: 5px;
        }
        
        .stat-box p {
            color: #666;
            font-size: 0.9em;
        }
        
        .content {
            padding: 30px;
        }
        
        .section {
            margin-bottom: 30px;
        }
        
        .section h2 {
            color: #333;
            margin-bottom: 20px;
            padding-bottom: 10px;
            border-bottom: 2px solid #667eea;
        }
        
        table {
            width: 100%;
            border-collapse: collapse;
            background: white;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            border-radius: 8px;
            overflow: hidden;
        }
        
        th {
            background: #667eea;
            color: white;
            padding: 15px;
            text-align: left;
            font-weight: 600;
        }
        
        td {
            padding: 12px 15px;
            border-bottom: 1px solid #eee;
        }
        
        tr:hover {
            background: #f8f9fa;
        }
        
        .method {
            display: inline-block;
            padding: 4px 8px;
            border-radius: 4px;
            font-weight: bold;
            font-size: 0.85em;
        }
        
        .method-get {
            background: #28a745;
            color: white;
        }
        
        .method-post {
            background: #ffc107;
            color: #333;
        }
        
        .method-put {
            background: #17a2b8;
            color: white;
        }
        
        .method-delete {
            background: #dc3545;
            color: white;
        }
        
        .method-patch {
            background: #6f42c1;
            color: white;
        }
        
        .badge {
            display: inline-block;
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 0.85em;
            font-weight: 600;
        }
        
        .badge-warning {
            background: #fff3cd;
            color: #856404;
        }
        
        .badge-success {
            background: #d4edda;
            color: #155724;
        }
        
        .footer {
            text-align: center;
            padding: 20px;
            background: #f8f9fa;
            color: #666;
            font-size: 0.9em;
        }
        
        @media (max-width: 768px) {
            .stats {
                flex-direction: column;
            }
            
            .stat-box {
                min-width: auto;
            }
            
            table {
                font-size: 0.9em;
            }
            
            th, td {
                padding: 10px;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔒 API Capture Report</h1>
            <p>Security Assessment & Discovery Results</p>
            <p style="margin-top: 10px; font-size: 0.9em;">Generated: """ + datetime.now().strftime("%Y-%m-%d %H:%M:%S") + """</p>
        </div>
        
        <div class="stats">
            <div class="stat-box">
                <h3>""" + str(stats['total_endpoints']) + """</h3>
                <p>Total Endpoints</p>
            </div>
            <div class="stat-box">
                <h3>""" + str(stats['total_parameters']) + """</h3>
                <p>Total Parameters</p>
            </div>
            <div class="stat-box">
                <h3>""" + str(stats['auth_required']) + """</h3>
                <p>Auth Required</p>
            </div>
            <div class="stat-box">
                <h3>""" + str(len(stats['methods'])) + """</h3>
                <p>HTTP Methods</p>
            </div>
        </div>
        
        <div class="content">
            <div class="section">
                <h2>📊 Method Distribution</h2>
                <div class="stats">
                    """ + method_stats + """
                </div>
            </div>
            
            <div class="section">
                <h2>🔗 Captured Endpoints</h2>
                <table>
                    <thead>
                        <tr>
                            <th>ID</th>
                            <th>Method</th>
                            <th>URL</th>
                            <th>Calls</th>
                            <th>Parameters</th>
                            <th>Auth</th>
                        </tr>
                    </thead>
                    <tbody>
                        """ + endpoint_rows + """
                    </tbody>
                </table>
            </div>
        </div>
        
        <div class="footer">
            <p>API Capture Framework v1.0.0 - Security Assessment Tool</p>
            <p>This report contains sensitive security information. Handle with care.</p>
        </div>
    </div>
</body>
</html>"""
        
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(html)
    
    # ==================== Help Command ====================
    
    def do_help(self, arg):
        """List available commands with their descriptions"""
        if arg:
            # Show help for specific command
            cmd.Cmd.do_help(self, arg)
        else:
            print(f"\n{Colors.HEADER}=== Available Commands ==={Colors.RESET}")
            print(f"{Colors.PARAM}Core Commands:{Colors.RESET}")
            print(f"  {Colors.VALUE}help{Colors.RESET}          - Show this help message")
            print(f"  {Colors.VALUE}banner{Colors.RESET}        - Display the banner")
            print(f"  {Colors.VALUE}clear{Colors.RESET}         - Clear the screen")
            print(f"  {Colors.VALUE}exit/quit{Colors.RESET}      - Exit the framework")
            
            print(f"\n{Colors.PARAM}Configuration:{Colors.RESET}")
            print(f"  {Colors.VALUE}set{Colors.RESET}           - Set configuration options (URL, MAXPAGES, OUTPUT, HEADLESS)")
            print(f"  {Colors.VALUE}show{Colors.RESET}          - Show configuration, endpoints, statistics, PDFs, or pages")
            
            print(f"\n{Colors.PARAM}Capture Commands:{Colors.RESET}")
            print(f"  {Colors.VALUE}capture{Colors.RESET}       - Smart full-site crawl (browser/stocks/news/manual)")
            print(f"  {Colors.VALUE}capture press{Colors.RESET} - ALL CSE press releases [{CSE_PRESS_RELEASES_URL}] (Firecrawl/Apify/Crawl4AI + API) + download PDFs & extract")
            print(f"  {Colors.VALUE}capture annual{Colors.RESET}- ALL CSE annual reports [{CSE_ANNUAL_REPORTS_URL}] (16 PDFs 2010-2025) + download & extract")
            print(f"  {Colors.VALUE}capture cse{Colors.RESET}   - BOTH press releases + annual reports (recommended, uses all engines)")
            print(f"  {Colors.VALUE}set URL{Colors.RESET}       - Set target URL before browser capture")
            print(f"    Engines priority: Firecrawl (FIRECRAWL_API_KEY) -> Apify (APIFY_TOKEN) -> Crawl4AI -> Selenium -> Requests/API")
            print(f"    CSE API: {CSE_PRESS_API} (direct) + HTML fallback")
            
            print(f"\n{Colors.PARAM}Stock & News Commands:{Colors.RESET}")
            print(f"  {Colors.VALUE}show stocks{Colors.RESET}   - List captured stock records")
            print(f"  {Colors.VALUE}stockinfo{Colors.RESET}     - Show full record for a stock symbol")
            print(f"  {Colors.VALUE}show news{Colors.RESET}     - List captured news articles")
            print(f"  {Colors.VALUE}newsinfo{Colors.RESET}      - Show article details with sentiment")
            
            print(f"\n{Colors.PARAM}Analysis Commands:{Colors.RESET}")
            print(f"  {Colors.VALUE}search{Colors.RESET}        - Search for endpoints")
            print(f"  {Colors.VALUE}filter{Colors.RESET}        - Filter endpoints by criteria")
            print(f"  {Colors.VALUE}info{Colors.RESET}          - Show detailed endpoint information")
            print(f"  {Colors.VALUE}analyze{Colors.RESET}       - Market analysis (sentiment + correlations)")
            print(f"  {Colors.VALUE}models{Colors.RESET}        - View AI models and crawlers catalog")
            
            print(f"\n{Colors.PARAM}Export Commands:{Colors.RESET}")
            print(f"  {Colors.VALUE}save{Colors.RESET}          - Save all captured data (endpoints, stocks, news, PDFs) to JSON")
            print(f"  {Colors.VALUE}load{Colors.RESET}          - Load data from JSON file")
            print(f"  {Colors.VALUE}report{Colors.RESET}        - Generate HTML report")
            
            print(f"\n{Colors.PARAM}PDF Commands:{Colors.RESET}")
            print(f"  {Colors.VALUE}show pdfs{Colors.RESET}     - List captured PDF documents")
            print(f"  {Colors.VALUE}pdfinfo{Colors.RESET}       - Show extracted text from a PDF")
            
            print(f"\n{Colors.PARAM}Web Dashboard:{Colors.RESET}")
            print(f"  {Colors.VALUE}ui{Colors.RESET}            - Launch web dashboard with analysis modal")
            
            print(f"\n{Colors.INFO}Quick Start (CSE Docs):{Colors.RESET}")
            print(f"  {Colors.VALUE}capture cse{Colors.RESET}        (reads ALL press releases + ALL annual reports, downloads PDFs, extracts data)")
            print(f"  {Colors.VALUE}show pdfs{Colors.RESET}          (list press + annual PDFs with type)")
            print(f"  {Colors.VALUE}pdfinfo 1{Colors.RESET}           (show extracted text + sentiment + financial entities)")
            print(f"  {Colors.VALUE}analyze{Colors.RESET}            (market sentiment over news/PDFs + CSE docs)")
            print(f"  {Colors.VALUE}save{Colors.RESET}               (persist to api_captures/*.json)")
            print(f"\n{Colors.INFO}Legacy Quick Start:{Colors.RESET}")
            print(f"  1. {Colors.VALUE}set URL https://www.cse.lk/{Colors.RESET}")
            print(f"  2. {Colors.VALUE}capture stocks{Colors.RESET}   (full-site crawl + stock extraction)")
            print(f"  3. {Colors.VALUE}capture news{Colors.RESET}     (Sri Lankan financial news + sentiment)")
            print(f"  4. {Colors.VALUE}analyze{Colors.RESET}          (market analysis)")
            print(f"  5. {Colors.VALUE}save{Colors.RESET}             (structured JSON export)")
            print(f"  6. {Colors.VALUE}ui{Colors.RESET}               (web dashboard with analysis modal)")
            print()
            print(f"{Colors.PARAM}CSE Engines:{Colors.RESET} Firecrawl={'yes' if FIRECRAWL_AVAILABLE else 'not installed'} | Apify={'yes' if APIFY_AVAILABLE else 'not installed'} | Crawl4AI={'yes' if CRAWL4AI_AVAILABLE else 'not installed'} | Selenium={'yes' if SELENIUM_AVAILABLE else 'no'} | Requests={'yes' if REQUESTS_AVAILABLE else 'no'}")
            print(f"  Install: pip install firecrawl-py apify-client crawl4ai  (optional, fallback to Requests+Selenium)")
            print()


def main():
    """Main function to start the console"""
    parser = argparse.ArgumentParser(description='API Capture Framework')
    parser.add_argument('--headless', action='store_true', help='Start in headless mode')
    parser.add_argument('--url', help='Target URL to capture from')
    parser.add_argument('--max-pages', type=int, default=0, help='Max pages to crawl (0 = unlimited)')
    
    args = parser.parse_args()
    
    try:
        console = APICaptureConsole()
        
        # Set initial values from command line arguments
        if args.headless:
            console.headless = True
        
        if args.url:
            console.current_url = args.url
            console.store.session_info['target_url'] = args.url
        
        if args.max_pages:
            console.max_pages = args.max_pages
        
        # Start the console
        console.cmdloop()
        
    except KeyboardInterrupt:
        print(f"\n{Colors.INFO}[*] Interrupted by user{Colors.RESET}")
        print(f"{Colors.INFO}[*] Goodbye!{Colors.RESET}")
    except Exception as e:
        print(f"{Colors.ERROR}[!] Fatal error: {e}{Colors.RESET}")
        import traceback
        traceback.print_exc()
        return 1
    
    return 0


if __name__ == "__main__":
    sys.exit(main())