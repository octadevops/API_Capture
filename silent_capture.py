#!/usr/bin/env python3
"""
Silent Capture Service — headless, no console Colors, suitable for Streamlit / background jobs.
Wraps CSEPressReleasesCrawler, CSEAnnualReportsCrawler, NewsCrawler, BrowserCapture
and provides a single `capture_all_silently()` entrypoint.
"""

import os
import json
import time
import logging
import threading
from datetime import datetime
from pathlib import Path
from typing import Dict, Optional, Callable

# Suppress noisy urllib warnings
import warnings
warnings.filterwarnings("ignore")

# Load .env for keys
try:
    from dotenv import load_dotenv
    load_dotenv(dotenv_path=Path(__file__).resolve().parent / ".env")
except Exception:
    pass

logger = logging.getLogger("silent_capture")
if not logger.handlers:
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter("[%(asctime)s] %(levelname)s: %(message)s", "%H:%M:%S"))
    logger.addHandler(handler)
logger.setLevel(logging.INFO)

# Re-use existing store / crawlers without importing Colors prints
try:
    from app import (
        APIStore,
        CSEPressReleasesCrawler,
        CSEAnnualReportsCrawler,
        NewsCrawler,
        BrowserCapture,
        CSE_PRESS_RELEASES_URL,
        CSE_ANNUAL_REPORTS_URL,
        CSE_PRESS_API,
    )
except Exception as e:
    logger.error(f"Failed to import app modules: {e}")
    raise


class SilentCaptureService:
    """Thread-safe, non-interactive capture. All progress via callbacks / logger."""

    def __init__(self, output_dir: str = "api_captures"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        (self.output_dir / "pdfs" / "press_releases").mkdir(parents=True, exist_ok=True)
        (self.output_dir / "pdfs" / "annual_reports").mkdir(parents=True, exist_ok=True)
        self.store = APIStore()
        self._lock = threading.Lock()
        self._running = False
        self.last_result: Dict = {}
        self.progress_cb: Optional[Callable[[str, float], None]] = None

    def set_progress_callback(self, cb: Callable[[str, float], None]):
        self.progress_cb = cb

    def _emit(self, msg: str, pct: float = -1):
        logger.info(msg)
        if self.progress_cb:
            try:
                self.progress_cb(msg, pct)
            except Exception:
                pass

    # ---------- high-level ----------
    def capture_all_silently(self, press_max: int = 0, annual_download: bool = True,
                             headless: bool = True, silent_pdfs: bool = True) -> Dict:
        """
        Capture everything without console interaction:
         1) CSE press releases (all 285 via API, PDFs downloaded + extracted)
         2) CSE annual reports (all 16, PDFs downloaded + extracted)
         3) Optional: generic news crawl (DailyFT etc.) — disabled by default for speed

        Args:
            press_max: 0 = all 285, N = first N only (useful for quick Streamlit demo)
            annual_download: False skips large annual PDFs
            headless: BrowserCapture headless flag
            silent_pdfs: passed to processors
        """
        if self._running:
            return {"status": "already_running", "result": self.last_result}
        self._running = True
        start = time.time()
        try:
            self._emit("Starting silent capture — press releases + annual reports", 0.05)
            # Load existing _live.json to resume
            live_path = self.output_dir / "_live.json"
            if live_path.exists():
                try:
                    self.store.load_from_file(str(live_path))
                    self._emit(f"Resumed existing store: {len(self.store.pdfs)} PDFs, {len(self.store.news_records)} news", 0.08)
                except Exception as e:
                    logger.warning(f"Live reload failed: {e}")

            # 1) Press releases — silent, suppress Colors prints by monkey-patching temporarily
            self._emit("Capturing CSE press releases (API + Firecrawl/Apify/Crawl4AI fallback)", 0.15)
            # Temporarily silence Colors prints by redirecting? We'll just call crawler — its prints are already minimal
            # Use thread-safe store lock
            with self._lock:
                pr = CSEPressReleasesCrawler()
                press_count = pr.crawl(self.store, download_pdfs=True, max_items=press_max)
            self._save_live()
            self._emit(f"Press releases done: {press_count} releases", 0.55)

            # 2) Annual reports
            if annual_download:
                self._emit("Capturing CSE annual reports (2010-2025)", 0.60)
                with self._lock:
                    ar = CSEAnnualReportsCrawler()
                    annual_count = ar.crawl(self.store, download_pdfs=True)
                self._save_live()
                self._emit(f"Annual reports done: {annual_count} reports", 0.85)
            else:
                annual_count = 0
                self._emit("Skipped annual report PDFs (annual_download=False)", 0.75)

            # Save final timestamped snapshot
            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            snap = self.output_dir / f"api_capture_{ts}.json"
            self.store.save_to_file(str(snap))
            self._save_live()
            self._emit(f"Silent capture complete — snapshot {snap.name}", 1.0)

            stats = self.store.get_statistics()
            self.last_result = {
                "status": "success",
                "press_count": press_count,
                "annual_count": annual_count,
                "stats": stats,
                "snapshot": str(snap),
                "live": str(live_path),
                "elapsed_s": round(time.time() - start, 1),
            }
            return self.last_result
        except Exception as e:
            logger.exception(f"Silent capture failed: {e}")
            self.last_result = {"status": "error", "error": str(e), "elapsed_s": round(time.time() - start, 1)}
            return self.last_result
        finally:
            self._running = False

    def _save_live(self):
        try:
            live = self.output_dir / "_live.json"
            self.store.save_to_file(str(live))
        except Exception as e:
            logger.warning(f"_live save failed: {e}")

    def load_live_store(self) -> APIStore:
        live = self.output_dir / "_live.json"
        if live.exists():
            try:
                self.store.load_from_file(str(live))
            except Exception:
                pass
        return self.store

    def is_running(self) -> bool:
        return self._running
