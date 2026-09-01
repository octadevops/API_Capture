#!/usr/bin/env python3
"""
Streamlit — Silent CSE Capture + Trained Model Analysis
Deploy to Streamlit Cloud: point to this file. All captures run silently (no Colors console).
Trained model: models/trained_analyzer.TrainedCSEAnalyzer (env TRAINED_MODEL_PATH -> local -> ProsusAI/finbert -> lexicon).

Features:
 - Auto-loads api_captures/_live.json if exists
 - Silent "Capture All" button (press releases + annual reports) with progress bar
 - Trained-model sentiment re-analysis over captured texts
 - Dashboards: KPIs, PDF browser, news table, sentiment charts (plotly)
 - Silent background thread — UI never blocks on downloads
"""
import os
import json
import time
import logging
from pathlib import Path
from datetime import datetime
from typing import Dict, List

# Load .env for keys when running locally (Streamlit Cloud uses secrets.toml)
try:
    from dotenv import load_dotenv
    load_dotenv(dotenv_path=Path(__file__).resolve().parent / ".env")
except Exception:
    pass

import streamlit as st

# Bridge Streamlit Cloud secrets -> os.environ so CSEEngine / TrainedAnalyzer see them
try:
    for _k in ["FIRECRAWL_API_KEY", "FIRECRAWL_API_TOKEN", "APIFY_TOKEN", "APIFY_API_TOKEN", "TRAINED_MODEL_PATH", "CSE_MODEL_PATH", "CSE_ENGINE_ORDER", "HF_TOKEN"]:
        if _k in st.secrets:
            os.environ[_k] = str(st.secrets[_k])
except Exception:
    pass

# Page config must be first
st.set_page_config(
    page_title="CSE Silent Capture — Press & Annual Reports",
    page_icon="📊",
    layout="wide",
    initial_sidebar_state="expanded",
)

# Lazy heavy imports (keep startup fast)
from silent_capture import SilentCaptureService
from models.trained_analyzer import get_analyzer

# Paths
LIVE_PATH = Path("api_captures/_live.json")
OUTPUT_DIR = Path("api_captures")

# ---- Cache: trained model ----
@st.cache_resource(show_spinner=False)
def load_trained_analyzer(model_path: str = None):
    try:
        analyzer = get_analyzer(model_path=model_path)
        return analyzer
    except Exception as e:
        logging.exception(e)
        # Fallback to lexicon-only
        from models.trained_analyzer import TrainedCSEAnalyzer
        return TrainedCSEAnalyzer(model_path=None)

# ---- Helpers ----
def load_live_data() -> Dict:
    if LIVE_PATH.exists():
        try:
            with open(LIVE_PATH, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception as e:
            st.warning(f"Failed to load {LIVE_PATH}: {e}")
    # Fallback: newest snapshot
    snaps = sorted(OUTPUT_DIR.glob("api_capture_*.json"), key=lambda p: p.stat().st_mtime, reverse=True)
    if snaps:
        try:
            with open(snaps[0], "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            pass
    return {"pdfs": {}, "news": {}, "stocks": {}, "endpoints": {}, "pages_visited": [], "statistics": {}, "metadata": {}}

def kpi_cards(data: Dict, analyzer_info: Dict):
    stats = data.get("statistics", {})
    summary = {
        "Press PDFs": stats.get("press_release_pdfs", sum(1 for p in data.get("pdfs", {}).values() if p.get("doc_type") == "press_release")),
        "Annual PDFs": stats.get("annual_report_pdfs", sum(1 for p in data.get("pdfs", {}).values() if p.get("doc_type") == "annual_report")),
        "Total PDFs": len(data.get("pdfs", {})),
        "News": len(data.get("news", {})),
        "Pages": len(data.get("pages_visited", [])),
        "Model": analyzer_info.get("engine", "lexicon"),
    }
    cols = st.columns(len(summary))
    for (label, val), col in zip(summary.items(), cols):
        col.metric(label, val)

def sentiment_chart(data: Dict):
    try:
        import plotly.express as px
        import pandas as pd
    except ImportError:
        st.info("Install plotly for charts: pip install plotly")
        return
    records = []
    for pdf in data.get("pdfs", {}).values():
        s = pdf.get("sentiment")
        if s:
            records.append({"source": pdf.get("doc_type", "pdf"), "label": s.get("label", "Neutral"), "score": s.get("score", 0.5)})
    for n in data.get("news", {}).values():
        s = n.get("sentiment")
        if s:
            records.append({"source": "news", "label": s.get("label", "Neutral"), "score": s.get("score", 0.5)})
    if not records:
        st.caption("No sentiment data yet — run capture.")
        return
    df = pd.DataFrame(records)
    c1, c2 = st.columns(2)
    with c1:
        fig = px.histogram(df, x="label", color="label", title="Sentiment Distribution", color_discrete_map={"Positive": "#16a34a", "Negative": "#dc2626", "Neutral": "#64748b"})
        fig.update_layout(height=320, margin=dict(t=40, b=20))
        st.plotly_chart(fig, use_container_width=True)
    with c2:
        fig2 = px.box(df, x="label", y="score", color="label", title="Score by Label")
        fig2.update_layout(height=320, margin=dict(t=40, b=20))
        st.plotly_chart(fig2, use_container_width=True)

# ---- Sidebar ----
with st.sidebar:
    st.title("⚙️ Controls")
    st.caption("Silent capture — no console. Trained model auto-loads.")
    # Model selector
    model_opts = ["(auto) Trained → FinBERT → lexicon", "ProsusAI/finbert", "ahmedrachid/FinancialBERT-Sentiment-Analysis", "lexicon (no model)"]
    model_choice = st.selectbox("Trained model", model_opts, index=0, help="Env TRAINED_MODEL_PATH overrides if set. Place fine-tuned checkpoint at models/cse_finbert.")
    if model_choice.startswith("(auto)"):
        model_path = os.environ.get("TRAINED_MODEL_PATH") or os.environ.get("CSE_MODEL_PATH") or None
    elif model_choice == "lexicon (no model)":
        model_path = "__lexicon__"
    else:
        model_path = model_choice

    st.divider()
    st.subheader("📥 Silent Capture")
    st.caption("Runs headless: Press releases (285) + Annual reports (16). No popups.")
    press_max = st.number_input("Press releases limit (0 = all 285)", min_value=0, max_value=500, value=0, step=5, help="Set small (e.g. 5) for fast Streamlit demo.")
    annual_dl = st.checkbox("Download annual report PDFs", value=True, help="Uncheck to skip large PDFs (faster).")
    col_a, col_b = st.columns(2)
    capture_btn = col_a.button("🚀 Capture All Silently", type="primary", use_container_width=True, help="Runs in background, shows progress bar.")
    refresh_btn = col_b.button("🔄 Refresh Data", use_container_width=True)

    st.divider()
    auto_capture = st.checkbox("Auto-capture on startup if no data", value=False, help="If checked and no _live.json, capture 5 press releases silently on load.")
    st.caption("Engine priority: Firecrawl (FIRECRAWL_API_KEY) → Apify (APIFY_TOKEN) → Crawl4AI → Selenium → Requests/API")

    # Re-analyze with trained model
    st.divider()
    st.subheader("🤖 Trained Model Re-analysis")
    reanalyze_btn = st.button("Re-run Trained Model on Captured Texts", use_container_width=True, help="Re-scores all news+PDFs with selected trained model.")

# ---- Load analyzer (cached) ----
if model_path == "__lexicon__":
    # Force lexicon by passing nonsense path that fails
    analyzer = load_trained_analyzer(model_path="/nonexistent_lexicon__")
    # Ensure fallback
    analyzer.engine = "lexicon"
    analyzer._pipe = None
else:
    analyzer = load_trained_analyzer(model_path=model_path if model_path else None)

# ---- Capture handler ----
if capture_btn:
    svc = SilentCaptureService(output_dir=str(OUTPUT_DIR))
    progress_bar = st.progress(0, text="Starting silent capture...")
    log_area = st.empty()

    def cb(msg: str, pct: float):
        if pct >= 0:
            try:
                progress_bar.progress(min(1.0, pct), text=msg[:80])
            except Exception:
                pass
        log_area.caption(msg)

    svc.set_progress_callback(cb)
    with st.spinner("Silent capture running — fetching CSE press releases & annual reports (headless). This may take 1-4 min for full set."):
        result = svc.capture_all_silently(press_max=int(press_max), annual_download=bool(annual_dl))
    if result.get("status") == "success":
        st.success(f"✅ Silent capture done: {result['press_count']} press + {result['annual_count']} annual | {result['elapsed_s']}s | snapshot {Path(result['snapshot']).name}")
        progress_bar.progress(1.0, text="Done")
        st.rerun()
    else:
        st.error(f"Capture failed: {result.get('error')}")

if refresh_btn:
    st.rerun()

# ---- Auto-capture if enabled ----
if auto_capture and not LIVE_PATH.exists() and not st.session_state.get("_auto_done", False):
    st.session_state["_auto_done"] = True
    svc = SilentCaptureService(output_dir=str(OUTPUT_DIR))
    with st.spinner("Auto silent capture (5 press releases demo)..."):
        svc.capture_all_silently(press_max=5, annual_download=False)
    st.toast("Auto-capture of 5 press releases done.")
    st.rerun()

# ---- Main ----
st.title("📊 CSE — Silent Capture & Trained Model Analysis")
st.caption("Press releases: https://www.cse.lk/news-events/press-releases  ·  Annual reports: https://www.cse.lk/about-us/corporate-profile/annual-reports  ·  Silent (headless) · Deployable on Streamlit Cloud")

data = load_live_data()
analyzer_info = analyzer.info() if hasattr(analyzer, "info") else {"engine": getattr(analyzer, "engine", "lexicon")}

# KPIs
kpi_cards(data, analyzer_info)

# Model banner
with st.expander("🤖 Trained Model Info", expanded=False):
    st.json(analyzer_info)
    st.caption("Priority: TRAINED_MODEL_PATH env → models/cse_finbert (local fine-tune) → ProsusAI/finbert → lexicon. Train with: `python models/train.py --data api_captures/_live.json`")

# Re-analysis logic
if reanalyze_btn:
    if not data.get("pdfs") and not data.get("news"):
        st.warning("No captured data to re-analyze. Run Capture first.")
    else:
        bar = st.progress(0, text="Re-analyzing with trained model...")
        # Re-score news
        news = data.get("news", {})
        pdfs = data.get("pdfs", {})
        total = len(news) + len(pdfs)
        done = 0
        for url, rec in news.items():
            txt = (rec.get("title","") + ". " + rec.get("text",""))[:2000]
            rec["sentiment"] = analyzer.analyze(txt)
            done += 1
            bar.progress(done / max(1, total))
        for url, rec in pdfs.items():
            txt = (rec.get("title","") + " " + rec.get("text_preview","") + " " + rec.get("text_full","")[:2000])[:3000]
            rec["sentiment"] = analyzer.analyze(txt)
            done += 1
            bar.progress(done / max(1, total))
        # Persist back to _live.json
        try:
            # Reload store and overwrite sentiments then save
            svc = SilentCaptureService(output_dir=str(OUTPUT_DIR))
            store = svc.load_live_store()
            for url, rec in news.items():
                if url in store.news_records:
                    store.news_records[url]["sentiment"] = rec["sentiment"]
            for url, rec in pdfs.items():
                if url in store.pdfs:
                    store.pdfs[url]["sentiment"] = rec["sentiment"]
            store.save_to_file(str(LIVE_PATH))
            st.success(f"Re-analyzed {len(news)} news + {len(pdfs)} PDFs with engine `{analyzer.engine}` ({analyzer.model_path})")
            bar.progress(1.0, text="Done")
            time.sleep(0.6)
            st.rerun()
        except Exception as e:
            st.error(f"Failed to persist re-analysis: {e}")

# Charts
st.divider()
st.subheader("Sentiment — Trained Model")
sentiment_chart(data)

# Tabs: PDFs / News / Pages / Raw JSON
tab_pdf, tab_news, tab_pages, tab_raw = st.tabs(["📄 PDFs (Press & Annual)", "📰 News / Releases", "🌐 Pages Visited", "🧾 Raw JSON"])

with tab_pdf:
    pdfs = list(data.get("pdfs", {}).values())
    if not pdfs:
        st.info("No PDFs yet. Click **Capture All Silently**.")
    else:
        # Filters
        f1, f2, f3 = st.columns([2, 2, 3])
        dtype_filter = f1.selectbox("Doc type", ["All", "press_release", "annual_report", "other"], index=0)
        sent_filter = f2.selectbox("Sentiment", ["All", "Positive", "Negative", "Neutral"], index=0)
        search = f3.text_input("Search title/url", "", placeholder="e.g. 2024, dividend, HNB")
        filtered = pdfs
        if dtype_filter != "All":
            filtered = [p for p in filtered if p.get("doc_type") == dtype_filter]
        if sent_filter != "All":
            filtered = [p for p in filtered if p.get("sentiment", {}).get("label") == sent_filter]
        if search.strip():
            q = search.lower()
            filtered = [p for p in filtered if q in (p.get("title","")+p.get("url","")+p.get("filepath","")).lower()]
        st.caption(f"Showing {len(filtered)} / {len(pdfs)} PDFs")
        # Table
        import pandas as pd
        rows = []
        for p in filtered[:200]:
            rows.append({
                "Type": p.get("doc_type", "other"),
                "Year": p.get("year", ""),
                "Pages": p.get("page_count", 0),
                "Sentiment": p.get("sentiment", {}).get("label", "-"),
                "Score": p.get("sentiment", {}).get("score", ""),
                "Title": (p.get("title","")[:70]),
                "File": Path(p.get("filepath","")).name,
                "URL": p.get("url",""),
            })
        if rows:
            df = pd.DataFrame(rows)
            st.dataframe(df, use_container_width=True, height=380)
        # Detail expander for first selected
        if filtered:
            sel = st.selectbox("Inspect PDF detail", options=list(range(len(filtered))), format_func=lambda i: f"{i+1}. {filtered[i].get('title','')[:60]} — {Path(filtered[i].get('filepath','')).name}", index=0)
            rec = filtered[sel]
            with st.expander("Detail", expanded=True):
                st.write(f"**URL:** {rec.get('url')}")
                st.write(f"**File:** `{rec.get('filepath')}`  |  Pages: {rec.get('page_count')}  |  Doc type: `{rec.get('doc_type')}`")
                if rec.get("sentiment"):
                    st.write(f"**Sentiment:** {rec['sentiment']['label']} ({rec['sentiment']['score']}, engine `{rec['sentiment']['engine']}`)")
                if rec.get("financial_entities"):
                    st.json(rec["financial_entities"])
                txt = rec.get("text_full") or rec.get("text_preview") or ""
                st.text_area("Extracted text (first 4000 chars)", txt[:4000], height=260)
                if rec.get("url"):
                    st.link_button("Open PDF URL", rec["url"])

with tab_news:
    news = list(data.get("news", {}).values())
    if not news:
        st.info("No news yet.")
    else:
        import pandas as pd
        news_sorted = sorted(news, key=lambda x: x.get("published") or x.get("captured_at") or "", reverse=True)
        df = pd.DataFrame([{
            "Source": n.get("source",""),
            "Sentiment": n.get("sentiment", {}).get("label",""),
            "Score": n.get("sentiment", {}).get("score",""),
            "Title": n.get("title","")[:80],
            "Published": n.get("published",""),
        } for n in news_sorted[:200]])
        st.dataframe(df, use_container_width=True, height=380)
        sel_n = st.selectbox("Inspect article", options=list(range(min(len(news_sorted), 50))), format_func=lambda i: news_sorted[i].get("title","")[:70], index=0)
        if sel_n is not None and news_sorted:
            rec = news_sorted[sel_n]
            st.write(f"**{rec.get('title')}** — {rec.get('source')} ({rec.get('published')})")
            st.write(rec.get("text","")[:3000])
            st.caption(rec.get("url",""))

with tab_pages:
    pages = data.get("pages_visited", [])
    st.caption(f"{len(pages)} pages visited (press releases + annual report pages + PDF URLs)")
    if pages:
        st.dataframe({"URL": pages[:500]}, use_container_width=True, height=320)

with tab_raw:
    st.caption(f"Data: {LIVE_PATH} — {len(json.dumps(data))//1024} KB")
    c1, c2 = st.columns(2)
    if c1.button("Download _live.json"):
        st.download_button("Download", data=json.dumps(data, indent=2), file_name="_live.json", mime="application/json", use_container_width=True)
    if c2.button("Clear _live.json (reset)"):
        try:
            LIVE_PATH.unlink(missing_ok=True)
            st.success("Cleared. Refresh page.")
        except Exception as e:
            st.error(str(e))
    st.json({k: f"<{len(v)} items>" if isinstance(v, dict) else f"{len(v)} items" if isinstance(v, list) else v for k, v in data.get("statistics", {}).items()})

st.divider()
st.caption("Silent capture runs headless (no console). Trained model: set TRAINED_MODEL_PATH or drop fine-tuned checkpoint at models/cse_finbert. Train: `python models/train.py`. Deploy: `streamlit run streamlit_app.py`.")
