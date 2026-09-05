import streamlit as st
import pandas as pd
import os
import base64
import textwrap
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from src.data_loader import load_or_generate
from src.attack_detector import run_pipeline
from src import report_generator

# ============================================================
# PAGE CONFIGURATION
# ============================================================

st.set_page_config(
    page_title="DeepSpace CyberShield AI",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed"
)


# ============================================================
# FILE PATHS
# ============================================================

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

IMAGE_DIR = os.path.join(BASE_DIR, "static", "images")
DATASET_PATH = os.path.join(BASE_DIR, "dataset", "communication_logs.csv")

LOGO_PATH = os.path.join(IMAGE_DIR, "logo.png")
EARTH_PATH = os.path.join(IMAGE_DIR, "earth.png")
SATELLITE_PATH = os.path.join(IMAGE_DIR, "satellite.png")
DEFENSE_PATH = os.path.join(IMAGE_DIR, "deep-space-cyber-defense.png")
AI_NETWORK_PATH = os.path.join(IMAGE_DIR, "ai-network.png")
ANOMALY_PATH = os.path.join(IMAGE_DIR, "anomaly-detection.png")
HERO_BG_PATH = os.path.join(IMAGE_DIR, "hero-bg.jpg")


@st.cache_data(show_spinner=False)
def _b64_image(path):
    """Base64-encode a local image so it can be used as a CSS background."""
    try:
        with open(path, "rb") as f:
            return base64.b64encode(f.read()).decode("utf-8")
    except Exception:
        return None


_hero_bg_b64 = _b64_image(HERO_BG_PATH)
_splash_bg_b64 = _hero_bg_b64  # reuse the same plate, dimmed differently, behind the splash


# ============================================================
# LOAD DATA + RUN THE REAL DETECTION PIPELINE
# (AI Behavioral Engine -> TTL-Evidence -> DSSLV -> Dynamic TTL Decay)
# Pipeline logic itself is completely untouched below - only the app flow
# around it (which screen you're on, where the file comes from) changed.
# ============================================================

@st.cache_data(show_spinner=False)
def load_and_analyze():
    raw = load_or_generate(DATASET_PATH)
    result = run_pipeline(raw)
    metrics = report_generator.summarize(result)
    return result, metrics


@st.cache_data(show_spinner=False)
def analyze_uploaded(raw_df: pd.DataFrame):
    """Run the exact same detection pipeline against a dataframe the user
    uploaded, instead of the built-in fleet dataset."""
    result = run_pipeline(raw_df)
    metrics = report_generator.summarize(result)
    return result, metrics


def get_active_result():
    """Single entry point that returns (data, metrics) for whichever data
    source the user picked in Mission Control - default fleet file, or
    their own uploaded CSV."""
    ss = st.session_state
    if ss.mission_data_source == "upload" and ss.uploaded_raw_df is not None:
        return analyze_uploaded(ss.uploaded_raw_df)
    return load_and_analyze()


# ============================================================
# SESSION STATE
#
# app_stage drives which *screen* is visible - only one is ever rendered
# at a time, instead of the whole site being stacked on one long page:
#   "intro"     -> splash screen
#   "home"      -> hero + features + AI workflow + Mission Control
#                  (pick attack type, pick data source, Start Analysis)
#   "loading"   -> nothing but the animated analysis console
#   "results"   -> nothing but the ranked-threat investigation view
#   "dashboard" -> optional deeper analytics (accuracy, charts, full
#                  bundle table) - opened on demand from the results screen
# ============================================================

st.session_state.setdefault("app_stage", "intro")
st.session_state.setdefault("mission_selected_bundle", None)
st.session_state.setdefault("mission_threat_index", 0)
st.session_state.setdefault("mission_selected_rank", 1)
st.session_state.setdefault("mission_selected_attack", "All Detected Threats")
st.session_state.setdefault("mission_data_source", "default")
st.session_state.setdefault("uploaded_raw_df", None)
st.session_state.setdefault("uploaded_file_name", None)


def safe_text(value):
    import html
    return html.escape(str(value))


def goto(stage):
    st.session_state.app_stage = stage
    st.rerun()


# ============================================================
# SCORE + THREAT RANKING HELPERS  (pipeline output is untouched below)
# ============================================================

RANK_META = {
    1: {"icon": "🥇", "name": "CRITICAL", "class": "critical"},
    2: {"icon": "🥈", "name": "HIGH RISK", "class": "high"},
    3: {"icon": "🥉", "name": "SUSPICIOUS", "class": "suspicious"},
    4: {"icon": "🔵", "name": "MEDIUM", "class": "medium"},
    5: {"icon": "🟢", "name": "LOW", "class": "low"},
}

def as_score(value, default=0.0):
    """Safely normalize pipeline scores to 0-100 for display/ranking."""
    try:
        value = float(value)
    except Exception:
        return float(default)
    if pd.isna(value):
        return float(default)
    if 0 <= value <= 1:
        value *= 100
    return max(0.0, min(100.0, value))

def score_bar(label, score, icon=""):
    normalized_score = as_score(score)
    return f"""
    <div class="score-row">
        <div class="score-row-head">
            <span>{icon} {safe_text(label)}</span>
            <strong>{normalized_score:.1f}%</strong>
        </div>
        <div class="score-track">
            <div class="score-fill" style="width:{normalized_score:.1f}%"></div>
        </div>
    </div>
    """


def first_available(row, columns, default=0.0):
    for column in columns:
        if column in row.index:
            value = row.get(column)
            if pd.notna(value):
                return as_score(value, default)
    return float(default)


def infer_attack_type(row):
    values = " ".join(
        str(row.get(c, "")) for c in [
            "attack_type", "status", "verdict", "reasons",
            "relay_path", "source"
        ] if c in row.index
    ).lower()

    if any(k in values for k in ["spoof", "impersonat", "forg"]):
        return "Spoofing Attack"
    if any(k in values for k in ["replay", "duplicate", "repeat"]):
        return "Replay Attack"
    if any(k in values for k in ["relay", "lineage", "route", "path"]):
        return "Relay Path Attack"
    return "Behavioral Anomaly"

def filter_attack(frame, attack):
    if attack == "All Detected Threats":
        return frame.copy()

    classified = frame.copy()
    classified["_attack_type_ui"] = classified.apply(infer_attack_type, axis=1)
    return classified[classified["_attack_type_ui"] == attack].copy()

def build_threat_ranking(frame):
    ranked = frame.copy()
    if ranked.empty:
        ranked["_rank"] = pd.Series(dtype="int64")
        ranked["_threat_score"] = pd.Series(dtype="float64")
        return ranked

    ranked["_ai_score"] = ranked.apply(
        lambda r: first_available(r, ["anomaly_confidence", "ai_score", "anomaly_score"]), axis=1
    )
    ranked["_trust_score"] = ranked.apply(
        lambda r: first_available(r, ["trust_score", "dynamic_trust", "ttl_evidence_score"]), axis=1
    )
    ranked["_lineage_score"] = ranked.apply(
        lambda r: first_available(r, ["lineage_score", "dsslv_score", "lineage_confidence"]), axis=1
    )
    ranked["_combined_score"] = ranked.apply(
        lambda r: first_available(r, ["combined_confidence", "combined_score", "final_score"]), axis=1
    )

    if "priority_score" in ranked.columns:
        priority = pd.to_numeric(ranked["priority_score"], errors="coerce").fillna(0).apply(as_score)
    else:
        priority = pd.Series(0.0, index=ranked.index)

    trust_risk = 100 - ranked["_trust_score"]
    lineage_risk = 100 - ranked["_lineage_score"]

    verdict = ranked.get("verdict", pd.Series("", index=ranked.index)).astype(str).str.lower()
    verdict_risk = pd.Series(10.0, index=ranked.index)
    verdict_risk.loc[verdict.str.contains("malicious", na=False)] = 100.0
    verdict_risk.loc[verdict.str.contains("suspicious", na=False)] = 65.0
    verdict_risk.loc[verdict.str.contains("legitimate", na=False)] = 0.0

    composite = (
        ranked["_ai_score"] * 0.30
        + trust_risk * 0.25
        + lineage_risk * 0.15
        + ranked["_combined_score"] * 0.20
        + verdict_risk * 0.10
    )
    if priority.nunique() > 1 and priority.max() > 0:
        composite = composite * 0.70 + priority * 0.30

    ranked["_threat_score"] = composite.clip(0, 100)

    ranked = ranked.sort_values("_threat_score", ascending=False).copy()
    n = len(ranked)
    positions = pd.Series(range(n), index=ranked.index)
    ranked["_rank"] = ((positions * 5) // n + 1).clip(upper=5).astype(int)

    return ranked

# ============================================================
# CUSTOM CSS
# ============================================================

st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Orbitron:wght@500;600;700;800&family=Poppins:wght@300;400;500;600;700;800&display=swap');
html { scroll-behavior:smooth; }
body,.stApp { font-family:'Poppins',sans-serif; }
.stApp { background:radial-gradient(circle at 15% 10%,rgba(0,217,255,.10),transparent 28%),radial-gradient(circle at 85% 45%,rgba(111,92,255,.10),transparent 32%),#020611; color:white; }
#MainMenu,footer { visibility:hidden; } header { background:transparent !important; }
.brand-title { color:#00d9ff; font-size:24px; font-weight:800; padding-top:10px; }

/* general */
.hero-container { min-height:390px; display:flex; align-items:center; justify-content:center; text-align:center; padding:35px 25px; border-radius:28px; background:radial-gradient(circle,rgba(0,217,255,.11),transparent 65%); border:1px solid rgba(0,217,255,.10); }
.hero-title { font-size:clamp(38px,5vw,60px); font-weight:800; line-height:1.1; color:white; text-shadow:0 0 25px rgba(0,217,255,.35); } .hero-highlight { color:#00d9ff; text-shadow:0 0 20px #00d9ff; }
.hero-subtitle { color:#8fe9ff; font-size:20px; margin-top:14px; } .hero-description { max-width:850px; margin:18px auto; color:#d4dde1; line-height:1.8; }
.section-title { text-align:center; font-size:34px; font-weight:800; color:#00d9ff; margin:52px 0 10px; text-shadow:0 0 20px rgba(0,217,255,.35); } .section-description { text-align:center; max-width:900px; margin:0 auto 22px; color:#b8c7cd; line-height:1.8; }

/* selected analysis */
.analysis-panel { padding:22px; border-radius:24px; background:linear-gradient(145deg,rgba(0,217,255,.06),rgba(111,92,255,.05)); border:1px solid rgba(0,217,255,.20); margin-top:16px; } .score-box { padding:17px; border-radius:16px; background:rgba(255,255,255,.04); border:1px solid rgba(255,255,255,.08); text-align:center; } .score-value { font-size:29px; font-weight:800; color:#00d9ff; } .score-label { color:#aabac1; font-size:10px; text-transform:uppercase; letter-spacing:.8px; } .alert-box { padding:15px 18px; border-radius:15px; margin-top:14px; background:rgba(255,107,127,.08); border:1px solid rgba(255,107,127,.25); color:#ffdfe3; }

.features-grid { display:grid; grid-template-columns:repeat(3,1fr); gap:18px; margin-top:6px; }
@media (max-width:1000px) { .features-grid { grid-template-columns:repeat(2,1fr); } }
@media (max-width:640px) { .features-grid { grid-template-columns:1fr; } }
.feature-card { padding:23px; border-radius:20px; background:rgba(255,255,255,.045); border:1px solid rgba(255,255,255,.08); min-height:200px; height:100%; display:flex; flex-direction:column; transition:.25s; box-sizing:border-box; } .feature-card:hover { transform:translateY(-5px); border-color:rgba(0,217,255,.55); box-shadow:0 0 30px rgba(0,217,255,.12); } .feature-tag { display:inline-block; align-self:flex-start; font-size:10px; font-weight:800; letter-spacing:.7px; color:#02111d; background:linear-gradient(90deg,#00d9ff,#00ffb3); padding:4px 10px; border-radius:20px; margin-bottom:9px; } .feature-title { color:#00d9ff; font-size:18px; font-weight:700; margin-bottom:8px; } .feature-text { color:#d1d9dd; line-height:1.65; font-size:13.5px; flex-grow:1; }
.stat-card { text-align:center; padding:22px 12px; border-radius:18px; background:rgba(255,255,255,.04); border:1px solid rgba(255,255,255,.08); } .stat-number { font-size:36px; font-weight:800; color:#00d9ff; } .stat-text { color:#c0cbd0; font-size:13px; } .verdict-legit .stat-number { color:#00ffb3; } .verdict-suspicious .stat-number { color:#ffd166; } .verdict-malicious .stat-number { color:#ff6b7f; }
.metric-pill { display:inline-block; padding:6px 14px; border-radius:30px; font-size:12px; font-weight:800; margin:4px; } .pill-good { background:rgba(0,255,179,.10); color:#00ffb3; border:1px solid rgba(0,255,179,.35); } .pill-warn { background:rgba(255,209,102,.10); color:#ffd166; border:1px solid rgba(255,209,102,.35); } .workflow-step { text-align:center; padding:15px 7px; border-radius:18px; background:rgba(255,255,255,.04); border:1px solid rgba(0,217,255,.16); color:#dce8ec; font-size:13px; }
.footer { text-align:center; padding:35px; margin-top:55px; color:#718087; border-top:1px solid rgba(255,255,255,.08); }

[data-testid='stImage'] { display:flex; justify-content:center; }
[data-testid='stImage'] img { object-fit:contain; }

/* Floating mission imagery */
.float-wrap{ display:inline-block; width:100%; }
.float-wrap [data-testid='stImage'] img{
    filter:drop-shadow(0 18px 26px rgba(0,0,0,.45));
    animation:floatBob var(--float-dur,4.5s) ease-in-out infinite;
    animation-delay:var(--float-delay,0s);
}
.float-wrap.drift [data-testid='stImage'] img{
    animation-name:floatDrift;
}
@keyframes floatBob{
    0%,100%{ transform:translateY(0); }
    50%{ transform:translateY(-14px); }
}
@keyframes floatDrift{
    0%,100%{ transform:translateY(0) rotate(0deg); }
    50%{ transform:translateY(-16px) rotate(2.5deg); }
}
/* Hero image row: satellite / dish / earth are different sizes, so this
   pins them all to one shared horizontal mid-line and centers each one
   inside its column, instead of Streamlit's default top-alignment (that
   mismatch was making the small satellite/earth icons look like they were
   floating up near the header instead of flanking the dish image). */
div[class*="hero_image_row"] [data-testid="stHorizontalBlock"]{
    align-items:center;
}
div[class*="hero_image_row"] [data-testid="column"]{
    display:flex;
    align-items:center;
    justify-content:center;
    min-height:150px;
}
div[class*="hero_image_row"] .float-wrap{
    display:flex;
    align-items:center;
    justify-content:center;
    width:auto;
}

.stButton > button { border-radius:999px; padding:9px 18px; font-weight:800; border:1px solid rgba(0,217,255,.35); background:linear-gradient(90deg,#00d9ff,#00ffb3); color:#02111d; transition:.2s; } .stButton > button:hover { transform:translateY(-2px); box-shadow:0 0 24px rgba(0,217,255,.35); }
.stButton > button:disabled { opacity:.4; box-shadow:none!important; transform:none!important; }

@keyframes starDrift{to{transform:translate3d(5%,3%,0)}}
@keyframes ringSpin{to{transform:rotate(360deg)}}
@keyframes spin{to{transform:rotate(360deg)}}
@keyframes bootIn{to{opacity:1;transform:none}}
@keyframes bootLoad{from{width:0}to{width:100%}}
@keyframes corePulse{50%{transform:scale(1.08);box-shadow:0 0 70px rgba(0,217,255,.9),0 0 140px rgba(0,217,255,.22)}}

/* attack selection + rank selection + data-source cards.
   NOTE: these target real st.container(key=...) wrapper divs (Streamlit
   assigns them a class containing the key), NOT a markdown div-wrap.
   A raw <div> opened via st.markdown never actually nests around a
   sibling widget - Streamlit renders every st.markdown call as its own
   isolated HTML fragment, so the browser auto-closes the tag before the
   next widget even exists. That's why these buttons were falling back to
   the default pill-shaped .stButton style instead of the card look. */
div[class*="attack_card_"] .stButton button { min-height:150px!important; border-radius:20px!important; background:rgba(255,255,255,.035)!important; color:#eafcff!important; border:1px solid rgba(0,217,255,.16)!important; white-space:pre-line!important; font-size:13px!important; box-shadow:none!important; }
div[class*="attack_card_"] .stButton button:hover { transform:translateY(-5px)!important; border-color:#00d9ff!important; box-shadow:0 0 30px rgba(0,217,255,.16)!important; }
div[class*="attack_card_"][class*="_selected"] .stButton button { background:linear-gradient(145deg,rgba(0,217,255,.18),rgba(111,92,255,.12))!important; border-color:#00d9ff!important; box-shadow:0 0 32px rgba(0,217,255,.20)!important; }

div[class*="source_card_"] .stButton button { min-height:52px!important; border-radius:20px!important; background:rgba(255,255,255,.035)!important; color:#eafcff!important; border:1px solid rgba(124,108,255,.20)!important; font-size:14px!important; box-shadow:none!important; }
div[class*="source_card_"] .stButton button:hover { transform:translateY(-5px)!important; border-color:#7c6cff!important; box-shadow:0 0 26px rgba(124,108,255,.20)!important; }
div[class*="source_card_"][class*="_selected"] .stButton button { background:linear-gradient(145deg,rgba(124,108,255,.20),rgba(0,217,255,.10))!important; border-color:#7c6cff!important; box-shadow:0 0 30px rgba(124,108,255,.22)!important; }

.analysis-console { max-width:900px; margin:30px auto; padding:30px; border-radius:24px; background:linear-gradient(145deg,rgba(0,217,255,.07),rgba(111,92,255,.06)); border:1px solid rgba(0,217,255,.22); text-align:center; box-shadow:0 0 60px rgba(0,217,255,.10); }
.analysis-console h2 { color:#00d9ff; font-family:'Orbitron',sans-serif; }
.analysis-status { color:#b9d7df; letter-spacing:1px; font-size:12px; margin:14px 0; }
.solution-box { padding:16px 18px; border-radius:16px; background:rgba(0,255,179,.06); border:1px solid rgba(0,255,179,.22); margin-top:16px; color:#dfffea; }
.analysis-ready { text-align:center; padding:32px 20px; border:1px dashed rgba(0,217,255,.25); border-radius:24px; background:rgba(255,255,255,.02); }
.stage-kicker { text-align:center; color:#7c94a0; font-family:'Orbitron',sans-serif; font-size:11px; letter-spacing:3px; margin-bottom:6px; }

.rank-selector-title { text-align:center; color:#8fa3ad; margin:0 0 18px; }
div[class*="rank_card_"] .stButton button { width:100%; min-height:102px; white-space:pre-line!important; border-radius:18px!important; background:rgba(255,255,255,.035)!important; color:#eafcff!important; border:1px solid rgba(255,255,255,.10)!important; box-shadow:none!important; }
div[class*="rank_card_"] .stButton button:hover { transform:translateY(-5px)!important; border-color:#00d9ff!important; box-shadow:0 0 28px rgba(0,217,255,.14)!important; }
div[class*="rank_card_"][class*="_selected"] .stButton button { border-color:#00d9ff!important; box-shadow:0 0 30px rgba(0,217,255,.24)!important; background:linear-gradient(145deg,rgba(0,217,255,.16),rgba(111,92,255,.12))!important; }
.threat-card { padding:24px; margin:14px 0; border-radius:22px; background:linear-gradient(145deg,rgba(255,255,255,.055),rgba(0,217,255,.025)); border:1px solid rgba(0,217,255,.16); box-shadow:0 0 26px rgba(0,0,0,.18); transition:.25s; }
.threat-card:hover { transform:translateY(-3px); border-color:rgba(0,217,255,.55); box-shadow:0 0 32px rgba(0,217,255,.12); }
.threat-head { display:flex; justify-content:space-between; gap:12px; align-items:center; border-bottom:1px solid rgba(255,255,255,.08); padding-bottom:13px; margin-bottom:16px; }
.threat-rank { font-family:'Orbitron',sans-serif; color:#eafcff; font-size:18px; font-weight:800; }.threat-level { font-size:11px; color:#8fa3ad; }
.threat-score { color:#00d9ff; font-family:'Orbitron',sans-serif; font-size:24px; font-weight:800; }
.threat-grid { display:grid; grid-template-columns:repeat(4,1fr); gap:10px; }.threat-mini { padding:12px; border-radius:13px; background:rgba(255,255,255,.035); border:1px solid rgba(255,255,255,.06); }.threat-mini small{display:block;color:#8fa3ad;font-size:9px;letter-spacing:.8px}.threat-mini b{font-size:17px;color:#eaffff}
.threat-grid.single-score{grid-template-columns:1fr;max-width:100%}
.threat-grid.single-score .threat-mini{padding:18px 20px;background:linear-gradient(90deg,rgba(0,217,255,.11),rgba(0,255,179,.05))}
.threat-grid.single-score .threat-mini b{font-size:34px;color:#00e5ff}
@media(max-width:850px){.threat-grid{grid-template-columns:repeat(2,1fr)}}
.score-row{margin:15px 0}.score-row-head{display:flex;justify-content:space-between;color:#dff8ff;font-size:13px;margin-bottom:7px}.score-row-head strong{color:#00d9ff}.score-track{height:10px;border-radius:99px;background:rgba(255,255,255,.08);overflow:hidden}.score-fill{height:100%;border-radius:99px;background:linear-gradient(90deg,#00d9ff,#00ffb3);box-shadow:0 0 12px rgba(0,217,255,.5)}
.pipeline-flow{display:flex;align-items:stretch;justify-content:center;gap:8px;flex-wrap:wrap;margin:22px 0}.pipeline-node{min-width:145px;padding:14px;border:1px solid rgba(0,217,255,.16);border-radius:14px;background:rgba(255,255,255,.035);text-align:center;color:#dff8ff;font-size:12px}.pipeline-arrow{align-self:center;color:#00d9ff;font-size:22px}

/* one-threat-at-a-time navigator */
.threat-nav-bar{ display:flex; align-items:center; justify-content:center; gap:14px; margin:10px 0 4px; }
.threat-nav-pos{ font-family:'Orbitron',sans-serif; color:#b9d7df; font-size:12px; letter-spacing:1.5px; padding:8px 16px; border:1px solid rgba(0,217,255,.20); border-radius:999px; background:rgba(255,255,255,.03); }

/* ===== TRUE SPLASH INTRO: quick reveal, brief glow, then CTA ===== */
.splash-intro{
    position:relative; width:100%; min-height:560px;
    display:flex; align-items:center; justify-content:center; overflow:hidden;
    border-radius:34px; border:1px solid rgba(0,217,255,.22);
    box-shadow:0 0 75px rgba(0,217,255,.13),inset 0 0 90px rgba(0,217,255,.05);
    background:
        radial-gradient(circle at 50% 45%, rgba(0,217,255,.20), transparent 24%),
        radial-gradient(circle at 18% 18%, rgba(111,92,255,.14), transparent 30%),
        %%SPLASH_BG%%
        #020611;
}
.splash-intro::before{
    content:""; position:absolute; inset:-15%;
    background-image:
        radial-gradient(circle, rgba(255,255,255,.9) 0 1px, transparent 1.6px),
        radial-gradient(circle, rgba(0,217,255,.7) 0 1px, transparent 1.8px);
    background-size:105px 105px, 175px 175px;
    opacity:.40; animation:starDrift 16s linear infinite;
}
.splash-grid{
    position:absolute; left:-25%; right:-25%; bottom:-48%; height:92%;
    background-image:
        linear-gradient(rgba(0,217,255,.12) 1px, transparent 1px),
        linear-gradient(90deg, rgba(0,217,255,.12) 1px, transparent 1px);
    background-size:58px 58px; transform:perspective(600px) rotateX(62deg); opacity:.28;
}
.splash-ring{ position:absolute; width:250px; height:250px; border:1px solid rgba(0,217,255,.28); border-radius:50%; animation:ringSpin 8s linear infinite; }
.splash-ring::before,.splash-ring::after{ content:""; position:absolute; border-radius:50%; border:1px solid rgba(0,217,255,.24); }
.splash-ring::before{ inset:-34px; border-right-color:#00ffb3; border-left-color:transparent; }
.splash-ring::after{ inset:34px; border-color:rgba(111,92,255,.48); border-top-color:transparent; }
.splash-content{ position:relative; z-index:5; text-align:center; padding:24px; }
.splash-core{
    width:86px; height:86px; margin:0 auto 24px; display:grid; place-items:center; border-radius:50%; color:#fff; font-size:34px;
    background:radial-gradient(circle,#fff 0 5%,#00d9ff 12%,rgba(0,217,255,.12) 42%,transparent 68%);
    box-shadow:0 0 50px rgba(0,217,255,.72),0 0 120px rgba(0,217,255,.18);
    opacity:0; animation:corePulse 1.5s ease-in-out infinite, introRise .3s ease .02s forwards;
}
.splash-kicker{ color:#78e9ff; font-family:'Orbitron',sans-serif; font-size:11px; letter-spacing:5px; margin-bottom:16px; opacity:0; transform:translateY(12px); animation:introRise .3s ease .15s forwards; }

/* Brand name: rises + glows briefly, then fades so the CTA can take over
   fast - the whole reveal now finishes in ~2.3s instead of ~5s. */
.splash-title{
    margin:0; color:#f7fbff; font-family:'Orbitron',sans-serif; font-size:clamp(40px,7vw,88px); line-height:1.05; letter-spacing:-2px;
    opacity:0; transform:translateY(18px) scale(.96); text-shadow:0 0 0 rgba(0,217,255,0);
    animation:
        titleRise .5s cubic-bezier(.2,.8,.2,1) .25s forwards,
        titleGlow 1s ease-in-out .75s 1,
        titleFade .6s ease 1.5s forwards;
}
.splash-title span{color:#00d9ff;}
.splash-subtitle{
    margin-top:18px; color:#a4c5ce; font-size:12px; letter-spacing:3px;
    opacity:0; animation:introRise .3s ease .45s forwards, titleFade .6s ease 1.5s forwards;
}
.splash-line{
    width:min(420px,70vw); height:2px; margin:26px auto 0;
    background:linear-gradient(90deg,transparent,#00d9ff,#00ffb3,transparent); box-shadow:0 0 18px rgba(0,217,255,.6);
    transform:scaleX(0); animation:lineGrow .4s ease .55s forwards, titleFade .6s ease 1.5s forwards;
}

/* CTA block: hidden while the brand is glowing, fades in right after */
.splash-cta{
    margin-top:8px; opacity:0; transform:translateY(14px);
    animation:ctaIn .5s ease 1.75s forwards;
}
.splash-cta .splash-status{
    color:#00ffb3; font-family:'Orbitron',sans-serif; font-size:11px; letter-spacing:4px; margin-bottom:18px;
}
.splash-cta-wrap{ opacity:0; transform:translateY(14px); animation:ctaIn .5s ease 1.85s forwards; }

@keyframes introRise{to{opacity:1;transform:translateY(0)}}
@keyframes titleRise{to{opacity:1;transform:translateY(0) scale(1)}}
@keyframes titleGlow{
    0%{text-shadow:0 0 10px rgba(0,217,255,.25)}
    50%{text-shadow:0 0 55px rgba(0,217,255,.85),0 0 110px rgba(0,217,255,.35)}
    100%{text-shadow:0 0 22px rgba(0,217,255,.4)}
}
@keyframes titleFade{to{opacity:0;transform:translateY(-14px) scale(.97);filter:blur(6px)}}
@keyframes lineGrow{to{transform:scaleX(1)}}
@keyframes ctaIn{to{opacity:1;transform:translateY(0)}}

@media(max-width:700px){ .splash-title{font-size:44px;} .splash-kicker{letter-spacing:2px;} .splash-subtitle{letter-spacing:1.5px;} }

/* ===== "Scientist researching" analysis loader ===== */
.lab-loader{
    position:relative; max-width:820px; margin:22px auto 6px; padding:26px 24px;
    border-radius:22px; border:1px solid rgba(0,217,255,.20);
    background:radial-gradient(circle at 30% 20%,rgba(0,217,255,.10),transparent 55%),rgba(4,10,24,.55);
    overflow:hidden;
}
.lab-loader::before{
    content:""; position:absolute; inset:-30%;
    background-image:radial-gradient(circle, rgba(255,255,255,.5) 0 1px, transparent 1.4px);
    background-size:70px 70px; opacity:.25; animation:starDrift 12s linear infinite;
}
.lab-scope{ position:relative; width:120px; height:120px; margin:0 auto 18px; }
.lab-scope-grid{
    position:absolute; inset:0; border-radius:50%; border:1px solid rgba(0,217,255,.35);
    background-image:linear-gradient(rgba(0,217,255,.18) 1px,transparent 1px),linear-gradient(90deg,rgba(0,217,255,.18) 1px,transparent 1px);
    background-size:15px 15px; overflow:hidden;
}
.lab-scope-sweep{
    position:absolute; inset:0; border-radius:50%;
    background:conic-gradient(from 0deg, rgba(0,217,255,.55), transparent 34%);
    animation:spin 1.6s linear infinite;
}
.lab-scope-dot{ position:absolute; width:6px; height:6px; border-radius:50%; background:#ff6b7f; box-shadow:0 0 10px #ff6b7f; animation:blipPulse 1.6s ease-in-out infinite; }
.lab-scope-dot.d1{ top:28%; left:62%; } .lab-scope-dot.d2{ top:60%; left:32%; animation-delay:.4s; } .lab-scope-dot.d3{ top:45%; left:48%; animation-delay:.9s; }
@keyframes blipPulse{0%,100%{opacity:.2;transform:scale(.7)}50%{opacity:1;transform:scale(1.3)}}
.lab-glass{
    position:absolute; left:50%; top:50%; width:46px; height:46px; margin:-23px 0 0 -23px;
    border:3px solid #00d9ff; border-radius:50%; box-shadow:0 0 18px rgba(0,217,255,.7);
    animation:glassOrbit 2.6s linear infinite;
}
.lab-glass::after{ content:""; position:absolute; width:16px; height:3px; background:#00d9ff; border-radius:3px; right:-13px; bottom:2px; transform:rotate(45deg); box-shadow:0 0 10px rgba(0,217,255,.7); }
@keyframes glassOrbit{
    0%{ transform:rotate(0deg) translateX(38px) rotate(0deg); }
    100%{ transform:rotate(360deg) translateX(38px) rotate(-360deg); }
}
.lab-log{ max-width:560px; margin:6px auto 0; text-align:left; font-family:'Poppins',monospace; font-size:12px; color:#9fe9ff; display:grid; gap:6px; }
.lab-log div{ opacity:0; transform:translateX(-6px); animation:bootIn .4s ease forwards; white-space:nowrap; overflow:hidden; }
.lab-log div:nth-child(1){animation-delay:.05s}
.lab-log div:nth-child(2){animation-delay:.35s}
.lab-log div:nth-child(3){animation-delay:.65s}
.lab-log div:nth-child(4){animation-delay:.95s}
.lab-log div:nth-child(5){animation-delay:1.25s}
.lab-log div:nth-child(6){animation-delay:1.55s}
.lab-log .ok{ color:#00ffb3; }

/* ===== Data-source panel (default file vs upload) ===== */
.upload-panel{
    max-width:1000px; margin:18px auto; padding:26px 28px; border-radius:26px;
    border:1px solid rgba(124,108,255,.28);
    background:linear-gradient(145deg,rgba(124,108,255,.08),rgba(0,217,255,.04));
}
.upload-badge{ display:inline-block; font-size:11px; font-weight:800; letter-spacing:.6px; color:#0b0620; background:linear-gradient(90deg,#7c6cff,#00d9ff); padding:5px 12px; border-radius:20px; margin-bottom:10px; }
</style>
""".replace(
    "%%SPLASH_BG%%",
    (f"linear-gradient(rgba(2,6,17,.80),rgba(2,6,17,.92)), url(data:image/jpeg;base64,{_splash_bg_b64})," if _splash_bg_b64 else "")
), unsafe_allow_html=True)


def render_html(raw_html, **kwargs):
    """Fix for multiline HTML rendering: a blank line inside the string
    ends the CommonMark HTML block early, so indented Python-template
    content after it gets treated as a code block instead of HTML.
    Dropping blank lines is always safe since HTML is whitespace-insensitive
    between tags."""
    cleaned = textwrap.dedent('\n' + raw_html).strip()
    cleaned = "\n".join(line for line in cleaned.split("\n") if line.strip() != "")
    st.markdown(cleaned, unsafe_allow_html=True)


# ============================================================
# NAVBAR (shown on every screen)
# ============================================================

col1, col2 = st.columns([1, 6])
with col1:
    if os.path.exists(LOGO_PATH):
        st.image(LOGO_PATH, width=65)
with col2:
    st.markdown(
        '<div class="brand-title" style="padding-top:12px;">DeepSpace CyberShield AI</div>',
        unsafe_allow_html=True,
    )

st.divider()


# ============================================================
# SCREEN 1 — SPLASH INTRO
# All timed in pure CSS (now compressed to ~2.3s total instead of ~5s):
#   core + kicker rise in -> brand title rises & glows briefly -> title/
#   kicker/subtitle/line fade out together -> CTA fades in in their place.
# Stays in normal document flow (no position:fixed / no JS redirect) since
# Streamlit's app container applies a CSS transform that silently breaks
# position:fixed on descendants, and a JS redirect would have to cross an
# iframe boundary some browsers block.
# ============================================================

if st.session_state.app_stage == "intro":
    render_html("""
    <div class="splash-intro">
        <div class="splash-grid"></div>
        <div class="splash-ring"></div>

        <div class="splash-content">
            <div class="splash-core">✦</div>
            <div class="splash-kicker">AUTONOMOUS DEEP-SPACE DEFENSE SYSTEM</div>
            <h1 class="splash-title">DEEPSPACE <span>CYBERSHIELD AI</span></h1>
            <div class="splash-subtitle">AI-POWERED • AUTONOMOUS • DEEP-SPACE SECURITY</div>
            <div class="splash-line"></div>
            <div class="splash-cta">
                <div class="splash-status">SYSTEM ONLINE — MISSION CONTROL READY</div>
            </div>
        </div>
    </div>
    """)

    st.write("")
    st.markdown('<div class="splash-cta-wrap">', unsafe_allow_html=True)
    b1, b2, b3 = st.columns([3, 2, 3])
    with b2:
        if st.button("🚀 ENTER MISSION CONTROL", use_container_width=True):
            goto("home")
    st.markdown("</div>", unsafe_allow_html=True)

    st.stop()


# ============================================================
# SCREEN 2 — HOME
# Hero + aligned mission imagery + feature grid + AI workflow, all shown
# BEFORE the user ever picks an attack type or a data source, followed by
# Mission Control (attack type -> data source -> Start Analysis) at the
# bottom of this same screen. Nothing from the results/analytics screens
# renders here.
# ============================================================

def render_home():
    hero_style = ""
    if _hero_bg_b64:
        hero_style = (
            f'style="background-image:linear-gradient(180deg, rgba(2,6,17,.72), rgba(2,6,17,.90)), '
            f'url(data:image/jpeg;base64,{_hero_bg_b64}); background-size:cover; background-position:center;"'
        )

    render_html(f"""
    <div class="hero-container" {hero_style}>
        <div>
            <div class="hero-title">Protecting Humanity's<br>
                <span class="hero-highlight">Deep-Space Future</span>
            </div>
            <div class="hero-subtitle">Autonomous Cyber Defense Beyond Earth</div>
            <div class="hero-description">
                DeepSpace CyberShield AI continuously analyzes interplanetary communication
                networks to identify anomalies, evaluate trust, and protect critical deep-space
                transmissions from emerging cyber threats.
            </div>
        </div>
    </div>
    """)

    # Mission imagery row - wrapped in a keyed container so the CSS rule
    # above can vertically center the satellite / dish / earth on one
    # visual mid-line instead of Streamlit's default top-alignment.
    with st.container(key="hero_image_row"):
        image_col1, image_col2, image_col3 = st.columns([1, 2, 1])
        with image_col1:
            if os.path.exists(SATELLITE_PATH):
                st.markdown('<div class="float-wrap drift" style="--float-dur:5.5s;--float-delay:0s;">', unsafe_allow_html=True)
                st.image(SATELLITE_PATH, width=64)
                st.markdown('</div>', unsafe_allow_html=True)
        with image_col2:
            if os.path.exists(DEFENSE_PATH):
                st.markdown('<div class="float-wrap" style="--float-dur:6.5s;--float-delay:.3s;">', unsafe_allow_html=True)
                st.image(DEFENSE_PATH, width=220)
                st.markdown('</div>', unsafe_allow_html=True)
        with image_col3:
            if os.path.exists(EARTH_PATH):
                st.markdown('<div class="float-wrap drift" style="--float-dur:5s;--float-delay:.6s;">', unsafe_allow_html=True)
                st.image(EARTH_PATH, width=64)
                st.markdown('</div>', unsafe_allow_html=True)

    # ---- Features, shown on the home page before any analysis starts ----
    render_html("""
    <div class="section-title">Core Cyber Defense Features</div>
    <div class="section-description">
        Every module below is a live pipeline stage - not a static description - and
        corresponds to a contribution from our research paper, <i>"AI-Driven Detection of
        Cyber Anomalies in Deep-Space Communication Networks Using Temporal Trust Leakage
        Evidence and Dynamic TTL Decay."</i>
    </div>
    """)

    FEATURES = [
        ("AI Behavioral Engine", "🤖 Autoencoder &amp; Isolation Forest Anomaly Scoring",
         "Lightweight models profile normal communication behaviour from telemetry, timing, "
         "propagation delay, RSS, packet size and relay sequence data - producing an initial "
         "anomaly confidence score for every incoming bundle, without needing labelled attack data."),
        ("Core Contribution", "⏳ Temporal Trust Leakage Evidence (TTL-Evidence)",
         "Instead of judging packets in isolation, TTL-Evidence tracks transmission timing "
         "consistency, latency, communication rhythm and historical similarity over time. Even "
         "a near-perfect spoof accumulates small behavioural discrepancies that erode its trust "
         "score - exposing advanced spoofing and replay attacks that packet-level inspection misses."),
        ("Core Contribution", "🛰️ Deep-Space Signal Lineage Verification (DSSLV)",
         "Verifies the entire route a bundle took - ground station, orbiter, relay satellite, "
         "receiver - against its expected path. An improbable route or impossible relay "
         "transition is flagged as suspicious, catching forged routing and injected relay nodes "
         "even when the signal signature looks legitimate."),
        ("Core Contribution", "🛡️ Passive Autonomous Eviction — Dynamic TTL Decay",
         "Rather than actively deleting malicious packets, suspicious bundles simply have their "
         "Bundle Protocol TTL decayed toward zero - letting the native DTN garbage collector "
         "expire them automatically, with near-zero extra CPU or memory overhead."),
        ("Threat Intelligence", "🎯 Priority-Ranked Threat Command Center",
         "Every bundle is scored end-to-end and ranked by combined risk, surfacing the highest-"
         "priority signals first instead of leaving an operator to scroll through a flat log "
         "during a live incident."),
        ("Explainability", "🧾 Human-Readable Evidence Trail",
         "Each verdict ships with the specific behavioural, timing and routing reasons that "
         "produced it, so an operator can audit a decision instead of trusting an opaque score."),
        ("Fleet-Wide Visibility", "🌐 Mission Communication Dashboard",
         "Search, filter and export every monitored bundle - ground stations, orbiters and relay "
         "satellites - in one live table with anomaly, trust and lineage scores side by side."),
        ("Reporting", "📄 One-Click Mission Security Reports",
         "Generate and download CSV evidence exports and Markdown detection reports on demand, "
         "ready to hand to a mission review board."),
    ]

    cards_html = "".join(
        f"""<div class="feature-card">
            <div class="feature-tag">{safe_text(tag)}</div>
            <div class="feature-title">{title}</div>
            <div class="feature-text">{safe_text(text)}</div>
        </div>"""
        for tag, title, text in FEATURES
    )
    render_html(f'<div class="features-grid">{cards_html}</div>')

    if os.path.exists(ANOMALY_PATH):
        an_col1, an_col2, an_col3 = st.columns([1, 2, 1])
        with an_col2:
            st.markdown('<div class="float-wrap" style="--float-dur:6s;--float-delay:.2s;">', unsafe_allow_html=True)
            st.image(ANOMALY_PATH, caption="AI Anomaly Detection System", width=300)
            st.markdown('</div>', unsafe_allow_html=True)

    render_html("""
    <div class="section-title">Defending Communication Across the Void</div>
    <div class="section-description">
        DeepSpace CyberShield AI is designed to protect communication infrastructure
        operating across extreme distances where traditional cybersecurity approaches
        may not be sufficient. Our AI-driven system analyzes mission communication
        patterns and identifies suspicious anomalies before they become critical threats.
    </div>
    """)

    if os.path.exists(AI_NETWORK_PATH):
        ai_col1, ai_col2, ai_col3 = st.columns([1, 2, 1])
        with ai_col2:
            st.markdown('<div class="float-wrap" style="--float-dur:7s;--float-delay:.4s;">', unsafe_allow_html=True)
            st.image(AI_NETWORK_PATH, caption="AI-Powered Deep Space Communication Monitoring", width=300)
            st.markdown('</div>', unsafe_allow_html=True)

    st.markdown('<div class="section-title">AI Security Workflow</div>', unsafe_allow_html=True)
    w1, w2, w3, w4, w5 = st.columns(5)
    steps = [
        ("📡", "Telemetry Input"),
        ("🧠", "AI Confidence Score"),
        ("⏳", "TTL-Evidence Trust"),
        ("🛰️", "DSSLV Lineage Check"),
        ("🛡️", "Dynamic TTL Decay"),
    ]
    for col, (icon, label) in zip([w1, w2, w3, w4, w5], steps):
        with col:
            st.markdown(f'<div class="workflow-step">{icon}<br>{label}</div>', unsafe_allow_html=True)

    # ---- Mission Control now lives on its own dedicated pages ----
    st.write("")
    render_html("""
    <div class="section-title">🎛️ Begin Mission Threat Investigation</div>
    <div class="section-description">Ready to investigate? You'll pick an attack category, then choose
    your data source - default fleet data or your own upload - on the next screens.</div>
    """)
    go_col1, go_col2, go_col3 = st.columns([2, 2, 2])
    with go_col2:
        if st.button("🎯 BEGIN MISSION SETUP", key="begin_mission_setup", use_container_width=True):
            goto("attack_select")


# ============================================================
# SCREEN 2b — ATTACK SELECTION (its own page)
# ============================================================

ATTACK_OPTIONS = [
    ("🟥", "Spoofing Attack", "Fake or manipulated communication identity and signal evidence."),
    ("🟧", "Replay Attack", "Repeated or replayed transmissions requiring temporal trust investigation."),
    ("🟪", "Relay Path Attack", "Unexpected routing, lineage, relay or path anomalies."),
    ("🟡", "Behavioral Anomaly", "Unusual telemetry, timing or communication behaviour."),
    ("🌐", "All Detected Threats", "Run the complete mission threat investigation."),
]


def render_attack_select():
    ss = st.session_state

    st.markdown('<div class="stage-kicker">STEP 1 OF 3</div>', unsafe_allow_html=True)
    st.markdown('<div class="section-title">🎯 Select Attack Category</div>', unsafe_allow_html=True)
    st.markdown(
        '<div class="section-description">Choose the type of deep-space cyber threat you want to '
        'investigate. The next screen lets you pick which data to run it against.</div>',
        unsafe_allow_html=True,
    )

    attack_cols = st.columns(5)
    for (icon, name, desc), col in zip(ATTACK_OPTIONS, attack_cols):
        selected = ss.mission_selected_attack == name
        safe_name = name.replace(" ", "_")
        wrap_key = f"attack_card_{safe_name}" + ("_selected" if selected else "")
        with col:
            with st.container(key=wrap_key):
                if st.button(f"{icon}\n{name}\n\n{desc}", key=f"attack_{name}", use_container_width=True):
                    ss.mission_selected_attack = name
                    st.rerun()

    st.write("")
    st.markdown(
        f'<div class="analysis-ready"><p>Selected: <b>{safe_text(ss.mission_selected_attack)}</b></p></div>',
        unsafe_allow_html=True,
    )

    st.write("")
    nav1, nav2 = st.columns(2)
    with nav1:
        if st.button("← Back to Home", key="attack_back_home", use_container_width=True):
            goto("home")
    with nav2:
        if st.button("Choose Data Source →", key="attack_next", use_container_width=True):
            goto("source_select")


# ============================================================
# SCREEN 2c — DATA SOURCE SELECTION (its own page)
# From here the user branches to one of two dedicated pages: uploading
# their own CSV, or running the analysis against the existing/default
# communication_logs.csv already sitting in the project.
# ============================================================

def render_source_select():
    ss = st.session_state

    st.markdown('<div class="stage-kicker">STEP 2 OF 3</div>', unsafe_allow_html=True)
    st.markdown('<div class="section-title">📂 Choose Data Source</div>', unsafe_allow_html=True)
    st.markdown(
        f'<div class="section-description">Investigating: <b>{safe_text(ss.mission_selected_attack)}</b>. '
        'Pick where the communication log data should come from.</div>',
        unsafe_allow_html=True,
    )

    src_col1, src_col2 = st.columns(2)
    with src_col1:
        with st.container(key="source_card_default"):
            st.markdown(
                '<div class="analysis-ready" style="min-height:170px;">'
                '<h3 style="color:#00d9ff">🛰️ Use Existing Dataset</h3>'
                '<p style="color:#b8c7cd">Run the analysis on the default communication_logs.csv '
                'that already ships with this project - no upload needed.</p></div>',
                unsafe_allow_html=True,
            )
            if st.button("Analyze Existing Data →", key="go_default_page", use_container_width=True):
                goto("default_page")
    with src_col2:
        with st.container(key="source_card_upload"):
            st.markdown(
                '<div class="analysis-ready" style="min-height:170px;">'
                '<h3 style="color:#7c6cff">📡 Upload My Own CSV</h3>'
                '<p style="color:#b8c7cd">Bring a communication log from another organisation or '
                'satellite operator and run it through the same pipeline.</p></div>',
                unsafe_allow_html=True,
            )
            if st.button("Upload a CSV →", key="go_upload_page", use_container_width=True):
                goto("upload_page")

    st.write("")
    if st.button("← Back to Attack Selection", key="source_back_attack"):
        goto("attack_select")


# ============================================================
# SCREEN 2d — UPLOAD-YOUR-OWN-CSV (its own dedicated page)
# ============================================================

def render_upload_page():
    ss = st.session_state

    st.markdown('<div class="stage-kicker">STEP 3 OF 3 · EXTERNAL UPLOAD</div>', unsafe_allow_html=True)
    st.markdown('<div class="section-title">📡 Upload Your Communication Log</div>', unsafe_allow_html=True)

    render_html("""
    <div class="upload-panel">
        <span class="upload-badge">EXTERNAL MISSION UPLOAD</span>
        <div class="section-description" style="margin:6px 0 0;">
            Upload a communication log CSV using the same column layout as
            communication_logs.csv. It will run through the exact same AI Behavioral Engine
            → TTL-Evidence → DSSLV → Dynamic TTL Decay pipeline as the default fleet data.
        </div>
    </div>
    """)

    uploaded_file = st.file_uploader(
        "Upload a communication log CSV",
        type=["csv"],
        key="external_upload",
    )
    if uploaded_file is not None:
        try:
            uploaded_df = pd.read_csv(uploaded_file)
            ss.uploaded_raw_df = uploaded_df
            ss.uploaded_file_name = uploaded_file.name
            st.success(f"Loaded {len(uploaded_df)} rows from **{uploaded_file.name}**. Ready to start.")
        except Exception as e:
            st.error(f"Couldn't read that file as a CSV: {e}")
    elif ss.uploaded_raw_df is not None:
        st.caption(f"Using previously uploaded file: **{ss.uploaded_file_name}** ({len(ss.uploaded_raw_df)} rows). "
                   "Upload a new file above to replace it.")

    source_ready = ss.uploaded_raw_df is not None

    st.write("")
    if source_ready:
        st.markdown(
            f'<div class="analysis-ready"><h3 style="color:#00d9ff">READY FOR INVESTIGATION</h3>'
            f'<p>Selected intelligence: <b>{safe_text(ss.mission_selected_attack)}</b></p>'
            f'<p>Data source: <b>Uploaded file — {safe_text(ss.uploaded_file_name)}</b></p></div>',
            unsafe_allow_html=True,
        )
    else:
        st.markdown(
            '<div class="analysis-ready"><p style="color:#8fa3ad">Upload a CSV above to enable Start Analysis.</p></div>',
            unsafe_allow_html=True,
        )

    st.write("")
    nav1, nav2 = st.columns(2)
    with nav1:
        if st.button("← Back to Data Source", key="upload_back_source", use_container_width=True):
            goto("source_select")
    with nav2:
        if st.button(
            f"🚀 START ANALYSIS — {ss.mission_selected_attack.upper()}",
            key="start_analysis_upload",
            use_container_width=True,
            disabled=not source_ready,
        ):
            ss.mission_data_source = "upload"
            goto("loading")


# ============================================================
# SCREEN 2e — ANALYZE EXISTING DATASET (its own dedicated page)
# ============================================================

def render_default_page():
    ss = st.session_state

    st.markdown('<div class="stage-kicker">STEP 3 OF 3 · EXISTING DATASET</div>', unsafe_allow_html=True)
    st.markdown('<div class="section-title">🛰️ Analyze Existing Fleet Data</div>', unsafe_allow_html=True)

    file_exists = os.path.exists(DATASET_PATH)
    row_count = None
    if file_exists:
        try:
            row_count = sum(1 for _ in open(DATASET_PATH, "r", encoding="utf-8")) - 1
        except Exception:
            row_count = None

    detail = f"{row_count} communication records" if row_count is not None else "the built-in communication log"
    render_html(f"""
    <div class="upload-panel">
        <span class="upload-badge">BUILT-IN FLEET DATA</span>
        <div class="section-description" style="margin:6px 0 0;">
            This runs the pipeline against <b>communication_logs.csv</b>, already present in this
            project's <code>dataset/</code> folder ({safe_text(detail)}). Nothing to upload - just start
            the analysis.
        </div>
    </div>
    """)

    if not file_exists:
        st.warning("communication_logs.csv wasn't found on disk - a fresh synthetic dataset will be generated automatically.")

    st.write("")
    st.markdown(
        f'<div class="analysis-ready"><h3 style="color:#00d9ff">READY FOR INVESTIGATION</h3>'
        f'<p>Selected intelligence: <b>{safe_text(ss.mission_selected_attack)}</b></p>'
        f'<p>Data source: <b>Default Fleet Dataset</b></p></div>',
        unsafe_allow_html=True,
    )

    st.write("")
    nav1, nav2 = st.columns(2)
    with nav1:
        if st.button("← Back to Data Source", key="default_back_source", use_container_width=True):
            goto("source_select")
    with nav2:
        if st.button(
            f"🚀 START ANALYSIS — {ss.mission_selected_attack.upper()}",
            key="start_analysis_default",
            use_container_width=True,
        ):
            ss.mission_data_source = "default"
            goto("loading")


# ============================================================
# SCREEN 3 — LOADING (nothing else on screen while this runs)
# ============================================================

LAB_LOG_LINES = [
    "📡 Ingesting telemetry stream...",
    "🤖 AI Behavioral Engine profiling communication patterns...",
    "⏳ TTL-Evidence cross-referencing transmission history...",
    "🛰️ DSSLV tracing relay lineage hop by hop...",
    "🛡️ Dynamic TTL Decay weighing containment response...",
    "🚨 Compiling autonomous threat ranking...",
]


def render_loading():
    ss = st.session_state

    render_html(f"""
    <div class="analysis-console"><h2>🤖 DEEPSPACE THREAT ANALYSIS</h2>
    <div class="analysis-status">TARGET: {safe_text(ss.mission_selected_attack).upper()}</div>
    <div class="analysis-status">INITIALIZING AI BEHAVIORAL ENGINE → TTL-EVIDENCE → DSSLV → DYNAMIC TTL DECAY</div></div>
    """)

    log_html = "".join(f"<div>{line}</div>" for line in LAB_LOG_LINES)
    render_html(f"""
    <div class="lab-loader">
        <div class="lab-scope">
            <div class="lab-scope-grid"></div>
            <div class="lab-scope-sweep"></div>
            <div class="lab-scope-dot d1"></div>
            <div class="lab-scope-dot d2"></div>
            <div class="lab-scope-dot d3"></div>
            <div class="lab-glass"></div>
        </div>
        <div class="lab-log">{log_html}</div>
    </div>
    """)

    progress = st.progress(0)
    status = st.empty()
    stages = list(zip([8, 24, 45, 68, 86, 100], LAB_LOG_LINES))
    for target, message in stages:
        status.markdown(f"### {message}")
        current = 0 if target == 8 else target - 15
        for value in range(max(0, current), target + 1):
            progress.progress(value)
            time.sleep(0.018)
    status.success("ANALYSIS COMPLETE — THREATS PRIORITIZED BY AUTONOMOUS DEFENSE AI")

    # Actually run the pipeline now that the console has finished (this is
    # cached, so re-entering "results" later doesn't recompute anything).
    get_active_result()

    time.sleep(0.4)
    goto("results")


# ============================================================
# SCREEN 4 — RESULTS (ranked threats, one at a time)
# ============================================================

def render_ranked_results():
    ss = st.session_state
    data, metrics = get_active_result()

    investigation_data = filter_attack(data, ss.mission_selected_attack)
    ranked = build_threat_ranking(investigation_data)

    st.markdown('<div class="section-title">🏆 Autonomous Threat Ranking</div>', unsafe_allow_html=True)
    st.markdown(
        f'<div class="section-description">Analysis complete for <b>{safe_text(ss.mission_selected_attack)}</b>. '
        'Results are ordered from highest risk to lowest risk using the pipeline outputs. Rank 1 always contains '
        'the highest-risk real bundle in this investigation.</div>',
        unsafe_allow_html=True,
    )

    rank_counts = ranked["_rank"].value_counts().to_dict() if not ranked.empty else {}
    rank_cols = st.columns(5)

    for rank, col in zip(range(1, 6), rank_cols):
        meta = RANK_META[rank]
        selected = ss.mission_selected_rank == rank
        wrap_key = f"rank_card_{rank}" + ("_selected" if selected else "")
        with col:
            with st.container(key=wrap_key):
                if st.button(
                    f"{meta['icon']}\nRANK {rank}\n{meta['name']}\n{rank_counts.get(rank, 0)} THREATS",
                    key=f"rank_selector_{rank}",
                    use_container_width=True,
                ):
                    ss.mission_selected_rank = rank
                    ss.mission_selected_bundle = None
                    ss.mission_threat_index = 0
                    st.rerun()

    selected_rank = ss.mission_selected_rank
    selected_meta = RANK_META[selected_rank]
    rank_view = ranked[ranked["_rank"] == selected_rank].sort_values("_threat_score", ascending=False)

    st.markdown(
        f'<div class="rank-selector-title">{selected_meta["icon"]} RANK {selected_rank} — '
        f'<b>{selected_meta["name"]}</b> • {len(rank_view)} bundles</div>',
        unsafe_allow_html=True,
    )

    if rank_view.empty:
        st.info(f"No bundles currently fall into Rank {selected_rank} for this selected attack category.")
    else:
        # ---- one threat at a time, not a stacked list ----
        total = len(rank_view)
        idx = min(ss.mission_threat_index, total - 1)

        nav_left, nav_mid, nav_right = st.columns([1, 2, 1])
        with nav_left:
            if st.button("← PREV THREAT", key=f"prev_{selected_rank}", use_container_width=True, disabled=(idx == 0)):
                ss.mission_threat_index = max(0, idx - 1)
                ss.mission_selected_bundle = None
                st.rerun()
        with nav_mid:
            st.markdown(f'<div class="threat-nav-bar"><div class="threat-nav-pos">THREAT {idx + 1} OF {total}</div></div>', unsafe_allow_html=True)
        with nav_right:
            if st.button("NEXT THREAT →", key=f"next_{selected_rank}", use_container_width=True, disabled=(idx >= total - 1)):
                ss.mission_threat_index = min(total - 1, idx + 1)
                ss.mission_selected_bundle = None
                st.rerun()

        row = rank_view.iloc[idx]

        bundle_id = str(row.get("bundle_id", "Unknown"))
        source = safe_text(row.get("source", "Unknown source"))
        attack_type = safe_text(row.get("_attack_type_ui", infer_attack_type(row)))
        verdict = safe_text(row.get("verdict", "Under Review"))
        ai_score = as_score(row.get("_ai_score", 0))
        trust_score = as_score(row.get("_trust_score", 0))
        lineage_score = as_score(row.get("_lineage_score", 0))
        threat_score = as_score(row.get("_threat_score", 0))
        ttl_original = safe_text(row.get("ttl_original", "N/A"))
        ttl_new = safe_text(row.get("ttl_new", "N/A"))

        if "Malicious" in str(row.get("verdict", "")):
            solution = f"🛡️ Dynamic TTL Decay applied: TTL {ttl_original}s → {ttl_new}s. Autonomous containment/expiry response evaluated by the pipeline."
        elif "Suspicious" in str(row.get("verdict", "")):
            solution = "🔎 Investigation required: maintain enhanced monitoring and review the evidence trail before escalation."
        else:
            solution = "🟢 Continue monitoring: no immediate autonomous containment action is indicated by the current pipeline verdict."

        render_html(f"""
        <div class="threat-card">
          <div class="threat-head">
            <div><div class="threat-rank">{selected_meta['icon']} RANK {selected_rank} — {selected_meta['name']}</div>
            <div class="threat-level">ATTACK: {attack_type} • BUNDLE {safe_text(bundle_id)} • {source}</div></div>
            <div class="threat-score">{threat_score:.1f}%</div>
          </div>
          <div class="threat-grid single-score">
            <div class="threat-mini"><small>⚡ FINAL / COMBINED THREAT SCORE</small><b>{threat_score:.1f}%</b></div>
          </div>
          <div class="reason" style="margin-top:12px"><b>Signal summary:</b> AI anomaly + TTL-Evidence + DSSLV lineage were combined into this one final priority score.</div>
          <div class="reason" style="margin-top:14px"><b>FINAL VERDICT:</b> {verdict}</div>
          <div class="solution-box"><b>🛡️ RECOMMENDED / AUTONOMOUS ACTION</b><br>{safe_text(solution)}</div>
        </div>
        """)

        is_open = ss.mission_selected_bundle == bundle_id
        toggle_label = "🔎 HIDE FULL THREAT ANALYSIS" if is_open else f"🔎 ANALYZE FULL THREAT — {bundle_id}"
        if st.button(toggle_label, key=f"analyze_{bundle_id}_{selected_rank}", use_container_width=True):
            ss.mission_selected_bundle = None if is_open else bundle_id
            st.rerun()

        if is_open:
            combined_score = as_score(row.get("_combined_score", 0))

            st.markdown('<div class="section-title">🔬 Threat Analysis</div>', unsafe_allow_html=True)
            st.markdown(
                f'<div class="analysis-panel"><b>Bundle ID:</b> {safe_text(bundle_id)} &nbsp; • &nbsp; '
                f'<b>Current Rank:</b> {selected_meta["icon"]} Rank {selected_rank} — {selected_meta["name"]} &nbsp; • &nbsp; '
                f'<b>Overall Threat Score:</b> {threat_score:.1f}%<br><br>'
                f'<b>Final Verdict:</b> {verdict}</div>',
                unsafe_allow_html=True,
            )

            st.markdown(textwrap.dedent("""
            <div class="pipeline-flow">
              <div class="pipeline-node">📡<br>TELEMETRY INPUT</div><div class="pipeline-arrow">↓</div>
              <div class="pipeline-node">🤖<br>AI BEHAVIORAL ENGINE</div><div class="pipeline-arrow">↓</div>
              <div class="pipeline-node">⏳<br>TTL-EVIDENCE TRUST</div><div class="pipeline-arrow">↓</div>
              <div class="pipeline-node">🛰️<br>DSSLV LINEAGE</div><div class="pipeline-arrow">↓</div>
              <div class="pipeline-node">🛡️<br>DYNAMIC TTL DECAY</div><div class="pipeline-arrow">↓</div>
              <div class="pipeline-node">🚨<br>FINAL VERDICT</div>
            </div>
            """), unsafe_allow_html=True)

            st.markdown(score_bar("AI ANOMALY CONFIDENCE", ai_score, "🤖"), unsafe_allow_html=True)
            st.markdown(score_bar("TTL-EVIDENCE TRUST SCORE", trust_score, "⏳"), unsafe_allow_html=True)
            st.markdown(score_bar("DSSLV LINEAGE SCORE", lineage_score, "🛰️"), unsafe_allow_html=True)
            st.markdown(score_bar("COMBINED CONFIDENCE", combined_score, "⚡"), unsafe_allow_html=True)
            st.markdown(score_bar("FINAL THREAT SCORE", threat_score, "🚨"), unsafe_allow_html=True)

            st.markdown("### WHY WAS THIS THREAT RANKED HERE?")
            reasons = row.get("reasons", [])
            if isinstance(reasons, str):
                reasons = [reasons]
            if reasons:
                for reason in reasons:
                    st.markdown(f"✓ {safe_text(reason)}")
            else:
                st.caption(
                    "No explicit reason list was returned by the pipeline for this bundle. "
                    "The displayed rank is based on available pipeline scores and verdict only."
                )
            st.divider()

    st.write("")
    nav1, nav2 = st.columns(2)
    with nav1:
        if st.button("← Run Another Attack Analysis", key="reset_analysis", use_container_width=True):
            ss.mission_selected_bundle = None
            ss.mission_threat_index = 0
            goto("attack_select")
    with nav2:
        if st.button("📊 View Full Mission Analytics Dashboard", key="open_dashboard", use_container_width=True):
            goto("dashboard")


# ============================================================
# SCREEN 5 — FULL ANALYTICS DASHBOARD (opt-in, opened from results)
# Accuracy/precision stats, confusion matrix, charts and the full bundle
# explorer/table - kept off the main flow so the home/results screens
# stay focused, but still reachable in one click.
# ============================================================

def render_dashboard():
    ss = st.session_state
    data, metrics = get_active_result()

    back1, back2 = st.columns(2)
    with back1:
        if st.button("← Back to Threat Ranking", key="dashboard_back_results", use_container_width=True):
            goto("results")
    with back2:
        if st.button("🏠 Back to Home", key="dashboard_back_home", use_container_width=True):
            goto("home")

    st.markdown('<div class="section-title">Analysis</div>', unsafe_allow_html=True)
    st.markdown(
        '<div class="section-description">Results of running every bundle through the AI Engine, '
        'TTL-Evidence, DSSLV, and Dynamic TTL Decay modules.</div>',
        unsafe_allow_html=True,
    )

    verdict_counts = data["verdict"].value_counts()
    total_records = len(data)
    legit = int(verdict_counts.get("Legitimate", 0))
    suspicious = int(verdict_counts.get("Suspicious", 0))
    malicious = int(verdict_counts.get("Malicious (TTL Decayed)", 0))

    st.write("")
    s1, s2, s3, s4 = st.columns(4)
    with s1:
        st.markdown(f'<div class="stat-card"><div class="stat-number">{total_records}</div>'
                    f'<div class="stat-text">Total Bundles Analyzed</div></div>', unsafe_allow_html=True)
    with s2:
        st.markdown(f'<div class="stat-card verdict-legit"><div class="stat-number">{legit}</div>'
                    f'<div class="stat-text">Legitimate</div></div>', unsafe_allow_html=True)
    with s3:
        st.markdown(f'<div class="stat-card verdict-suspicious"><div class="stat-number">{suspicious}</div>'
                    f'<div class="stat-text">Suspicious</div></div>', unsafe_allow_html=True)
    with s4:
        st.markdown(f'<div class="stat-card verdict-malicious"><div class="stat-number">{malicious}</div>'
                    f'<div class="stat-text">Malicious — TTL Decayed</div></div>', unsafe_allow_html=True)

    st.write("")
    st.markdown(
        f'<div style="text-align:center;">'
        f'<span class="metric-pill pill-good">Accuracy {metrics["accuracy"]}%</span>'
        f'<span class="metric-pill pill-good">Precision {metrics["precision"]}%</span>'
        f'<span class="metric-pill pill-warn">Recall {metrics["recall"]}%</span>'
        f'<span class="metric-pill pill-good">F1-Score {metrics["f1_score"]}%</span>'
        f'</div>',
        unsafe_allow_html=True,
    )
    st.caption(
        "Computed against synthetic ground-truth labels attached at dataset generation time "
        "(see src/report_generator.py). Precision is high because Legitimate traffic is never "
        "misflagged; recall reflects that sophisticated spoofing — the hardest case, and the "
        "whole reason TTL-Evidence exists — needs a longer behavioural history to fully erode trust."
    )

    st.write("")
    cm_col, chart_col = st.columns([1, 1])

    with cm_col:
        st.markdown("**Confusion Matrix** (Legitimate vs Malicious/Flagged)")
        labels = metrics["confusion_labels"]
        cm = metrics["confusion_matrix"]
        cm_df = pd.DataFrame(
            cm,
            index=[f"Actual: {l}" for l in labels],
            columns=[f"Predicted: {l}" for l in labels],
        )
        st.dataframe(cm_df, use_container_width=True)

    with chart_col:
        st.markdown("**Trust Score vs Anomaly Confidence**")
        chart_data = data[["anomaly_confidence", "trust_score"]].rename(
            columns={"anomaly_confidence": "AI Anomaly Confidence", "trust_score": "TTL-Evidence Trust Score"}
        )
        st.scatter_chart(chart_data, x="AI Anomaly Confidence", y="TTL-Evidence Trust Score", height=280)
        st.caption("Higher AI anomaly confidence correlates with lower TTL-Evidence trust, as expected.")

    st.write("")
    st.markdown("**Verdicts by Simulated Attack Type**")
    by_type = pd.DataFrame(metrics["by_attack_type"]).fillna(0).astype(int).T
    st.dataframe(by_type, use_container_width=True)

    st.write("")
    dist_col, trust_col = st.columns(2)

    with dist_col:
        st.markdown("**Verdict Distribution**")
        st.bar_chart(verdict_counts, height=280)
        st.caption("How every analyzed bundle was ultimately classified by the pipeline.")

    with trust_col:
        st.markdown("**Trust Score Distribution**")
        if "trust_score" in data.columns:
            trust_values = data["trust_score"].apply(as_score) / 100.0
            bins = pd.cut(
                trust_values,
                bins=[0, .2, .4, .6, .8, 1.0],
                labels=["0.0–0.2", "0.2–0.4", "0.4–0.6", "0.6–0.8", "0.8–1.0"],
                include_lowest=True,
            )
            trust_hist = bins.value_counts().sort_index()
            st.bar_chart(trust_hist, height=280)
            st.caption("Most legitimate traffic clusters near a high TTL-Evidence trust score.")
        else:
            st.info("No trust_score column available.")

    st.write("")
    src_col, time_col = st.columns(2)

    with src_col:
        st.markdown("**Top Sources by Flagged Bundles**")
        if "source" in data.columns:
            flagged = data[data["verdict"] != "Legitimate"]
            if not flagged.empty:
                top_sources = flagged["source"].value_counts().head(8)
                st.bar_chart(top_sources, height=280)
                st.caption("Ground stations, orbiters or relays generating the most suspicious/malicious bundles.")
            else:
                st.success("No flagged bundles from any source.")
        else:
            st.info("No source column available.")

    with time_col:
        st.markdown("**Flagged Bundles Over Time**")
        if "timestamp" in data.columns:
            ts = pd.to_datetime(data["timestamp"], errors="coerce")
            if ts.notna().any():
                trend = pd.DataFrame({"timestamp": ts, "flagged": data["verdict"] != "Legitimate"})
                trend = trend.dropna(subset=["timestamp"]).set_index("timestamp")
                trend_series = trend["flagged"].resample("D").sum()
                if len(trend_series) > 1:
                    st.line_chart(trend_series, height=280)
                    st.caption("Daily count of suspicious/malicious bundles across the monitored period.")
                else:
                    st.info("Not enough distinct timestamps to plot a trend.")
            else:
                st.info("Timestamp column could not be parsed as dates.")
        else:
            st.info("No timestamp column available.")

    render_html("""
    <div class="section-title">Mission Communication Dashboard</div>
    <div class="section-description">
        Explore every communication bundle along with its computed anomaly confidence,
        trust score, lineage score, and final Dynamic-TTL-Decay verdict.
    </div>
    """)

    display_columns = [
        "bundle_id", "timestamp", "source", "status", "relay_path",
        "anomaly_confidence", "trust_score", "dynamic_trust", "lineage_score",
        "ttl_original", "ttl_new", "combined_confidence", "verdict",
    ]
    display_columns = [c for c in display_columns if c in data.columns]

    search = st.text_input("🔍 Search communication records")
    filtered_data = data[display_columns].copy()

    if search:
        mask = filtered_data.astype(str).apply(
            lambda column: column.str.contains(search, case=False, na=False)
        ).any(axis=1)
        filtered_data = filtered_data[mask]

    st.dataframe(filtered_data, use_container_width=True, height=400)

    csv = filtered_data.to_csv(index=False).encode("utf-8")
    st.download_button(
        label="📥 Download Filtered Results",
        data=csv,
        file_name="deepspace_cybershield_results.csv",
        mime="text/csv",
    )

    report_md = report_generator.to_markdown(metrics)
    st.download_button(
        label="📄 Download Detection Report (Markdown)",
        data=report_md.encode("utf-8"),
        file_name="deepspace_cybershield_detection_report.md",
        mime="text/markdown",
    )

    render_html("""
    <div class="footer">
        <h3 style="color:#00d9ff;">DeepSpace CyberShield AI</h3>
        <p>Autonomous AI-powered cybersecurity for the future of interplanetary communication.</p>
        <p>© 2026 DeepSpace CyberShield AI</p>
    </div>
    """)

    if st.button("🔁 Replay Intro"):
        st.session_state.app_stage = "intro"
        st.rerun()


# ============================================================
# ROUTER
# ============================================================

stage = st.session_state.app_stage

if stage == "home":
    render_home()
elif stage == "attack_select":
    render_attack_select()
elif stage == "source_select":
    render_source_select()
elif stage == "upload_page":
    render_upload_page()
elif stage == "default_page":
    render_default_page()
elif stage == "loading":
    render_loading()
elif stage == "results":
    render_ranked_results()
elif stage == "dashboard":
    render_dashboard()
else:
    # Shouldn't normally happen (intro is handled above with st.stop()),
    # but fall back to home instead of a blank screen.
    render_home()