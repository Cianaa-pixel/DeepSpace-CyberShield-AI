import streamlit as st
import pandas as pd
import numpy as np
import os
import time
import sys
 
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
 
 
# ============================================================
# CACHED DETECTION PIPELINE
# (AI Behavioral Engine -> TTL-Evidence -> DSSLV -> Dynamic TTL Decay)
# NOTE: this is intentionally NOT called until after the intro has
# already been sent to the browser, so the cinematic boot sequence
# never waits on the dataset / model run (fixes the blank-screen bug).
# ============================================================
 
@st.cache_data(show_spinner=False)
def load_and_analyze():
    raw = load_or_generate(DATASET_PATH)
    result = run_pipeline(raw)
    metrics = report_generator.summarize(result)
    return result, metrics
 
 
# ============================================================
# SESSION STATE
# ============================================================
 
if "entered" not in st.session_state:
    st.session_state.entered = False
if "selected_bundle" not in st.session_state:
    st.session_state.selected_bundle = None
if "selected_tier" not in st.session_state:
    st.session_state.selected_tier = 1
 
 
def safe_text(value):
    import html
    return html.escape(str(value))
 
 
def render_html(raw_html):
    cleaned = __import__("textwrap").dedent("\n" + raw_html).strip()
    st.markdown(cleaned, unsafe_allow_html=True)
 
 
def pct(value, default=0.0):
    """Normalize a score to a 0-100 percentage regardless of whether the
    pipeline stored it as a 0-1 float or an already-scaled percentage."""
    try:
        v = float(value)
    except (TypeError, ValueError):
        return default
    if np.isnan(v):
        return default
    if -1.0 <= v <= 1.0:
        v = v * 100.0
    return max(0.0, min(100.0, v))
 
 
def verdict_style(verdict):
    v = str(verdict)
    if v == "Malicious (TTL Decayed)":
        return "#ff3b5c", "🔴", "MALICIOUS — TTL DECAYED"
    if v == "Suspicious":
        return "#ffd166", "🟡", "SUSPICIOUS"
    return "#00ffb3", "🟢", "LEGITIMATE"
 
 
# ============================================================
# INTRO TIMING (letter-by-letter title -> boot checklist -> hold -> fade)
# Tuned to land at ~3.5s total so the app never feels frozen.
# ============================================================
 
LETTER_STAGGER = 0.020
LETTER_DURATION = 0.40
LINE_STAGGER = 0.18
LINE_DURATION = 0.40
EXIT_DURATION = 0.6
 
 
def _letter_spans(text, start_delay):
    spans = []
    delay = start_delay
    last_char_delay = start_delay
    for ch in text:
        content = "&nbsp;" if ch == " " else safe_text(ch)
        spans.append(f'<span class="ltr" style="animation-delay:{delay:.3f}s">{content}</span>')
        last_char_delay = delay
        delay += LETTER_STAGGER
    return "".join(spans), last_char_delay
 
 
_part1, _ = _letter_spans("DeepSpace ", 0.0)
_part2, _last_char_delay = _letter_spans("CyberShield AI", len("DeepSpace ") * LETTER_STAGGER)
INTRO_TITLE_HTML = f'<div class="intro-title">{_part1}<span class="hl">{_part2}</span></div>'
 
LETTERS_FINISH = _last_char_delay + LETTER_DURATION
 
BOOT_LINES = [
    "CONNECTING TO DEEP-SPACE NETWORK...",
    "✓ AI BEHAVIORAL ENGINE ONLINE",
    "✓ TTL-EVIDENCE MODEL LOADED",
    "✓ DSSLV LINEAGE SYSTEM VERIFIED",
    "✓ DEEP-SPACE TELEMETRY SYNCHRONIZED",
    "✓ AUTONOMOUS DEFENSE SYSTEM ARMED",
]
 
_boot_start = LETTERS_FINISH + 0.10
_boot_lines_html = ""
_line_delay = _boot_start
for i, line in enumerate(BOOT_LINES):
    cls = "boot-line boot-connecting" if i == 0 else "boot-line"
    _boot_lines_html += f'<div class="{cls}" style="animation-delay:{_line_delay:.3f}s">{safe_text(line)}</div>'
    _line_delay += LINE_STAGGER
LAST_LINE_DELAY = _line_delay - LINE_STAGGER + LINE_DURATION
 
BAR_DELAY = _boot_start + 0.05
FINAL_TEXT_DELAY = LAST_LINE_DELAY + 0.15
EXIT_DELAY = FINAL_TEXT_DELAY + 0.55
TOTAL_INTRO_SECONDS = EXIT_DELAY + EXIT_DURATION + 0.15
 
 
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
 
/* ---------------- CINEMATIC INTRO ---------------- */
.intro-screen { min-height:640px; margin-top:6px; border:1px solid rgba(0,217,255,.25); border-radius:34px; overflow:hidden; position:relative; display:flex; align-items:center; justify-content:center; text-align:center; background:#01040d; box-shadow:0 0 75px rgba(0,217,255,.15),inset 0 0 90px rgba(0,217,255,.05); }
.intro-screen.exiting { animation:introExit 0.6s ease forwards; }
 
/* starfield + parallax particles */
.starfield { position:absolute; inset:0; z-index:0;
  background-image:
    radial-gradient(1.5px 1.5px at 20px 30px, #ffffff 100%, transparent 100%),
    radial-gradient(1.5px 1.5px at 140px 80px, #cdefff 100%, transparent 100%),
    radial-gradient(1px 1px at 90px 160px, #ffffff 100%, transparent 100%),
    radial-gradient(2px 2px at 250px 60px, #9be9ff 100%, transparent 100%),
    radial-gradient(1px 1px at 300px 200px, #ffffff 100%, transparent 100%),
    radial-gradient(1.5px 1.5px at 60px 220px, #ffffff 100%, transparent 100%),
    radial-gradient(1px 1px at 380px 140px, #cdefff 100%, transparent 100%);
  background-repeat:repeat; background-size:400px 260px;
  animation:driftStars 40s linear infinite; opacity:.75; }
.starfield.layer2 { background-size:600px 400px; animation-duration:70s; animation-direction:reverse; opacity:.4; }
.particles { position:absolute; inset:0; z-index:1; overflow:hidden; }
.particle { position:absolute; width:3px; height:3px; border-radius:50%; background:#00d9ff; box-shadow:0 0 8px 2px rgba(0,217,255,.9); animation:floatParticle linear infinite; opacity:0; }
 
/* cyber grid */
.cyber-grid { position:absolute; inset:-20% -20% -20% -20%; z-index:1;
  background-image:linear-gradient(rgba(0,217,255,.16) 1px, transparent 1px), linear-gradient(90deg, rgba(0,217,255,.16) 1px, transparent 1px);
  background-size:44px 44px; transform:perspective(500px) rotateX(58deg); transform-origin:center bottom;
  mask-image:radial-gradient(circle at 50% 100%, black 5%, transparent 68%);
  -webkit-mask-image:radial-gradient(circle at 50% 100%, black 5%, transparent 68%);
  animation:panGrid 6s linear infinite; opacity:.55; }
 
/* scanning line */
.scan-line { position:absolute; left:0; right:0; height:2px; z-index:2; background:linear-gradient(90deg, transparent, #00d9ff, #baffef, #00d9ff, transparent); box-shadow:0 0 18px 3px rgba(0,217,255,.85); animation:scanMove 2.6s ease-in-out infinite; }
 
/* radar rings + AI core */
.radar-wrap { position:absolute; top:50%; left:50%; width:0; height:0; z-index:1; }
.radar-ring { position:absolute; top:50%; left:50%; border-radius:50%; border:1px solid rgba(0,217,255,.30); transform:translate(-50%,-50%); }
.radar-ring.r1 { width:230px; height:230px; animation:spinCW 7s linear infinite; border-top-color:#00d9ff; border-right-color:#00d9ff; }
.radar-ring.r2 { width:340px; height:340px; animation:spinCCW 11s linear infinite; border-bottom-color:#7c6cff; border-left-color:#7c6cff; }
.radar-ring.r3 { width:460px; height:460px; animation:spinCW 16s linear infinite; border-top-color:rgba(0,255,179,.35); }
.ai-core { position:absolute; top:50%; left:50%; width:64px; height:64px; margin:-32px 0 0 -32px; border-radius:50%; z-index:3;
  background:radial-gradient(circle, #baffef 0%, #00d9ff 45%, rgba(0,217,255,0) 75%); box-shadow:0 0 40px 12px rgba(0,217,255,.65), 0 0 90px 30px rgba(0,217,255,.25); animation:corePulse 1.8s ease-in-out infinite; }
 
.intro-content { position:relative; z-index:4; width:100%; padding:44px 20px; }
.intro-shield { font-size:30px; margin-bottom:6px; filter:drop-shadow(0 0 20px rgba(0,217,255,.8)); }
.intro-kicker { color:#71ecff; letter-spacing:5px; font-size:11px; text-transform:uppercase; margin:6px 0 10px; opacity:.9; }
.intro-title { font-family:'Orbitron',sans-serif; font-size:clamp(30px,5.2vw,58px); font-weight:800; line-height:1.05; color:#f1fdff; text-shadow:0 0 18px rgba(0,217,255,.55),0 0 45px rgba(0,217,255,.22); }
.intro-title .hl { color:#00d9ff; }
.intro-title .ltr { display:inline-block; opacity:0; animation:letterIn 0.4s cubic-bezier(.2,.8,.2,1) both; }
 
.boot-console { margin:22px auto 0; max-width:520px; text-align:left; padding:14px 18px; border-radius:14px; background:rgba(0,10,20,.55); border:1px solid rgba(0,217,255,.20); font-family:'Orbitron',monospace; font-size:12.5px; min-height:150px; backdrop-filter:blur(6px); }
.boot-line { opacity:0; color:#7fffd4; letter-spacing:.5px; padding:2.5px 0; animation:lineIn 0.4s ease both; }
.boot-line.boot-connecting { color:#71ecff; }
 
.intro-bar { width:min(480px,86%); height:4px; margin:20px auto 4px; background:rgba(255,255,255,.08); border-radius:99px; overflow:hidden; opacity:0; animation:fadeUp 0.5s ease forwards; }
.intro-bar div { height:100%; width:100%; transform-origin:left; background:linear-gradient(90deg,#00d9ff,#00ffb3,#7c6cff); animation:loadBar 1.1s ease-in-out infinite; }
 
.intro-final { margin-top:16px; opacity:0; animation:fadeUp 0.5s ease forwards; }
.intro-final .line1 { font-family:'Orbitron',sans-serif; font-weight:800; color:#00ffb3; letter-spacing:3px; font-size:18px; text-shadow:0 0 18px rgba(0,255,179,.6); }
.intro-final .line2 { color:#9fe9ff; letter-spacing:2px; font-size:12px; margin-top:4px; }
 
/* skip button — pulled visually INTO the intro card */
.skip-wrap-anchor { margin-top:-52px; position:relative; z-index:10; display:flex; justify-content:center; }
.st-key-skip_intro_btn button { border-radius:999px !important; padding:8px 26px !important; font-family:'Orbitron',sans-serif !important; font-size:11px !important; letter-spacing:1.5px !important; background:rgba(0,20,30,.65) !important; color:#71ecff !important; border:1px solid rgba(0,217,255,.45) !important; box-shadow:0 0 18px rgba(0,217,255,.18) !important; backdrop-filter:blur(6px); }
.st-key-skip_intro_btn button:hover { color:#02111d !important; background:linear-gradient(90deg,#00d9ff,#00ffb3) !important; box-shadow:0 0 30px rgba(0,217,255,.55) !important; transform:translateY(-2px); }
 
/* keyframes */
@keyframes driftStars { from { background-position:0 0; } to { background-position:-400px 260px; } }
@keyframes floatParticle { 0% { transform:translateY(0) translateX(0); opacity:0; } 10% { opacity:1; } 90% { opacity:1; } 100% { transform:translateY(-140px) translateX(20px); opacity:0; } }
@keyframes panGrid { from { background-position:0 0; } to { background-position:0 44px; } }
@keyframes scanMove { 0% { top:6%; opacity:0; } 10% { opacity:1; } 50% { top:92%; opacity:1; } 60% { opacity:0; } 100% { top:6%; opacity:0; } }
@keyframes spinCW { from { transform:translate(-50%,-50%) rotate(0deg); } to { transform:translate(-50%,-50%) rotate(360deg); } }
@keyframes spinCCW { from { transform:translate(-50%,-50%) rotate(0deg); } to { transform:translate(-50%,-50%) rotate(-360deg); } }
@keyframes corePulse { 0%,100% { transform:scale(0.9); opacity:.85; } 50% { transform:scale(1.15); opacity:1; } }
@keyframes letterIn { 0% { opacity:0; transform:translateY(18px) scale(.6); filter:blur(7px); } 100% { opacity:1; transform:none; filter:none; } }
@keyframes lineIn { 0% { opacity:0; transform:translateX(-10px); } 100% { opacity:1; transform:none; } }
@keyframes fadeUp { from { opacity:0; transform:translateY(14px); } to { opacity:1; transform:none; } }
@keyframes loadBar { 0% { transform:scaleX(.08); opacity:.55; } 55% { transform:scaleX(1); opacity:1; } 100% { transform:scaleX(.08); opacity:.55; } }
@keyframes introExit { 0% { opacity:1; transform:scale(1); filter:blur(0); } 100% { opacity:0; transform:scale(1.04); filter:blur(10px); } }
 
/* general */
.hero-container { min-height:390px; display:flex; align-items:center; justify-content:center; text-align:center; padding:35px 25px; border-radius:28px; background:radial-gradient(circle,rgba(0,217,255,.11),transparent 65%); }
.hero-title { font-size:clamp(38px,5vw,60px); font-weight:800; line-height:1.1; color:white; text-shadow:0 0 25px rgba(0,217,255,.35); } .hero-highlight { color:#00d9ff; text-shadow:0 0 20px #00d9ff; }
.hero-subtitle { color:#8fe9ff; font-size:20px; margin-top:14px; } .hero-description { max-width:850px; margin:18px auto; color:#d4dde1; line-height:1.8; }
.section-title { text-align:center; font-size:34px; font-weight:800; color:#00d9ff; margin:52px 0 10px; text-shadow:0 0 20px rgba(0,217,255,.35); } .section-description { text-align:center; max-width:900px; margin:0 auto 22px; color:#b8c7cd; line-height:1.8; }
 
/* ---------------- THREAT COMMAND CENTER ---------------- */
.cmd-intro { text-align:center; color:#b8c7cd; margin-bottom:18px; }
.rank-grid { display:grid; grid-template-columns:repeat(5,1fr); gap:12px; margin-bottom:26px; }
@media (max-width:900px) { .rank-grid { grid-template-columns:repeat(2,1fr); } }
.rank-card-deco { border-radius:16px 16px 0 0; padding:16px 10px 10px; text-align:center; background:rgba(255,255,255,.035); border:1px solid rgba(255,255,255,.10); border-bottom:none; transition:.2s; }
.rank-card-deco .rk-emoji { font-size:26px; }
.rank-card-deco .rk-label { font-family:'Orbitron',sans-serif; font-weight:800; font-size:13px; margin-top:6px; letter-spacing:1px; }
.rank-card-deco .rk-name { font-size:11px; letter-spacing:1px; opacity:.85; margin-top:2px; }
.rank-card-deco .rk-count { margin-top:10px; font-size:12px; font-weight:700; padding:3px 10px; border-radius:20px; display:inline-block; background:rgba(255,255,255,.06); }
.rank-card-deco.active { box-shadow:0 0 26px var(--rk-color,#00d9ff); border-color:var(--rk-color,#00d9ff); background:linear-gradient(180deg, color-mix(in srgb, var(--rk-color,#00d9ff) 18%, transparent), transparent); }
div[data-testid="column"] div[class*="st-key-tier_btn_"] button { border-radius:0 0 16px 16px !important; margin-top:-1px !important; width:100%; }
 
/* threat cards */
.threat-card { padding:20px 22px; border-radius:20px; background:rgba(255,255,255,.035); border:1px solid rgba(255,255,255,.10); margin-bottom:14px; border-left:4px solid var(--tc-color,#00d9ff); transition:.2s; }
.threat-card:hover { transform:translateX(4px); box-shadow:0 0 26px rgba(0,217,255,.10); }
.tc-top { display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:8px; }
.tc-rank-pill { font-family:'Orbitron',sans-serif; font-weight:800; font-size:12px; letter-spacing:1px; padding:5px 12px; border-radius:20px; color:#02111d; background:var(--tc-color,#00d9ff); }
.tc-bundle { color:#effcff; font-weight:700; font-size:16px; margin-top:8px; }
.tc-source { color:#8fa3ad; font-size:12.5px; margin-bottom:10px; }
.score-mini-grid { display:grid; grid-template-columns:repeat(4,1fr); gap:10px; margin:12px 0 6px; }
@media (max-width:900px) { .score-mini-grid { grid-template-columns:repeat(2,1fr); } }
.score-mini { padding:10px; border-radius:12px; background:rgba(255,255,255,.03); border:1px solid rgba(255,255,255,.07); text-align:center; }
.score-mini .sm-label { font-size:10px; letter-spacing:.6px; color:#9fb4bd; text-transform:uppercase; }
.score-mini .sm-value { font-size:18px; font-weight:800; color:#00d9ff; margin-top:2px; }
.tc-verdict { margin-top:10px; padding:9px 14px; border-radius:12px; font-weight:700; font-size:12.5px; display:inline-block; }
 
/* score bars (used in analyze panel + explorer) */
.score-bar-item { margin:14px 0; }
.score-bar-top { display:flex; justify-content:space-between; font-size:12.5px; color:#d6e4e9; margin-bottom:5px; }
.score-bar-track { height:11px; border-radius:8px; background:rgba(255,255,255,.07); overflow:hidden; }
.score-bar-fill { height:100%; border-radius:8px; transition:width .4s ease; box-shadow:0 0 12px currentColor; }
 
/* analyze panel */
.analysis-panel { padding:26px; border-radius:24px; background:linear-gradient(145deg,rgba(0,217,255,.07),rgba(111,92,255,.05)); border:1px solid rgba(0,217,255,.22); margin-top:10px; }
.analysis-head { display:flex; flex-wrap:wrap; gap:22px; justify-content:space-between; align-items:center; margin-bottom:6px; }
.analysis-head .ah-item .ah-label { font-size:10px; letter-spacing:.8px; color:#9fb4bd; text-transform:uppercase; }
.analysis-head .ah-item .ah-value { font-size:20px; font-weight:800; color:#00d9ff; }
.pipeline-flow { display:flex; flex-direction:column; align-items:center; gap:2px; margin:20px 0; }
.pipeline-step { width:min(520px,92%); text-align:center; padding:10px 14px; border-radius:14px; background:rgba(255,255,255,.045); border:1px solid rgba(0,217,255,.20); color:#dce8ec; font-size:13px; font-weight:600; }
.pipeline-arrow { color:#00d9ff; font-size:15px; opacity:.8; }
.alert-box { padding:15px 18px; border-radius:15px; margin-top:14px; background:rgba(255,107,127,.08); border:1px solid rgba(255,107,127,.25); color:#ffdfe3; }
.why-box { margin-top:16px; padding:16px 18px; border-radius:16px; background:rgba(255,255,255,.03); border:1px solid rgba(255,255,255,.08); }
.why-box h4 { color:#00d9ff; margin:0 0 8px; font-size:14px; }
.why-box .wr { color:#cdd8dc; font-size:13.5px; line-height:1.8; }
 
.features-grid { display:grid; grid-template-columns:repeat(3,1fr); gap:18px; margin-top:6px; }
@media (max-width:1000px) { .features-grid { grid-template-columns:repeat(2,1fr); } }
@media (max-width:640px) { .features-grid { grid-template-columns:1fr; } }
.feature-card { padding:23px; border-radius:20px; background:rgba(255,255,255,.045); border:1px solid rgba(255,255,255,.08); min-height:200px; height:100%; display:flex; flex-direction:column; transition:.25s; box-sizing:border-box; } .feature-card:hover { transform:translateY(-5px); border-color:rgba(0,217,255,.55); box-shadow:0 0 30px rgba(0,217,255,.12); } .feature-tag { display:inline-block; align-self:flex-start; font-size:10px; font-weight:800; letter-spacing:.7px; color:#02111d; background:linear-gradient(90deg,#00d9ff,#00ffb3); padding:4px 10px; border-radius:20px; margin-bottom:9px; } .feature-title { color:#00d9ff; font-size:18px; font-weight:700; margin-bottom:8px; } .feature-text { color:#d1d9dd; line-height:1.65; font-size:13.5px; flex-grow:1; }
.stat-card { text-align:center; padding:22px 12px; border-radius:18px; background:rgba(255,255,255,.04); border:1px solid rgba(255,255,255,.08); } .stat-number { font-size:36px; font-weight:800; color:#00d9ff; } .stat-text { color:#c0cbd0; font-size:13px; } .verdict-legit .stat-number { color:#00ffb3; } .verdict-suspicious .stat-number { color:#ffd166; } .verdict-malicious .stat-number { color:#ff6b7f; }
.metric-pill { display:inline-block; padding:6px 14px; border-radius:30px; font-size:12px; font-weight:800; margin:4px; } .pill-good { background:rgba(0,255,179,.10); color:#00ffb3; border:1px solid rgba(0,255,179,.35); } .pill-warn { background:rgba(255,209,102,.10); color:#ffd166; border:1px solid rgba(255,209,102,.35); } .workflow-step { text-align:center; padding:15px 7px; border-radius:18px; background:rgba(255,255,255,.04); border:1px solid rgba(0,217,255,.16); color:#dce8ec; font-size:13px; }
.footer { text-align:center; padding:35px; margin-top:55px; color:#718087; border-top:1px solid rgba(255,255,255,.08); }
 
[data-testid='stImage'] { display:flex; justify-content:center; }
[data-testid='stImage'] img { object-fit:contain; }
.stButton > button { border-radius:999px; padding:9px 18px; font-weight:800; border:1px solid rgba(0,217,255,.35); background:linear-gradient(90deg,#00d9ff,#00ffb3); color:#02111d; transition:.2s; } .stButton > button:hover { transform:translateY(-2px); box-shadow:0 0 24px rgba(0,217,255,.35); }
</style>
""", unsafe_allow_html=True)
 
 
# ============================================================
# NAVBAR
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
# ANIMATED INTRO — renders instantly, has ZERO dependency on the
# dataset or pipeline so there is never a blank frame while models run.
# ============================================================
 
if not st.session_state.entered:
    particles_html = "".join(
        f'<span class="particle" style="left:{(i * 37) % 100}%; animation-duration:{6 + (i % 5)}s; animation-delay:{(i * 0.4) % 4:.2f}s;"></span>'
        for i in range(18)
    )
 
    intro_html = f"""
<div class="intro-screen">
  <div class="starfield"></div>
  <div class="starfield layer2"></div>
  <div class="cyber-grid"></div>
  <div class="particles">{particles_html}</div>
  <div class="radar-wrap">
    <div class="radar-ring r1"></div>
    <div class="radar-ring r2"></div>
    <div class="radar-ring r3"></div>
  </div>
  <div class="ai-core"></div>
  <div class="scan-line"></div>
  <div class="intro-content">
    <div class="intro-shield">🛡️</div>
    <div class="intro-kicker">AUTONOMOUS CYBER DEFENSE • BEYOND EARTH</div>
    {INTRO_TITLE_HTML}
    <div class="boot-console">
      {_boot_lines_html}
    </div>
    <div class="intro-bar" style="animation-delay:{BAR_DELAY:.2f}s;"><div></div></div>
    <div class="intro-final" style="animation-delay:{FINAL_TEXT_DELAY:.2f}s;">
      <div class="line1">SYSTEM ONLINE</div>
      <div class="line2">AUTONOMOUS CYBER DEFENSE READY</div>
    </div>
  </div>
</div>
"""
    render_html(intro_html)
 
    st.markdown('<div class="skip-wrap-anchor">', unsafe_allow_html=True)
    skip_col1, skip_col2, skip_col3 = st.columns([3, 1.4, 3])
    with skip_col2:
        skipped = st.button("⏭ SKIP INTRO", use_container_width=True, key="skip_intro_btn")
    st.markdown('</div>', unsafe_allow_html=True)
 
    if skipped:
        st.session_state.entered = True
        st.rerun()
    else:
        time.sleep(TOTAL_INTRO_SECONDS)
        st.session_state.entered = True
        st.rerun()
    st.stop()
 
 
# ============================================================
# Dataset + pipeline only run once we're past the intro.
# ============================================================
 
data, metrics = load_and_analyze()
 
 
# ============================================================
# HERO SECTION
# ============================================================
 
render_html("""
<div class="hero-container">
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
 
image_col1, image_col2, image_col3 = st.columns([1, 2, 1])
with image_col1:
    if os.path.exists(SATELLITE_PATH):
        st.image(SATELLITE_PATH, width=130)
with image_col2:
    if os.path.exists(DEFENSE_PATH):
        st.image(DEFENSE_PATH, width=480)
with image_col3:
    if os.path.exists(EARTH_PATH):
        st.image(EARTH_PATH, width=130)
 
 
# ============================================================
# ============================================================
# THREAT COMMAND CENTER — dynamic 5-tier ranking system
# ============================================================
st.markdown('<div class="section-title">🚨 Threat Command Center</div>', unsafe_allow_html=True)
render_html("""
<div class="cmd-intro">Select a threat priority level to investigate. Rankings are computed live from the
AI Engine, TTL-Evidence, DSSLV Lineage and Dynamic TTL Decay pipeline output.</div>
""")
 
RANK_META = {
    1: {"emoji": "🥇", "name": "CRITICAL", "color": "#ff3b5c"},
    2: {"emoji": "🥈", "name": "HIGH RISK", "color": "#ff8c42"},
    3: {"emoji": "🥉", "name": "SUSPICIOUS", "color": "#ffd166"},
    4: {"emoji": "🔵", "name": "MEDIUM", "color": "#4fb0ff"},
    5: {"emoji": "🟢", "name": "LOW", "color": "#00ffb3"},
}
 
# Pull every flagged bundle from the existing pipeline-driven ranker
# (this reuses report_generator.rank_fake_signals as-is — the detection
# pipeline itself is never modified).
_flagged_total = int((data["verdict"] != "Legitimate").sum()) if "verdict" in data.columns else len(data)
ranked = report_generator.rank_fake_signals(data, top_n=max(_flagged_total, 1))
 
if ranked.empty:
    st.success("No suspicious or malicious bundles detected in the current dataset.")
    work = ranked.copy()
else:
    work = ranked.copy()
    work["bundle_id"] = work["bundle_id"].astype(str)
 
    # Backfill any pipeline scores the ranked view doesn't already carry,
    # pulling them from the full pipeline output by bundle_id.
    lookup_source = data.copy()
    lookup_source["bundle_id"] = lookup_source["bundle_id"].astype(str)
    lookup_source = lookup_source.set_index("bundle_id")
 
    for col in ["anomaly_confidence", "combined_confidence", "trust_score", "lineage_score", "priority_score", "verdict", "source"]:
        if col not in work.columns:
            if col in lookup_source.columns:
                work[col] = work["bundle_id"].map(lookup_source[col])
            else:
                work[col] = np.nan
 
    # The pipeline's own combined/priority score is the most trustworthy
    # single signal for overall threat severity — prefer it, and fall back
    # gracefully if a particular column is missing for this dataset.
    def _threat_score(row):
        for col in ["priority_score", "combined_confidence", "anomaly_confidence"]:
            val = row.get(col, np.nan)
            try:
                fval = float(val)
                if not np.isnan(fval):
                    return pct(fval)
            except (TypeError, ValueError):
                continue
        return 0.0
 
    work["threat_score"] = work.apply(_threat_score, axis=1)
    work = work.sort_values("threat_score", ascending=False).reset_index(drop=True)
 
    # Dynamic 5-way bucketing by descending threat score — always reflects
    # the *current* pipeline output rather than a fixed record count.
    n = len(work)
    tiers = np.empty(n, dtype=int)
    for i, idxs in enumerate(np.array_split(np.arange(n), 5)):
        tiers[idxs] = i + 1
    work["tier"] = tiers
 
tier_counts = work["tier"].value_counts().to_dict() if not work.empty else {}
 
# ---- Rank selector cards ----
rank_cols = st.columns(5)
for i, col in enumerate(rank_cols, start=1):
    meta = RANK_META[i]
    count = int(tier_counts.get(i, 0))
    active = st.session_state.selected_tier == i
    with col:
        render_html(f"""
<div class="rank-card-deco {'active' if active else ''}" style="--rk-color:{meta['color']};">
  <div class="rk-emoji">{meta['emoji']}</div>
  <div class="rk-label" style="color:{meta['color']};">RANK {i}</div>
  <div class="rk-name">{meta['name']}</div>
  <div class="rk-count">{count} Threat{'s' if count != 1 else ''}</div>
</div>
""")
        if st.button(f"View Rank {i}", key=f"tier_btn_{i}", use_container_width=True):
            st.session_state.selected_tier = i
            st.rerun()
 
_active_meta = RANK_META[st.session_state.selected_tier]
st.markdown(
    f"<style>.st-key-tier_btn_{st.session_state.selected_tier} button {{ "
    f"border-color:{_active_meta['color']} !important; "
    f"box-shadow:0 0 24px {_active_meta['color']}88 !important; "
    f"background:linear-gradient(90deg,{_active_meta['color']},#ffffff33) !important; }}</style>",
    unsafe_allow_html=True,
)
 
# ---- Threat cards for the selected rank ----
if not work.empty:
    tier_view = work[work["tier"] == st.session_state.selected_tier].sort_values(
        "threat_score", ascending=False
    )
    meta = RANK_META[st.session_state.selected_tier]
 
    if tier_view.empty:
        st.info(f"No bundles currently fall into {meta['emoji']} RANK {st.session_state.selected_tier} — {meta['name']}.")
 
    for _, row in tier_view.iterrows():
        bundle_id = str(row["bundle_id"])
        v_color, v_icon, v_text = verdict_style(row.get("verdict", ""))
        reasons = row.get("reasons", [])
        reason_text = " • ".join(str(r) for r in reasons[:3]) if isinstance(reasons, (list, tuple)) and reasons else \
            "Multiple behavioral, trust and lineage signals contributed to this score."
 
        ai_score = pct(row.get("anomaly_confidence", 0))
        trust_score = pct(row.get("trust_score", 0))
        lineage_score = pct(row.get("lineage_score", 0))
        final_score = row.get("threat_score", pct(row.get("combined_confidence", 0)))
 
        render_html(f"""
<div class="threat-card" style="--tc-color:{meta['color']};">
  <div class="tc-top">
    <span class="tc-rank-pill">{meta['emoji']} RANK {st.session_state.selected_tier} — {meta['name']}</span>
    <span style="color:#8fa3ad;font-size:11.5px;">{safe_text(reason_text[:70])}{'…' if len(reason_text) > 70 else ''}</span>
  </div>
  <div class="tc-bundle">Bundle: {safe_text(bundle_id)}</div>
  <div class="tc-source">Source: {safe_text(row.get('source', 'Unknown'))}</div>
  <div class="score-mini-grid">
    <div class="score-mini"><div class="sm-label">🤖 AI Engine</div><div class="sm-value">{ai_score:.1f}%</div></div>
    <div class="score-mini"><div class="sm-label">⏳ TTL-Evidence</div><div class="sm-value">{trust_score:.1f}%</div></div>
    <div class="score-mini"><div class="sm-label">🛰️ DSSLV Lineage</div><div class="sm-value">{lineage_score:.1f}%</div></div>
    <div class="score-mini"><div class="sm-label">⚡ Final Score</div><div class="sm-value">{final_score:.1f}%</div></div>
  </div>
  <div class="tc-verdict" style="background:{v_color}22;color:{v_color};border:1px solid {v_color}55;">{v_icon} {v_text}</div>
</div>
""")
        if st.button(f"🔎 ANALYZE FULL THREAT — {bundle_id}", key=f"analyze_{bundle_id}", use_container_width=True):
            st.session_state.selected_bundle = bundle_id
            st.rerun()
 
# ============================================================
# CLICKED THREAT ANALYSIS — premium investigation panel
# ============================================================
if st.session_state.selected_bundle is not None:
    selected_id = str(st.session_state.selected_bundle)
    matches = data[data["bundle_id"].astype(str) == selected_id]
    if not matches.empty:
        row = matches.iloc[0]
        rmatch = work[work["bundle_id"] == selected_id] if not work.empty else pd.DataFrame()
        tier_num = int(rmatch.iloc[0]["tier"]) if not rmatch.empty else None
        tier_meta = RANK_META.get(tier_num, {"emoji": "⚪", "name": "UNRANKED", "color": "#8fa3ad"})
        final_score = float(rmatch.iloc[0]["threat_score"]) if not rmatch.empty else pct(row.get("combined_confidence", 0))
        v_color, v_icon, v_text = verdict_style(row.get("verdict", ""))
 
        st.markdown('<div class="section-title">🔬 Live Threat Analysis</div>', unsafe_allow_html=True)
 
        render_html(f"""
<div class="analysis-panel">
  <div class="analysis-head">
    <div class="ah-item"><div class="ah-label">Bundle ID</div><div class="ah-value">{safe_text(selected_id)}</div></div>
    <div class="ah-item"><div class="ah-label">Current Rank</div><div class="ah-value" style="color:{tier_meta['color']};">{tier_meta['emoji']} RANK {tier_num if tier_num else '—'}</div></div>
    <div class="ah-item"><div class="ah-label">Threat Level</div><div class="ah-value" style="color:{tier_meta['color']};">{tier_meta['name']}</div></div>
    <div class="ah-item"><div class="ah-label">Overall Threat Score</div><div class="ah-value">{final_score:.1f}%</div></div>
  </div>
 
  <div class="pipeline-flow">
    <div class="pipeline-step">📡 TELEMETRY INPUT</div>
    <div class="pipeline-arrow">↓</div>
    <div class="pipeline-step">🤖 AI BEHAVIORAL ENGINE</div>
    <div class="pipeline-arrow">↓</div>
    <div class="pipeline-step">⏳ TTL-EVIDENCE TRUST ANALYSIS</div>
    <div class="pipeline-arrow">↓</div>
    <div class="pipeline-step">🛰️ DSSLV LINEAGE VERIFICATION</div>
    <div class="pipeline-arrow">↓</div>
    <div class="pipeline-step">🛡️ DYNAMIC TTL DECAY</div>
    <div class="pipeline-arrow">↓</div>
    <div class="pipeline-step" style="border-color:{v_color};color:{v_color};">🚨 FINAL VERDICT: {v_text}</div>
  </div>
</div>
""")
 
        # Score bars rendered separately (kept out of the f-string above for clarity)
        ai_c = pct(row.get("anomaly_confidence", 0))
        trust_c = pct(row.get("trust_score", 0))
        lineage_c = pct(row.get("lineage_score", 0))
        combined_c = pct(row.get("combined_confidence", final_score))
 
        render_html(f"""
<div class="analysis-panel" style="margin-top:-14px;">
  <div class="score-bar-item">
    <div class="score-bar-top"><span>🤖 AI ANOMALY CONFIDENCE</span><span>{ai_c:.1f}%</span></div>
    <div class="score-bar-track"><div class="score-bar-fill" style="width:{ai_c}%;background:#00d9ff;color:#00d9ff;"></div></div>
  </div>
  <div class="score-bar-item">
    <div class="score-bar-top"><span>⏳ TTL-EVIDENCE TRUST SCORE</span><span>{trust_c:.1f}%</span></div>
    <div class="score-bar-track"><div class="score-bar-fill" style="width:{trust_c}%;background:#ffd166;color:#ffd166;"></div></div>
  </div>
  <div class="score-bar-item">
    <div class="score-bar-top"><span>🛰️ DSSLV LINEAGE SCORE</span><span>{lineage_c:.1f}%</span></div>
    <div class="score-bar-track"><div class="score-bar-fill" style="width:{lineage_c}%;background:#7c6cff;color:#7c6cff;"></div></div>
  </div>
  <div class="score-bar-item">
    <div class="score-bar-top"><span>⚡ COMBINED / FINAL CONFIDENCE</span><span>{combined_c:.1f}%</span></div>
    <div class="score-bar-track"><div class="score-bar-fill" style="width:{combined_c}%;background:{v_color};color:{v_color};"></div></div>
  </div>
</div>
""")
 
        if v_text == "MALICIOUS — TTL DECAYED":
            render_html(f"""<div class="alert-box">🔴 <b>MALICIOUS — TTL DECAYED</b><br>
This bundle accumulated enough evidence for the passive TTL defense response: its Bundle Protocol
TTL was decayed toward zero so the native DTN garbage collector expires it automatically.</div>""")
        elif v_text == "SUSPICIOUS":
            render_html("""<div class="alert-box" style="background:rgba(255,209,102,.08);border-color:rgba(255,209,102,.25);color:#fff0c2;">
🟡 <b>SUSPICIOUS</b><br>This signal should be reviewed by the mission operator.</div>""")
 
        # WHY WAS THIS THREAT RANKED HERE — from the real pipeline reasons
        why_reasons = []
        if not rmatch.empty:
            raw_reasons = rmatch.iloc[0].get("reasons", [])
            if isinstance(raw_reasons, (list, tuple)):
                why_reasons = [str(r) for r in raw_reasons]
        if not why_reasons:
            why_reasons = ["Multiple pipeline signals (AI anomaly confidence, TTL-Evidence trust decay, "
                            "and DSSLV lineage score) combined to produce this bundle's threat score."]
 
        why_html = "".join(f'<div class="wr">✓ {safe_text(r)}</div>' for r in why_reasons)
        render_html(f"""
<div class="why-box">
  <h4>WHY WAS THIS THREAT RANKED HERE?</h4>
  {why_html}
</div>
""")
 
        d1, d2 = st.columns(2)
        with d1:
            st.markdown("**Communication details**")
            st.write(f"**Source:** {row.get('source','N/A')}")
            st.write(f"**Timestamp:** {row.get('timestamp','N/A')}")
            st.write(f"**Relay path:** {row.get('relay_path','N/A')}")
        with d2:
            st.markdown("**TTL response**")
            st.write(f"**Original TTL:** {row.get('ttl_original','N/A')} s")
            st.write(f"**New TTL (post decay):** {row.get('ttl_new','N/A')} s")
            st.write(f"**Verdict:** {row.get('verdict','N/A')}")
 
        if st.button("✕ Close Threat Analysis", key="close_analysis"):
            st.session_state.selected_bundle = None
            st.rerun()
 
# ============================================================
# MISSION
# ============================================================
 
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
    st.image(AI_NETWORK_PATH, caption="AI-Powered Deep Space Communication Monitoring", width=600)
 
 
# ============================================================
# FEATURES
# ============================================================
 
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
     "Every bundle is scored end-to-end and grouped into five dynamic risk tiers, surfacing "
     "the highest-priority signals first instead of leaving an operator to scroll through a "
     "flat log during a live incident."),
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
    st.image(ANOMALY_PATH, caption="AI Anomaly Detection System", width=600)
 
 
# ============================================================
# AI WORKFLOW
# ============================================================
 
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
 
 
# ============================================================
# LIVE MISSION SECURITY ANALYSIS
# ============================================================
 
st.markdown('<div class="section-title">Analysis</div>', unsafe_allow_html=True)
st.markdown(
    '<div class="section-description">Results of running every bundle through the AI Engine, '
    'TTL-Evidence, DSSLV, and Dynamic TTL Decay modules, just now.</div>',
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
        bins = pd.cut(
            data["trust_score"], bins=[0, .2, .4, .6, .8, 1.0],
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
 
 
# ============================================================
# DATASET / BUNDLE EXPLORER
# ============================================================
 
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
 
 
# ============================================================
# FOOTER
# ============================================================
 
render_html("""
<div class="footer">
    <h3 style="color:#00d9ff;">DeepSpace CyberShield AI</h3>
    <p>Autonomous AI-powered cybersecurity for the future of interplanetary communication.</p>
    <p>© 2026 DeepSpace CyberShield AI</p>
</div>
""")
 
if st.button("🔁 Replay Intro"):
    st.session_state.entered = False
    st.session_state.selected_bundle = None
    st.rerun()
 