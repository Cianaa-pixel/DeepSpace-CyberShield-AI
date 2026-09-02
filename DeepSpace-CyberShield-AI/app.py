import streamlit as st
import pandas as pd
import os
import textwrap
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
# LOAD DATA + RUN THE REAL DETECTION PIPELINE
# (AI Behavioral Engine -> TTL-Evidence -> DSSLV -> Dynamic TTL Decay)
# ============================================================

@st.cache_data(show_spinner=False)
def load_and_analyze():
    raw = load_or_generate(DATASET_PATH)
    result = run_pipeline(raw)
    metrics = report_generator.summarize(result)
    return result, metrics


data, metrics = load_and_analyze()


# ============================================================
# SESSION STATE
# ============================================================

if "entered" not in st.session_state:
    st.session_state.entered = False


# ============================================================
# CUSTOM CSS
# ============================================================
# NOTE: every st.markdown(..., unsafe_allow_html=True) call in this file
# passes its HTML through textwrap.dedent() first. Markdown treats any
# line indented 4+ spaces as a literal code block, and Python's own
# indentation was leaking into these multi-line strings - that's what was
# causing raw HTML/CSS to print as text instead of rendering (see the
# intro-sequence bug). dedent() strips that leading whitespace so the
# parser sees clean HTML instead of an "indented code block".

st.markdown(textwrap.dedent("""
<style>

@import url('https://fonts.googleapis.com/css2?family=Poppins:wght@300;400;500;600;700;800&display=swap');

html { scroll-behavior: smooth; }
body { font-family: 'Poppins', sans-serif; }

.stApp {
    background:
        radial-gradient(circle at 20% 20%, rgba(0, 217, 255, 0.10), transparent 30%),
        radial-gradient(circle at 80% 60%, rgba(111, 92, 255, 0.12), transparent 35%),
        #020611;
    color: white;
}

#MainMenu { visibility: hidden; }
footer { visibility: hidden; }
header { background: transparent !important; }

.brand-title { color: #00d9ff; font-size: 24px; font-weight: 700; }

.hero-container {
    min-height: 500px;
    display: flex;
    align-items: center;
    justify-content: center;
    text-align: center;
    padding: 50px 30px;
    border-radius: 30px;
    background: radial-gradient(circle, rgba(0,217,255,0.10), transparent 65%);
}

.hero-title { font-size: 60px; font-weight: 800; line-height: 1.1; color: white;
    text-shadow: 0 0 25px rgba(0,217,255,0.35); }
.hero-highlight { color: #00d9ff; text-shadow: 0 0 20px #00d9ff, 0 0 50px rgba(0,217,255,0.8); }
.hero-subtitle { color: #8fe9ff; font-size: 22px; font-weight: 500; margin-top: 16px; }
.hero-description { max-width: 850px; margin: 20px auto; color: #d8d8d8; font-size: 16px; line-height: 1.8; }

.section-title { text-align: center; font-size: 38px; font-weight: 700; color: #00d9ff;
    margin-top: 60px; margin-bottom: 16px; text-shadow: 0 0 20px rgba(0,217,255,0.4); }
.section-description { text-align: center; max-width: 850px; margin: auto; color: #d5d5d5; line-height: 1.8; }

.feature-card { padding: 26px; border-radius: 22px; background: rgba(255,255,255,0.05);
    backdrop-filter: blur(15px); border: 1px solid rgba(255,255,255,0.08); min-height: 220px; transition: 0.3s; }
.feature-card:hover { transform: translateY(-6px); border: 1px solid rgba(0,217,255,0.6);
    box-shadow: 0 0 35px rgba(0,217,255,0.2); }
.feature-title { color: #00d9ff; font-size: 19px; font-weight: 600; margin-bottom: 10px; }
.feature-tag { display: inline-block; font-size: 11px; font-weight: 700; letter-spacing: 0.5px;
    color: #02111d; background: linear-gradient(90deg, #00d9ff, #00ffb3); padding: 3px 10px;
    border-radius: 20px; margin-bottom: 10px; }
.feature-text { color: #d8d8d8; line-height: 1.7; font-size: 14px; }

.stat-card { text-align: center; padding: 26px; border-radius: 20px; background: rgba(255,255,255,0.05);
    border: 1px solid rgba(255,255,255,0.08); transition: 0.3s; }
.stat-card:hover { transform: translateY(-6px); box-shadow: 0 0 35px rgba(0,217,255,0.25); }
.stat-number { font-size: 40px; font-weight: 700; color: #00d9ff; }
.stat-text { color: #cccccc; }

.verdict-legit .stat-number { color: #00ffb3; }
.verdict-suspicious .stat-number { color: #ffd166; }
.verdict-malicious .stat-number { color: #ff6b7f; }

.workflow-step { text-align: center; padding: 18px; border-radius: 50px; background: rgba(255,255,255,0.05);
    border: 1px solid rgba(0,217,255,0.15); color: white; margin: 8px; }

.project-image { border-radius: 25px; box-shadow: 0 0 35px rgba(0,217,255,0.25); margin-top: 20px; }

.footer { text-align: center; padding: 40px; margin-top: 60px; color: #888;
    border-top: 1px solid rgba(255,255,255,0.08); }

.metric-pill { display:inline-block; padding: 6px 16px; border-radius: 30px; font-size: 13px;
    font-weight: 700; margin: 4px; }
.pill-good { background: rgba(0,255,179,0.12); color: #00ffb3; border: 1px solid rgba(0,255,179,0.4); }
.pill-warn { background: rgba(255,209,102,0.12); color: #ffd166; border: 1px solid rgba(255,209,102,0.4); }
.pill-bad { background: rgba(255,107,127,0.12); color: #ff6b7f; border: 1px solid rgba(255,107,127,0.4); }

.stButton > button { border-radius: 50px; padding: 12px 28px;
    background: linear-gradient(90deg, #00d9ff, #00ffb3); color: #02111d; font-weight: 700; border: none;
    transition: 0.3s; }
.stButton > button:hover { transform: scale(1.05); box-shadow: 0 0 30px rgba(0,217,255,0.6); }

[data-testid="stDataFrame"] { border-radius: 15px; overflow: hidden; }

.intro-wrap { min-height: 560px; border-radius: 30px;
    background: radial-gradient(circle at 50% 30%, rgba(0,217,255,0.10), transparent 65%), #020611;
    border: 1px solid rgba(0,217,255,0.15); box-shadow: 0 0 40px rgba(0,217,255,0.12);
    position: relative; overflow: hidden; padding: 40px 20px 44px;
    display: flex; align-items: center; justify-content: center; flex-direction: column; text-align: center; }

.letter-title { font-size: 46px; font-weight: 800; color: #eafcff; letter-spacing: 2px;
    text-shadow: 0 0 25px rgba(0,217,255,0.45); }
.intro-sub { margin-top: 16px; color: #7fe9ff; font-size: 15px; letter-spacing: 4px; text-transform: uppercase; }

.checklist { width: 100%; max-width: 480px; display: flex; flex-direction: column; gap: 10px; margin-top: 20px; }
.check-item { display: flex; align-items: center; justify-content: space-between; padding: 10px 18px;
    border-radius: 12px; background: rgba(255,255,255,0.04); border: 1px solid rgba(255,255,255,0.08); }
.check-item span.mod-name { color: #d8d8d8; font-size: 14px; }
.check-item span.mod-status { color: #00ffb3; font-weight: 700; font-size: 12px; letter-spacing: 1px; }

.infographic-stats { display: flex; flex-wrap: wrap; justify-content: center; gap: 18px; margin-top: 34px; }
.info-stat { background: rgba(255,255,255,0.04); border: 1px solid rgba(0,217,255,0.18); border-radius: 18px;
    padding: 18px 28px; min-width: 140px; text-align: center; }
.info-stat-num { font-size: 34px; font-weight: 800; color: #00d9ff; text-shadow: 0 0 16px rgba(0,217,255,0.4); }
.info-stat-label { color: #b9c2cc; font-size: 12px; letter-spacing: 0.5px; text-transform: uppercase; margin-top: 4px; }

.pipeline-flow { display: flex; flex-wrap: wrap; align-items: center; justify-content: center;
    gap: 6px; margin-top: 40px; max-width: 900px; }
.pipeline-node { display: flex; flex-direction: column; align-items: center; justify-content: center;
    background: rgba(255,255,255,0.04); border: 1px solid rgba(0,217,255,0.25); border-radius: 16px;
    padding: 16px 14px; width: 128px; min-height: 92px; transition: 0.3s; }
.pipeline-node:hover { border: 1px solid rgba(0,217,255,0.7); box-shadow: 0 0 24px rgba(0,217,255,0.25);
    transform: translateY(-4px); }
.pipeline-icon { font-size: 26px; margin-bottom: 6px; }
.pipeline-label { color: #d8d8d8; font-size: 11.5px; line-height: 1.35; text-align: center; }
.pipeline-arrow { color: #00d9ff; font-size: 20px; opacity: 0.6; }

.priority-card { padding: 18px 22px; border-radius: 16px; background: rgba(255,255,255,0.04);
    border: 1px solid rgba(255,107,127,0.25); margin-bottom: 12px; }
.priority-card.rank-suspicious { border: 1px solid rgba(255,209,102,0.3); }
.priority-rank-badge { display:inline-flex; align-items:center; justify-content:center; width: 30px; height: 30px;
    border-radius: 50%; background: rgba(255,107,127,0.15); color:#ff6b7f; font-weight:800; font-size: 13px;
    margin-right: 10px; }
.priority-card.rank-suspicious .priority-rank-badge { background: rgba(255,209,102,0.15); color:#ffd166; }
.priority-title { font-weight: 700; color: #eafcff; font-size: 15px; }
.priority-meta { color: #8fa3ad; font-size: 12px; margin-top: 2px; }
.priority-reasons { margin-top: 10px; color: #d8d8d8; font-size: 13.5px; line-height: 1.7; }
.priority-reasons li { margin-bottom: 4px; }

</style>
"""), unsafe_allow_html=True)


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
# INTRO SEQUENCE — infographic-style landing page
# (real numbers, pulled from the pipeline run above — not placeholders)
# ============================================================

if not st.session_state.entered:

    threats_flagged = int((data["verdict"] != "Legitimate").sum())

    st.markdown(textwrap.dedent(f"""
    <div class="intro-wrap">
        <div class="letter-title">DeepSpace Cyber Security Shield</div>
        <div class="intro-sub">Autonomous Cyber Defense &nbsp;•&nbsp; Beyond Earth</div>

        <div class="infographic-stats">
            <div class="info-stat">
                <div class="info-stat-num">{len(data)}</div>
                <div class="info-stat-label">Bundles Monitored</div>
            </div>
            <div class="info-stat">
                <div class="info-stat-num" style="color:#ff6b7f;">{threats_flagged}</div>
                <div class="info-stat-label">Threats Flagged</div>
            </div>
            <div class="info-stat">
                <div class="info-stat-num">{metrics['accuracy']}%</div>
                <div class="info-stat-label">Detection Accuracy</div>
            </div>
            <div class="info-stat">
                <div class="info-stat-num">5</div>
                <div class="info-stat-label">Defense Layers Online</div>
            </div>
        </div>

        <div class="pipeline-flow">
            <div class="pipeline-node">
                <div class="pipeline-icon">📡</div>
                <div class="pipeline-label">Telemetry<br>Acquisition</div>
            </div>
            <div class="pipeline-arrow">→</div>
            <div class="pipeline-node">
                <div class="pipeline-icon">🧠</div>
                <div class="pipeline-label">AI Behavioral<br>Engine</div>
            </div>
            <div class="pipeline-arrow">→</div>
            <div class="pipeline-node">
                <div class="pipeline-icon">⏳</div>
                <div class="pipeline-label">TTL-Evidence<br>Trust Score</div>
            </div>
            <div class="pipeline-arrow">→</div>
            <div class="pipeline-node">
                <div class="pipeline-icon">🛰️</div>
                <div class="pipeline-label">DSSLV Lineage<br>Check</div>
            </div>
            <div class="pipeline-arrow">→</div>
            <div class="pipeline-node">
                <div class="pipeline-icon">🛡️</div>
                <div class="pipeline-label">Dynamic TTL<br>Decay</div>
            </div>
        </div>
    </div>
    """), unsafe_allow_html=True)

    st.write("")
    b1, b2, b3 = st.columns([3, 2, 3])
    with b2:
        if st.button("🚀 Enter Mission Dashboard", use_container_width=True):
            st.session_state.entered = True
            st.rerun()

    st.stop()


# ============================================================
# HERO SECTION
# ============================================================

st.markdown(textwrap.dedent("""
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
"""), unsafe_allow_html=True)

image_col1, image_col2, image_col3 = st.columns([1, 2, 1])
with image_col1:
    if os.path.exists(SATELLITE_PATH):
        st.image(SATELLITE_PATH, width=180)
with image_col2:
    if os.path.exists(DEFENSE_PATH):
        st.image(DEFENSE_PATH, use_container_width=True)
with image_col3:
    if os.path.exists(EARTH_PATH):
        st.image(EARTH_PATH, width=180)


# ============================================================
# MISSION
# ============================================================

st.markdown(textwrap.dedent("""
<div class="section-title">Defending Communication Across the Void</div>
<div class="section-description">
    DeepSpace CyberShield AI is designed to protect communication infrastructure
    operating across extreme distances where traditional cybersecurity approaches
    may not be sufficient. Our AI-driven system analyzes mission communication
    patterns and identifies suspicious anomalies before they become critical threats.
</div>
"""), unsafe_allow_html=True)

if os.path.exists(AI_NETWORK_PATH):
    st.image(AI_NETWORK_PATH, caption="AI-Powered Deep Space Communication Monitoring", use_container_width=True)


# ============================================================
# FEATURES
# ============================================================

st.markdown(textwrap.dedent("""
<div class="section-title">Core Cyber Defense Features</div>
<div class="section-description">
    Every module below is a live pipeline stage - not a static description - and
    corresponds to a contribution from our research paper, <i>"AI-Driven Detection of
    Cyber Anomalies in Deep-Space Communication Networks Using Temporal Trust Leakage
    Evidence and Dynamic TTL Decay."</i>
</div>
"""), unsafe_allow_html=True)

f1, f2 = st.columns(2)
with f1:
    st.markdown(textwrap.dedent("""
    <div class="feature-card">
        <div class="feature-tag">AI Behavioral Engine</div>
        <div class="feature-title">🤖 Autoencoder &amp; Isolation Forest Anomaly Scoring</div>
        <div class="feature-text">
            Lightweight models profile normal communication behaviour from telemetry, timing,
            propagation delay, RSS, packet size and relay sequence data - producing an initial
            anomaly confidence score for every incoming bundle, without needing labelled attack data.
        </div>
    </div>
    """), unsafe_allow_html=True)
with f2:
    st.markdown(textwrap.dedent("""
    <div class="feature-card">
        <div class="feature-tag">Core Contribution</div>
        <div class="feature-title">⏳ Temporal Trust Leakage Evidence (TTL-Evidence)</div>
        <div class="feature-text">
            Instead of judging packets in isolation, TTL-Evidence tracks transmission timing
            consistency, latency, communication rhythm and historical similarity over time.
            Even a near-perfect spoof accumulates small behavioural discrepancies that erode
            its trust score - exposing advanced spoofing and replay attacks that packet-level
            inspection misses.
        </div>
    </div>
    """), unsafe_allow_html=True)

f3, f4 = st.columns(2)
with f3:
    st.markdown(textwrap.dedent("""
    <div class="feature-card">
        <div class="feature-tag">Core Contribution</div>
        <div class="feature-title">🛰️ Deep-Space Signal Lineage Verification (DSSLV)</div>
        <div class="feature-text">
            Verifies the entire route a bundle took - ground station, orbiter, relay satellite,
            receiver - against its expected path. An improbable route or impossible relay
            transition is flagged as suspicious, catching forged routing and injected relay
            nodes even when the signal signature looks legitimate.
        </div>
    </div>
    """), unsafe_allow_html=True)
with f4:
    st.markdown(textwrap.dedent("""
    <div class="feature-card">
        <div class="feature-tag">Core Contribution</div>
        <div class="feature-title">🛡️ Passive Autonomous Eviction — Dynamic TTL Decay</div>
        <div class="feature-text">
            Rather than actively deleting malicious packets, suspicious bundles simply have
            their Bundle Protocol TTL decayed toward zero - letting the native DTN garbage
            collector expire them automatically, with near-zero extra CPU or memory overhead.
        </div>
    </div>
    """), unsafe_allow_html=True)

if os.path.exists(ANOMALY_PATH):
    st.image(ANOMALY_PATH, caption="AI Anomaly Detection System", use_container_width=True)


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
# (this is the real pipeline output, computed above via
#  load_and_analyze() — not a static "status" column)
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


# ============================================================
# FAKE SIGNAL PRIORITY RANKING
# Every non-Legitimate bundle, ranked by how urgently it needs review,
# with a plain-English explanation built from its own component scores
# (not from the simulated ground-truth label — this is what an operator
# would actually see: the evidence, not the answer key).
# ============================================================

st.markdown('<div class="section-title">Fake Signal Priority Ranking</div>', unsafe_allow_html=True)
st.markdown(
    '<div class="section-description">Every bundle the framework did not clear, ordered by risk. '
    'Each entry shows exactly which signal(s) triggered it — the same evidence a mission operator '
    'would use to decide what to investigate first.</div>',
    unsafe_allow_html=True,
)
st.write("")

top_n = st.slider("Show top N highest-priority signals", min_value=5, max_value=50, value=15, step=5)
ranked = report_generator.rank_fake_signals(data, top_n=top_n)

if ranked.empty:
    st.success("No suspicious or malicious bundles in the current dataset.")
else:
    for _, row in ranked.iterrows():
        card_class = "priority-card" if row["verdict"] == "Malicious (TTL Decayed)" else "priority-card rank-suspicious"
        reasons_html = "".join(f"<li>{r}</li>" for r in row["reasons"])
        verdict_label = "🔴 MALICIOUS — TTL Decayed" if row["verdict"] == "Malicious (TTL Decayed)" else "🟡 SUSPICIOUS"

        st.markdown(textwrap.dedent(f"""
        <div class="{card_class}">
            <span class="priority-rank-badge">#{row['priority_rank']}</span>
            <span class="priority-title">Bundle {row['bundle_id']} — {row['source']} &nbsp;·&nbsp; {verdict_label}</span>
            <div class="priority-meta">
                Priority score {row['priority_score']:.2f} &nbsp;|&nbsp;
                Trust {row['trust_score']:.2f} &nbsp;|&nbsp;
                Lineage {row['lineage_score']:.2f} &nbsp;|&nbsp;
                TTL {row['ttl_original']}s → {row['ttl_new']}s &nbsp;|&nbsp;
                <span style="opacity:0.6;">simulated attack (ground truth, for reference): {row['status']}</span>
            </div>
            <ul class="priority-reasons">{reasons_html}</ul>
        </div>
        """), unsafe_allow_html=True)

    ranking_csv = ranked.drop(columns=["reasons"]).to_csv(index=False).encode("utf-8")
    st.download_button(
        label="📥 Download Priority Ranking (CSV)",
        data=ranking_csv,
        file_name="deepspace_cybershield_priority_ranking.csv",
        mime="text/csv",
    )


# ============================================================
# DATASET / BUNDLE EXPLORER
# ============================================================

st.markdown(textwrap.dedent("""
<div class="section-title">Mission Communication Dashboard</div>
<div class="section-description">
    Explore every communication bundle along with its computed anomaly confidence,
    trust score, lineage score, and final Dynamic-TTL-Decay verdict.
</div>
"""), unsafe_allow_html=True)

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

st.markdown(textwrap.dedent("""
<div class="footer">
    <h3 style="color:#00d9ff;">DeepSpace CyberShield AI</h3>
    <p>Autonomous AI-powered cybersecurity for the future of interplanetary communication.</p>
    <p>© 2026 DeepSpace CyberShield AI</p>
</div>
"""), unsafe_allow_html=True)

if st.button("🔁 Replay Intro"):
    st.session_state.entered = False
    st.rerun()
