import json
import time
import textwrap
from pathlib import Path

import pandas as pd
import streamlit as st


# ============================================================
# PAGE CONFIG
# ============================================================

st.set_page_config(
    page_title="Vulnerability Triage",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

BASE = Path(__file__).parent


def md(content, **kwargs):
    """Render indented HTML/Markdown safely by removing common indentation."""
    return st.markdown(textwrap.dedent(content), **kwargs)


def md_to(container, content, **kwargs):
    """Render indented HTML/Markdown into a Streamlit placeholder/container."""
    return container.markdown(textwrap.dedent(content), **kwargs)


# ============================================================
# DATA LOADING
# ============================================================

def first_existing(*names):
    for name in names:
        p = BASE / name
        if p.exists():
            return p
    return None


CSV_FILE = first_existing(
    "vulnerabilities (1).csv",
    "vulnerabilities.csv"
)

PROFILE_FILE = first_existing("profile.json")
PROFILES_FILE = first_existing("profiles.json")


@st.cache_data
def load_vulnerabilities():

    if CSV_FILE is None:
        return pd.DataFrame(
            columns=[
                "cve_id",
                "product_name",
                "cvss_base_score",
                "cisa_kev",
                "first_epss"
            ]
        )

    df = pd.read_csv(CSV_FILE, low_memory=False)

    required = [
        "cve_id",
        "product_name",
        "cvss_base_score",
        "cisa_kev",
        "first_epss"
    ]

    missing = [c for c in required if c not in df.columns]

    if missing:
        st.error("CSV is missing: " + ", ".join(missing))
        st.stop()

    df["cve_id"] = df["cve_id"].fillna("").astype(str)

    df["product_name"] = (
        df["product_name"]
        .fillna("")
        .astype(str)
    )

    df["cvss_base_score"] = (
        pd.to_numeric(
            df["cvss_base_score"],
            errors="coerce"
        )
        .fillna(0.0)
    )

    df["first_epss"] = (
        pd.to_numeric(
            df["first_epss"],
            errors="coerce"
        )
        .fillna(0.0)
    )

    df["cisa_kev"] = (
        df["cisa_kev"]
        .astype(str)
        .str.strip()
        .str.lower()
        .isin(["true", "1", "yes", "y"])
    )

    return df


@st.cache_data
def load_profiles():

    profiles = []

    # --------------------------------------------------------
    # profile.json
    # --------------------------------------------------------

    if PROFILE_FILE:

        raw = json.loads(
            PROFILE_FILE.read_text(
                encoding="utf-8"
            )
        )

        if isinstance(raw, list):

            for p in raw:

                profiles.append({

                    "key":
                        "detail::"
                        + str(
                            p.get(
                                "profile_id",
                                p.get(
                                    "name",
                                    "profile"
                                )
                            )
                        ),

                    "name":
                        p.get(
                            "name",
                            "Unnamed organisation"
                        ),

                    "sector":
                        p.get(
                            "sector",
                            "Unknown"
                        ),

                    "risk_appetite":
                        "Not supplied",

                    "technologies":
                        p.get(
                            "technologies",
                            []
                        ),

                    "critical_products":
                        [],

                    "weights": {

                        "cvss_weight": 0.35,

                        "cisa_kev_weight": 0.40,

                        "first_epss_weight": 0.25

                    },

                    "source":
                        "profile.json"

                })

    # --------------------------------------------------------
    # profiles.json
    # --------------------------------------------------------

    if PROFILES_FILE:

        raw = json.loads(
            PROFILES_FILE.read_text(
                encoding="utf-8"
            )
        )

        for p in raw.get(
            "organizations",
            []
        ):

            profiles.append({

                "key":
                    "org::"
                    + str(
                        p.get(
                            "org_id",
                            p.get(
                                "name",
                                "org"
                            )
                        )
                    ),

                "name":
                    p.get(
                        "name",
                        "Unnamed organisation"
                    ),

                "sector":
                    p.get(
                        "sector",
                        "Unknown"
                    ),

                "risk_appetite":
                    p.get(
                        "risk_appetite",
                        "Unknown"
                    ),

                "technologies":
                    [],

                "critical_products":
                    p.get(
                        "critical_products",
                        []
                    ),

                "weights":
                    p.get(
                        "weight_modifiers",
                        {

                            "cvss_weight": 0.35,

                            "cisa_kev_weight": 0.40,

                            "first_epss_weight": 0.25

                        }
                    ),

                "source":
                    "profiles.json"

            })

    return profiles


vulnerabilities = load_vulnerabilities()
profiles = load_profiles()


if not profiles:

    st.error(
        "No organisation profile was found. "
        "Put profile.json or profiles.json beside app.py."
    )

    st.stop()


# ============================================================
# HELPERS
# ============================================================

def norm(x):

    return (
        str(x or "")
        .lower()
        .strip()
        .replace("_", " ")
        .replace("/", " ")
        .replace("-", " ")
    )


def escape(v):

    return (
        str(v)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
    )


# ============================================================
# ORGANISATION ASSETS
# ============================================================

def assets_for(profile):

    assets = []

    # --------------------------------------------------------
    # Technology profiles
    # --------------------------------------------------------

    for t in profile.get(
        "technologies",
        []
    ):

        vendor = norm(
            t.get("vendor")
        )

        product = norm(
            t.get("product")
        )

        assets.append({

            "display":
                f"{t.get('vendor', '')}/"
                f"{t.get('product', '')}",

            "match": {

                vendor,

                product,

                f"{vendor} {product}".strip()

            },

            "version":
                t.get(
                    "version",
                    "Not supplied"
                ),

            "service":
                t.get(
                    "service",
                    "Not supplied"
                ),

            "exposure":
                t.get(
                    "exposure",
                    "Not supplied"
                ),

            "importance":
                t.get(
                    "importance",
                    "Not supplied"
                )

        })

    # --------------------------------------------------------
    # Critical products
    # --------------------------------------------------------

    for p in profile.get(
        "critical_products",
        []
    ):

        assets.append({

            "display": p,

            "match": {
                norm(p)
            },

            "version":
                "Not supplied",

            "service":
                "Critical product",

            "exposure":
                "Not supplied",

            "importance":
                "critical"

        })

    return assets


# ============================================================
# ASSET MATCHING
# ============================================================

def match_asset(
    product,
    assets
):

    p = norm(product)

    for a in assets:

        for m in a["match"]:

            if not m:
                continue

            # Exact match
            if p == m:
                return a

            # Partial match
            if (
                len(m) >= 5
                and (
                    m in p
                    or p in m
                )
            ):
                return a

    return None


# ============================================================
# SCORING ENGINE
# ============================================================

def score_row(
    row,
    profile,
    asset
):

    w = profile.get(
        "weights",
        {}
    )

    cw = float(
        w.get(
            "cvss_weight",
            0.35
        )
    )

    kw = float(
        w.get(
            "cisa_kev_weight",
            0.40
        )
    )

    ew = float(
        w.get(
            "first_epss_weight",
            0.25
        )
    )

    # --------------------------------------------------------
    # Base values
    # --------------------------------------------------------

    cvss = max(
        0.0,
        min(
            float(
                row.cvss_base_score
            ),
            10.0
        )
    )

    epss = max(
        0.0,
        min(
            float(
                row.first_epss
            ),
            1.0
        )
    )

    kev = bool(
        row.cisa_kev
    )

    # --------------------------------------------------------
    # Score components
    # --------------------------------------------------------

    cvss_part = (
        (cvss / 10)
        * 100
        * cw
    )

    kev_part = (
        100 * kw
        if kev
        else 0
    )

    epss_part = (
        epss
        * 100
        * ew
    )

    # --------------------------------------------------------
    # Organisation context
    # IMPORTANT:
    # Unmatched vulnerabilities get Context = 0
    # --------------------------------------------------------

    context = 0

    if asset:

        imp = norm(
            asset.get(
                "importance"
            )
        )

        exp = norm(
            asset.get(
                "exposure"
            )
        )

        context += {

            "critical": 10,

            "high": 6,

            "normal": 2

        }.get(
            imp,
            0
        )

        if exp == "internet facing":

            context += 8

    # --------------------------------------------------------
    # Total
    # --------------------------------------------------------

    total = min(

        100,

        cvss_part
        + kev_part
        + epss_part
        + context

    )

    return {

        "score":
            round(
                total,
                1
            ),

        "cvss":
            round(
                cvss_part,
                1
            ),

        "kev":
            round(
                kev_part,
                1
            ),

        "epss":
            round(
                epss_part,
                1
            ),

        "context":
            round(
                context,
                1
            )

    }


# ============================================================
# PRIORITY
# ============================================================

def priority(score):

    if score >= 75:

        return (
            "URGENT",
            "urgent"
        )

    if score >= 55:

        return (
            "HIGH",
            "high"
        )

    if score >= 35:

        return (
            "MEDIUM",
            "medium"
        )

    return (
        "LOW",
        "low"
    )


# ============================================================
# TRIAGE ENGINE
#
# IMPORTANT FIX:
# ALL VULNERABILITIES ARE INCLUDED.
#
# MATCHED:
# Gets organisation context.
#
# UNMATCHED:
# Still ranked.
# Context = 0.
# ============================================================

def triage(profile):

    assets = assets_for(
        profile
    )

    out = []

    for row in vulnerabilities.itertuples(
        index=False
    ):

        # Try to find organisation match

        asset = match_asset(
            row.product_name,
            assets
        )

        # DO NOT SKIP IF asset IS NONE

        parts = score_row(
            row,
            profile,
            asset
        )

        label, cls = priority(
            parts["score"]
        )

        out.append({

            "cve":
                row.cve_id,

            "product":
                row.product_name,

            "cvss":
                float(
                    row.cvss_base_score
                ),

            "epss":
                float(
                    row.first_epss
                ),

            "kev":
                bool(
                    row.cisa_kev
                ),

            "asset":
                asset,

            "profile_match":
                asset is not None,

            "parts":
                parts,

            "score":
                parts["score"],

            "label":
                label,

            "class":
                cls,

            "confidence":

                (
                    "HIGH"

                    if (
                        asset
                        and asset.get(
                            "version"
                        )
                        not in [
                            None,
                            "",
                            "Not supplied"
                        ]
                    )

                    else "MEDIUM"
                )

        })

    # --------------------------------------------------------
    # Remove duplicates
    # --------------------------------------------------------

    unique = {}

    for r in out:

        key = (
            r["cve"],
            r["product"]
        )

        if key not in unique:

            unique[key] = r

        elif (
            r["score"]
            > unique[key]["score"]
        ):

            unique[key] = r

    results = list(
        unique.values()
    )

    # --------------------------------------------------------
    # Rank all vulnerabilities
    # --------------------------------------------------------

    return sorted(

        results,

        key=lambda r: (

            r["score"],

            r["kev"],

            r["cvss"],

            r["epss"]

        ),

        reverse=True

    )


# ============================================================
# CSS
# ============================================================

md(
    """
<style>

/* -------------------------------------------------------- */
/* GLOBAL */
/* -------------------------------------------------------- */

.stApp{
    background:#060a11;
    color:#e7edf5;
}

.main .block-container{
    max-width:1500px;
    padding-top:1.2rem;
    padding-bottom:4rem;
}

section[data-testid="stSidebar"]{
    background:#080d15;
    border-right:1px solid #182335;
}


/* -------------------------------------------------------- */
/* TOP BAR */
/* -------------------------------------------------------- */

.topbar{
    height:78px;
    border:1px solid #1b344d;
    border-radius:18px;
    display:flex;
    align-items:center;
    justify-content:space-between;
    margin-bottom:28px;
    padding:0 24px;
    background:#09121e;
}

.brand{
    display:flex;
    gap:12px;
    align-items:center;
}

.logo{
    width:42px;
    height:42px;
    border:1px solid #169ee8;
    border-radius:12px;
    display:grid;
    place-items:center;
    color:#31b6ff;
    font-weight:900;
}

.muted{
    color:#71839b;
    font-size:11px;
}


/* -------------------------------------------------------- */
/* INTRO */
/* -------------------------------------------------------- */

.intro-screen{
    min-height:80vh;
    display:flex;
    flex-direction:column;
    justify-content:center;
    align-items:center;
    text-align:center;
    position:relative;
    overflow:hidden;
}

.intro-screen:before{
    content:"";
    position:absolute;
    inset:0;

    background:
        radial-gradient(
            circle at 50% 45%,
            rgba(0,174,255,.14),
            transparent 30%
        ),
        linear-gradient(
            145deg,
            #05080e,
            #080d15
        );

    z-index:-2;
}

.intro-grid{
    position:absolute;
    inset:0;

    background-image:
        linear-gradient(
            rgba(41,116,163,.08) 1px,
            transparent 1px
        ),
        linear-gradient(
            90deg,
            rgba(41,116,163,.08) 1px,
            transparent 1px
        );

    background-size:50px 50px;

    mask-image:
        linear-gradient(
            to bottom,
            black,
            transparent
        );

    z-index:-1;
}

.intro-title{
    font-family:monospace;
    font-size:clamp(32px,6vw,78px);
    font-weight:900;
    letter-spacing:5px;
    color:#f7fbff;

    text-shadow:
        0 0 20px rgba(32,170,242,.4),
        0 0 50px rgba(32,170,242,.15);
}

.intro-sub{
    margin-top:28px;
    color:#31b6ff;
    font:800 13px monospace;
    letter-spacing:3px;
}

.intro-status{
    margin-top:30px;
    color:#71839b;
    font:12px monospace;
    letter-spacing:1px;
}


/* -------------------------------------------------------- */
/* LANDING */
/* -------------------------------------------------------- */

.hero{
    position:relative;
    overflow:hidden;
    border:1px solid #1d3852;
    border-radius:26px;
    padding:58px 34px 34px;

    background:
        radial-gradient(
            circle at 50% 35%,
            rgba(0,174,255,.12),
            transparent 30%
        ),
        linear-gradient(
            145deg,
            #091221,
            #060b12
        );

    text-align:center;
}

.grid{
    position:absolute;
    inset:0;

    background-image:
        linear-gradient(
            rgba(41,116,163,.08) 1px,
            transparent 1px
        ),
        linear-gradient(
            90deg,
            rgba(41,116,163,.08) 1px,
            transparent 1px
        );

    background-size:42px 42px;

    mask-image:
        linear-gradient(
            to bottom,
            black,
            transparent
        );
}

.kicker{
    position:relative;
    color:#31b6ff;
    font:800 12px monospace;
    letter-spacing:2px;
}

.hero h1{
    position:relative;
    font-size:56px;
    line-height:1.0;
    margin:16px 0;
    color:#f7fbff;
}

.hero h1 span{
    color:#20aaf2;

    text-shadow:
        0 0 30px
        rgba(32,170,242,.35);
}

.hero p{
    position:relative;
    max-width:800px;
    margin:0 auto;

    color:#91a6bd;

    font-size:15px;

    line-height:1.7;
}

.machine{
    position:relative;

    max-width:760px;

    height:250px;

    margin:38px auto 18px;

    border:1px solid #214665;

    border-radius:28px;

    background:
        rgba(5,13,23,.75);

    box-shadow:
        0 0 50px
        rgba(0,159,255,.09);
}

.core{

    position:absolute;

    left:50%;
    top:50%;

    transform:
        translate(-50%,-50%);

    width:150px;
    height:150px;

    border-radius:50%;

    border:
        1px solid #1cb0ff;

    display:grid;

    place-items:center;

    color:#65d0ff;

    font:
        800 15px monospace;

    box-shadow:
        0 0 45px
        rgba(0,174,255,.2);
}

.node{

    position:absolute;

    padding:9px 14px;

    border:
        1px solid #254966;

    border-radius:10px;

    background:#0a1523;

    color:#8ca5bf;

    font:
        800 10px monospace;
}

.n1{
    left:5%;
    top:18%;
}

.n2{
    left:5%;
    bottom:18%;
}

.n3{
    right:5%;
    top:18%;
}

.n4{
    right:5%;
    bottom:18%;
}

.steps{

    color:#627a96;

    font:
        800 10px monospace;

    letter-spacing:1px;
}


/* -------------------------------------------------------- */
/* SETUP */
/* -------------------------------------------------------- */

.setup,
.analysis{

    max-width:1050px;

    margin:0 auto;

    border:
        1px solid #20364d;

    border-radius:24px;

    padding:30px;

    background:#09111c;
}

.eyebrow{

    color:#31b6ff;

    font:
        800 11px monospace;

    letter-spacing:1.5px;
}

.setup h2{
    font-size:34px;
    margin:10px 0;
}

.sub{

    color:#7890a9;

    font-size:13px;

    line-height:1.7;
}

.asset{

    border:
        1px solid #1e344b;

    border-radius:16px;

    background:#0a1421;

    padding:17px;

    height:100%;
}

.asset b{
    font-size:15px;
}

.tag{

    display:inline-block;

    margin-top:12px;

    padding:5px 9px;

    border-radius:999px;

    background:#0d2234;

    border:
        1px solid #164b70;

    color:#43bfff;

    font:
        700 10px monospace;
}


/* -------------------------------------------------------- */
/* ANALYSIS */
/* -------------------------------------------------------- */

.analysis-core{

    text-align:center;

    padding:50px 20px;
}

.progress-circle{

    width:230px;

    height:230px;

    border-radius:50%;

    margin:30px auto;

    border:
        2px solid #1db2ff;

    display:flex;

    align-items:center;

    justify-content:center;

    box-shadow:
        0 0 55px
        rgba(29,178,255,.25);
}

.progress-number{

    color:#65d0ff;

    font:
        900 48px monospace;
}

.analysis-step{

    color:#35df88;

    font:
        11px monospace;

    margin:7px;
}


/* -------------------------------------------------------- */
/* DASHBOARD */
/* -------------------------------------------------------- */

.profile{

    border:
        1px solid #1b3046;

    border-radius:18px;

    background:#09111c;

    padding:20px;
}

.profile-title{

    font-size:23px;

    font-weight:800;
}

.metric{

    border:
        1px solid #1b3046;

    border-radius:15px;

    background:#09111c;

    padding:17px;

    min-height:130px;
}

.metric small{

    color:#637890;

    font:
        800 10px monospace;

    letter-spacing:1px;
}

.metric strong{

    display:block;

    font-size:30px;

    margin-top:7px;
}

.metric span{

    color:#637890;

    font-size:11px;
}

.section-title{

    font-size:28px;

    font-weight:900;

    margin-top:38px;
}

.section-sub{

    color:#687e96;

    font-size:12px;

    margin:7px 0 18px;
}


/* -------------------------------------------------------- */
/* VULNERABILITY CARDS */
/* -------------------------------------------------------- */

.vcard{

    border:
        1px solid #1d3349;

    border-radius:18px;

    background:#0a111b;

    margin:16px 0;

    padding:24px;
}

.vcard.urgent{

    border-color:#ef4444;

    background:
        linear-gradient(
            90deg,
            rgba(127,15,15,.42),
            #0a111b 65%
        );
}

.vcard.high{
    border-color:#f97316;
}

.vcard.medium{
    border-color:#d9a500;
}

.vcard.low{
    border-color:#248d63;
}

.row{

    display:flex;

    justify-content:space-between;

    gap:20px;
}

.rank{

    color:#7fcfff;

    font:
        900 16px monospace;

    letter-spacing:1px;
}

.badge{

    display:inline-block;

    padding:7px 12px;

    border-radius:7px;

    font:
        900 11px monospace;

    letter-spacing:.8px;
}

.badge.urgent{

    color:#ff7777;

    border:
        1px solid #d63838;

    background:#3a1014;
}

.badge.high{

    color:#ffb15c;

    border:
        1px solid #a85a14;

    background:#351b0b;
}

.badge.medium{

    color:#f4d35e;

    border:
        1px solid #92740a;

    background:#332b08;
}

.badge.low{

    color:#66e5a8;

    border:
        1px solid #278b61;

    background:#0b2f21;
}

.cve{

    color:#2db8ff;

    font:
        800 19px monospace;

    margin-top:10px;
}

.title{

    font-size:26px;

    font-weight:850;

    margin-top:9px;

    color:#f6f9fc;
}

.meta{

    color:#8095aa;

    font:
        12px monospace;

    margin-top:10px;
}

.score{

    font-size:38px;

    font-weight:900;

    text-align:right;
}

.score small{

    display:block;

    color:#52677e;

    font:
        9px monospace;
}

.signalbar{

    display:flex;

    gap:8px;

    flex-wrap:wrap;

    margin:20px 0;
}

.sig{

    padding:8px 11px;

    border-radius:7px;

    background:#0d1825;

    border:
        1px solid #20384f;

    color:#9db1c5;

    font:
        11px monospace;
}

.sig.kev{

    color:#ff6670;

    border-color:#71313a;
}

.sig.epss{

    color:#c49cff;

    border-color:#563c7e;
}

.sig.net{

    color:#31b6ff;

    border-color:#185273;
}

.reason{

    border:
        1px solid #1d3349;

    border-radius:12px;

    padding:16px;

    background:#080e16;

    margin-top:12px;

    color:#c5d1dd;

    font-size:13px;

    line-height:1.75;
}

.reason b{

    color:#7a8fa6;

    font:
        800 11px monospace;

    letter-spacing:1px;
}

.action{

    border:
        1px solid #1a6842;

    border-radius:12px;

    padding:15px;

    background:
        rgba(12,78,46,.28);

    margin-top:12px;

    color:#d5ffe7;

    font-size:13px;

    line-height:1.6;
}

.action b{

    display:block;

    color:#31df83;

    font:
        800 10px monospace;

    letter-spacing:1px;

    margin-bottom:5px;
}

.foot{

    color:#536a82;

    text-align:center;

    font:
        10px monospace;

    padding:35px;
}

</style>
""",
    unsafe_allow_html=True
)


# ============================================================
# SESSION STATE
# ============================================================

if "screen" not in st.session_state:
    st.session_state.screen = "intro"

if "org_key" not in st.session_state:
    st.session_state.org_key = profiles[0]["key"]


# ============================================================
# TOP BAR
# ============================================================

def topbar():

    md(
        """
        <div class="topbar">

            <div class="brand">

                <div class="logo">
                    VT
                </div>

                <div>

                    <b>
                        Vulnerability Triage
                    </b>

                    <div class="muted">

                        PERSONALISED THREAT INTELLIGENCE
                        · PUBLIC DATA ONLY
                        · NO PAID FEEDS

                    </div>

                </div>

            </div>

            <div class="muted">

                DEFENSIVE INTELLIGENCE ENGINE

            </div>

        </div>
        """,
        unsafe_allow_html=True
    )


def get_profile(key):

    return next(
        p
        for p in profiles
        if p["key"] == key
    )


# ============================================================
# INTRO SCREEN
# ============================================================

if st.session_state.screen == "intro":

    md(
        """
        <div class="intro-screen">

            <div class="intro-grid"></div>

        </div>
        """,
        unsafe_allow_html=True
    )

    title_box = st.empty()

    name = "VULNERABILITY TRIAGE"

    current = ""

    for letter in name:

        current += letter

        md_to(title_box, 
            f"""
            <div class="intro-screen">

                <div class="intro-grid"></div>

                <div class="intro-title">

                    {current}

                </div>

            </div>
            """,
            unsafe_allow_html=True
        )

        time.sleep(0.08)

    time.sleep(0.7)

    md_to(title_box, 
        """
        <div class="intro-screen">

            <div class="intro-grid"></div>

            <div class="intro-title">
                VULNERABILITY TRIAGE
            </div>

            <div class="intro-sub">
                PERSONALISED THREAT INTELLIGENCE
            </div>

            <div class="intro-status">

                PUBLIC DATA ONLY · NO PAID FEEDS

                <br><br>

                INITIALISING TRIAGE ENGINE...

                <br>

                LOADING VULNERABILITY DATA...

                <br>

                PREPARING THREAT ANALYSIS...

            </div>

        </div>
        """,
        unsafe_allow_html=True
    )

    time.sleep(2.2)

    st.session_state.screen = "landing"

    st.rerun()


# ============================================================
# LANDING / HOMEPAGE
# ============================================================

elif st.session_state.screen == "landing":

    topbar()

    md(
        """
        <div class="hero">

            <div class="grid"></div>

            <div class="kicker">

                PERSONALISED THREAT INTELLIGENCE

            </div>

            <h1>

                Vulnerability

                <br>

                <span>
                    Triage
                </span>

            </h1>

            <p>

                Analyse vulnerability intelligence,
                identify exploitation indicators,
                apply organisation context,
                and rank the threats that deserve
                the most attention.

            </p>

            <div class="machine">

                <div class="node n1">

                    CVSS

                    <br>

                    <span>
                        SEVERITY
                    </span>

                </div>

                <div class="node n2">

                    EPSS

                    <br>

                    <span>
                        LIKELIHOOD
                    </span>

                </div>

                <div class="node n3">

                    CISA KEV

                    <br>

                    <span>
                        EXPLOITATION
                    </span>

                </div>

                <div class="node n4">

                    PROFILE

                    <br>

                    <span>
                        CONTEXT
                    </span>

                </div>

                <div class="core">

                    TRIAGE

                    <br>

                    ENGINE

                </div>

            </div>

            <div class="steps">

                MATCH → SCORE → RANK → EXPLAIN

            </div>

        </div>
        """,
        unsafe_allow_html=True
    )

    st.write("")

    _, c, _ = st.columns(
        [1.3, 1, 1.3]
    )

    with c:

        if st.button(
            "START TRIAGE →",
            type="primary",
            use_container_width=True
        ):

            st.session_state.screen = "setup"

            st.rerun()


# ============================================================
# ORGANISATION SELECTION
# ============================================================

elif st.session_state.screen == "setup":

    topbar()

    p = get_profile(
        st.session_state.org_key
    )

    md(
        """
        <div class="setup">

            <div class="eyebrow">

                STEP 01 / 02
                · ORGANISATION CONTEXT

            </div>

            <h2>

                Who are we protecting?

            </h2>

            <div class="sub">

                Select an organisation or college.
                VulnTriage uses available technology,
                exposure and criticality information
                when ranking vulnerability data.

                <br><br>

                Vulnerabilities without a direct
                technology match are still analysed
                and ranked as general threats.

            </div>

        </div>
        """,
        unsafe_allow_html=True
    )

    names = [
        p["name"]
        for p in profiles
    ]

    selected_name = st.selectbox(
        "Organisation",
        names,
        index=names.index(
            p["name"]
        )
    )

    selected = next(

        x
        for x in profiles
        if x["name"] == selected_name

    )

    st.session_state.org_key = selected["key"]

    assets = assets_for(
        selected
    )

    md(
        '<div class="section-title">'
        'Technology / critical product context'
        '</div>',
        unsafe_allow_html=True
    )

    if assets:

        cols = st.columns(
            min(
                3,
                len(assets)
            )
        )

        for i, a in enumerate(
            assets
        ):

            with cols[
                i % len(cols)
            ]:

                md(
                    f"""
                    <div class="asset">

                        <b>
                            {escape(a["display"])}
                        </b>

                        <div
                            class="muted"
                            style="margin-top:8px"
                        >

                            Version:
                            {escape(a["version"])}

                            <br>

                            Service:
                            {escape(a["service"])}

                            <br>

                            Importance:
                            {escape(a["importance"])}

                        </div>

                        <span class="tag">

                            {escape(a["exposure"])}

                        </span>

                    </div>
                    """,
                    unsafe_allow_html=True
                )

    st.write("")

    a, b = st.columns(
        [1, 3]
    )

    with a:

        if st.button(
            "← BACK",
            use_container_width=True
        ):

            st.session_state.screen = "landing"

            st.rerun()

    with b:

        if st.button(
            "ANALYSE THREATS →",
            type="primary",
            use_container_width=True
        ):

            st.session_state.screen = "analyzing"

            st.rerun()


# ============================================================
# ANALYSIS SCREEN
# ============================================================

elif st.session_state.screen == "analyzing":

    topbar()

    md(
        """
        <div class="analysis">

            <div class="analysis-core">

                <div class="eyebrow">

                    STEP 02 / 02
                    · TRIAGE ENGINE

                </div>

                <h2>

                    ANALYSING THREAT DATA

                </h2>

                <div class="sub">

                    Processing vulnerability intelligence
                    and organisation context.

                </div>

            </div>

        </div>
        """,
        unsafe_allow_html=True
    )

    progress_box = st.empty()

    steps_box = st.empty()

    percentages = [
        0,
        10,
        25,
        40,
        55,
        70,
        85,
        100
    ]

    analysis_steps = [

        "Loading vulnerability data",

        "Validating vulnerability records",

        "Analysing CVSS severity",

        "Analysing EPSS exploit probability",

        "Checking CISA KEV",

        "Analysing organisation context",

        "Analysing exposure",

        "Running negative tests",

        "Calculating risk scores",

        "Ranking vulnerabilities"

    ]

    completed = []

    for i, percent in enumerate(
        percentages
    ):

        md_to(progress_box, 
            f"""
            <div class="progress-circle">

                <div class="progress-number">

                    {percent}%

                </div>

            </div>
            """,
            unsafe_allow_html=True
        )

        if i < len(analysis_steps):

            completed.append(
                analysis_steps[i]
            )

        step_html = ""

        for step in completed:

            step_html += (
                f'<div class="analysis-step">'
                f'✓ {step}'
                f'</div>'
            )

        md_to(steps_box, 
            step_html,
            unsafe_allow_html=True
        )

        time.sleep(0.45)

    for step in analysis_steps[
        len(completed):
    ]:

        completed.append(
            step
        )

        step_html = ""

        for s in completed:

            step_html += (
                f'<div class="analysis-step">'
                f'✓ {s}'
                f'</div>'
            )

        md_to(steps_box, 
            step_html,
            unsafe_allow_html=True
        )

        time.sleep(0.25)

    st.success(
        "ANALYSIS COMPLETE"
    )

    time.sleep(1.2)

    st.session_state.screen = "dashboard"

    st.rerun()


# ============================================================
# DASHBOARD
# ============================================================

else:

    profile = get_profile(
        st.session_state.org_key
    )

    topbar()


    # ========================================================
    # SIDEBAR
    # ========================================================

    with st.sidebar:

        md(
            """
            <div class="brand">

                <div class="logo">
                    VT
                </div>

                <div>

                    <b>
                        Vulnerability Triage
                    </b>

                    <div class="muted">

                        Personalised security intelligence

                    </div>

                </div>

            </div>
            """,
            unsafe_allow_html=True
        )

        st.divider()

        names = [
            p["name"]
            for p in profiles
        ]

        selected_name = st.selectbox(
            "SELECT ORGANISATION",
            names,
            index=names.index(
                profile["name"]
            )
        )

        if selected_name != profile["name"]:

            profile = next(

                p
                for p in profiles
                if p["name"] == selected_name

            )

            st.session_state.org_key = profile["key"]

            st.rerun()

        st.divider()

        md(
            "**DATA PACK**"
        )

        st.caption(
            f"{len(vulnerabilities):,} "
            "vulnerability records"
        )

        st.caption(
            f"Source file: "
            f"{CSV_FILE.name if CSV_FILE else 'not found'}"
        )

        st.divider()

        st.caption(
            "RANKING SIGNALS"
        )

        st.caption(
            "CVSS severity"
        )

        st.caption(
            "CISA KEV exploitation"
        )

        st.caption(
            "FIRST EPSS likelihood"
        )

        st.caption(
            "Organisation context"
        )

        st.caption(
            "Exposure + service importance"
        )

        st.divider()

        if st.button(
            "↻ RUN ANALYSIS AGAIN",
            use_container_width=True
        ):

            st.session_state.screen = "analyzing"

            st.rerun()


    # ========================================================
    # RUN TRIAGE
    # ========================================================

    results = triage(
        profile
    )

    assets = assets_for(
        profile
    )

    total_vulnerabilities = len(
        results
    )

    matched = sum(
        r["profile_match"]
        for r in results
    )

    unmatched = (
        total_vulnerabilities
        - matched
    )

    urgent = sum(
        r["label"] == "URGENT"
        for r in results
    )

    high = sum(
        r["label"] == "HIGH"
        for r in results
    )

    medium = sum(
        r["label"] == "MEDIUM"
        for r in results
    )

    low = sum(
        r["label"] == "LOW"
        for r in results
    )

    critical = sum(
        r["score"] >= 90
        for r in results
    )


    # ========================================================
    # ORGANISATION PROFILE
    # ========================================================

    md(
        f"""
        <div class="profile">

            <div class="muted">

                ACTIVE ORGANISATION

            </div>

            <div class="profile-title">

                {escape(profile["name"])}

            </div>

            <div
                class="muted"
                style="margin-top:6px"
            >

                {escape(profile["sector"])}
                ·
                Risk appetite:
                {escape(profile["risk_appetite"])}

            </div>

        </div>
        """,
        unsafe_allow_html=True
    )

    st.write("")


    # ========================================================
    # SUMMARY CARDS
    # ========================================================

    cols = st.columns(
        6
    )

    metrics = [

        (
            "TOTAL VULNERABILITIES",
            total_vulnerabilities,
            "all ranked records"
        ),

        (
            "URGENT",
            urgent,
            "priority ≥ 75"
        ),

        (
            "CRITICAL",
            critical,
            "score ≥ 90"
        ),

        (
            "HIGH",
            high,
            "high priority"
        ),

        (
            "MEDIUM",
            medium,
            "moderate risk"
        ),

        (
            "LOW",
            low,
            "lower priority"
        )

    ]

    for col, (
        lab,
        val,
        note
    ) in zip(
        cols,
        metrics
    ):

        with col:

            md(
                f"""
                <div class="metric">

                    <small>

                        {lab}

                    </small>

                    <strong>

                        {val}

                    </strong>

                    <span>

                        {note}

                    </span>

                </div>
                """,
                unsafe_allow_html=True
            )


    # ========================================================
    # TOP 5
    # ========================================================

    md(
        """
        <div class="section-title">

            TOP 5 RANKED VULNERABILITIES

        </div>
        """,
        unsafe_allow_html=True
    )

    md(
        f"""
        <div class="section-sub">

            {total_vulnerabilities:,}
            vulnerabilities analysed
            ·
            {matched:,}
            profile matches
            ·
            {unmatched:,}
            general threats

        </div>
        """,
        unsafe_allow_html=True
    )


    if not results:

        st.warning(
            "No vulnerability records "
            "were found in the supplied CSV."
        )


    else:

        for i, r in enumerate(
            results[:5],
            1
        ):

            asset = r["asset"]

            parts = r["parts"]


            # ------------------------------------------------
            # PROFILE MATCH
            # ------------------------------------------------

            if r["profile_match"]:

                match_text = (
                    "PROFILE MATCH: YES"
                )

                asset_name = (
                    asset["display"]
                )

            else:

                match_text = (
                    "GENERAL THREAT"
                )

                asset_name = (
                    "No direct profile match"
                )


            # ------------------------------------------------
            # KEV
            # ------------------------------------------------

            if r["kev"]:

                kev_text = f"""

                <span class="sig kev">

                    CISA KEV CONFIRMED
                    +{parts["kev"]}

                </span>

                """

            else:

                kev_text = """

                <span class="sig">

                    CISA KEV NOT CONFIRMED

                </span>

                """


            # ------------------------------------------------
            # EXPOSURE
            # ------------------------------------------------

            if (
                r["profile_match"]
                and norm(
                    asset["exposure"]
                )
                == "internet facing"
            ):

                exposure_text = """

                <span class="sig net">

                    INTERNET-FACING

                </span>

                """

            elif r["profile_match"]:

                exposure_text = f"""

                <span class="sig">

                    {escape(asset["exposure"])}

                </span>

                """

            else:

                exposure_text = """

                <span class="sig">

                    GENERAL THREAT
                    · CONTEXT 0

                </span>

                """


            # ------------------------------------------------
            # VULNERABILITY CARD
            # ------------------------------------------------

            md(
                f"""
                <div class="vcard {r["class"]}">

                    <div class="row">

                        <div>

                            <div class="rank">

                                #{i} PRIORITY

                            </div>

                            <div class="cve">

                                {escape(r["cve"])}

                            </div>

                            <div class="title">

                                {escape(r["product"])}

                            </div>

                            <div class="meta">

                                {match_text}

                                ·

                                {escape(asset_name)}

                            </div>

                        </div>


                        <div>

                            <span
                                class="badge {r["class"]}"
                            >

                                {r["label"]}

                            </span>

                            <div class="score">

                                {r["score"]}

                                <small>

                                    RISK SCORE

                                </small>

                            </div>

                        </div>

                    </div>


                    <div class="signalbar">

                        <span class="sig">

                            CVSS
                            {r["cvss"]:.1f}

                            +{parts["cvss"]}

                        </span>


                        <span class="sig epss">

                            EPSS
                            {r["epss"] * 100:.1f}%

                            +{parts["epss"]}

                        </span>


                        {kev_text}


                        {exposure_text}


                        <span class="sig">

                            ORGANISATION CONTEXT
                            +{parts["context"]}

                        </span>

                    </div>


                    <div class="reason">

                        <b>

                            WHY THIS IS RANKED HERE

                        </b>

                        <br><br>

                        CVSS severity:
                        +{parts["cvss"]}

                        <br>

                        CISA KEV exploitation:
                        +{parts["kev"]}

                        <br>

                        EPSS likelihood:
                        +{parts["epss"]}

                        <br>

                        Organisation context:
                        +{parts["context"]}

                        <hr>

                        <b>

                            TOTAL RISK SCORE:
                            {r["score"]}

                        </b>

                    </div>


                    <div class="action">

                        <b>

                            RECOMMENDED NEXT STEP

                        </b>

                        Verify the affected product
                        and version, review the
                        relevant vendor guidance,
                        and prioritise remediation
                        according to exploitation
                        indicators and calculated
                        risk score.

                    </div>


                    <div
                        class="muted"
                        style="margin-top:12px"
                    >

                        {match_text}

                        ·

                        Confidence:
                        {r["confidence"]}

                        ·

                        Source:
                        supplied vulnerability CSV

                    </div>

                </div>
                """,
                unsafe_allow_html=True
            )


    # ========================================================
    # NEGATIVE TEST
    # ========================================================

    md(
        """
        <div class="section-title">

            Negative Test — High CVSS is not automatically relevant

        </div>
        """,
        unsafe_allow_html=True
    )

    md(
        """
        <div class="section-sub">

            A high CVSS score alone does not automatically
            make a vulnerability the highest priority.

        </div>
        """,
        unsafe_allow_html=True
    )

    high_cvss_results = sorted(

        results,

        key=lambda r: (
            r["cvss"],
            r["score"]
        ),

        reverse=True

    )

    if high_cvss_results:

        n = high_cvss_results[0]

        if n["profile_match"]:

            match_status = (
                "YES"
            )

        else:

            match_status = (
                "NO"
            )

        p = n["parts"]

        md(
            f"""
            <div class="reason">

                <b>

                    HIGH-CVSS NEGATIVE TEST

                </b>

                <br><br>

                <span
                    style="
                        color:#ffcf5c;
                        font:800 13px monospace
                    "
                >

                    {escape(n["cve"])}
                    ·
                    {escape(n["product"])}

                </span>

                <br><br>

                CVSS:
                {n["cvss"]:.1f}

                <br>

                EPSS:
                {n["epss"] * 100:.1f}%

                <br>

                CISA KEV:
                {"YES" if n["kev"] else "NO"}

                <br>

                PROFILE MATCH:
                {match_status}

                <br>

                ORGANISATION CONTEXT:
                +{p["context"]}

                <br>

                FINAL SCORE:
                {n["score"]}

                <br><br>

                This demonstrates that CVSS severity
                is only one part of the ranking.
                EPSS, CISA KEV exploitation indicators
                and available organisation context
                also influence priority.

            </div>
            """,
            unsafe_allow_html=True
        )

    else:

        md(
            """
            <div class="reason">

                <b>

                    NEGATIVE TEST

                </b>

                <br><br>

                No vulnerability records were available
                for the negative test.

            </div>
            """,
            unsafe_allow_html=True
        )


    # ========================================================
    # DATA & PROVENANCE
    # ========================================================

    md(
        """
        <div class="section-title">

            Data & Provenance

        </div>
        """,
        unsafe_allow_html=True
    )

    md(
        f"""
        <div class="reason">

            <b>

                SUPPLIED DATA ONLY

            </b>

            <br><br>

            Vulnerability records:
            {len(vulnerabilities):,}

            <br>

            Vulnerability file:
            {escape(
                CSV_FILE.name
                if CSV_FILE
                else "missing"
            )}

            <br>

            Profile source:
            {escape(profile["source"])}

            <br>

            Signals:

            CVSS
            ·
            CISA KEV
            ·
            FIRST EPSS
            ·
            organisation context

            <br><br>

            This prototype does not scan systems,
            execute exploits,
            or claim that an organisation is secure.

        </div>
        """,
        unsafe_allow_html=True
    )


    md(
        """
        <div class="foot">

            VULNTRIAGE

            ·

            MATCH → SCORE → RANK → EXPLAIN

        </div>
        """,
        unsafe_allow_html=True
    )