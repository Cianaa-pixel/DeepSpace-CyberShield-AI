# ==========================================================
# DeepSpace CyberShield AI
# dashboard.py
# Flask Dashboard Backend
# ==========================================================

from flask import Blueprint, jsonify, Response
import pandas as pd
import os
import io


# ==========================================================
# DASHBOARD BLUEPRINT
# ==========================================================

dashboard_bp = Blueprint(
    "dashboard",
    __name__,
    url_prefix="/api"
)


# ==========================================================
# PROJECT PATH
# ==========================================================

BASE_DIR = os.path.dirname(
    os.path.abspath(__file__)
)

DATASET_PATH = os.path.join(
    BASE_DIR,
    "data",
    "communication_logs.csv"
)


# ==========================================================
# LOAD DATASET
# ==========================================================

def load_dataset():

    if not os.path.exists(DATASET_PATH):

        print("Dataset not found:")
        print(DATASET_PATH)

        return pd.DataFrame()

    try:

        dataset = pd.read_csv(
            DATASET_PATH
        )

        print(
            f"Dataset loaded successfully: "
            f"{len(dataset)} records"
        )

        return dataset

    except Exception as error:

        print(
            "Error loading dataset:",
            error
        )

        return pd.DataFrame()


# ==========================================================
# PREPARE DATA
# ==========================================================

def prepare_dataset(dataset):

    if dataset.empty:

        return dataset

    dataset = dataset.copy()


    # ------------------------------------------------------
    # Required columns
    # ------------------------------------------------------

    required_columns = [

        "source",
        "relay",
        "status",
        "trust_score",
        "AI_Prediction"

    ]


    for column in required_columns:

        if column not in dataset.columns:

            print(
                f"Warning: Missing column: {column}"
            )

            dataset[column] = "Unknown"


    # ------------------------------------------------------
    # Clean trust score
    # ------------------------------------------------------

    dataset["trust_score"] = pd.to_numeric(

        dataset["trust_score"],

        errors="coerce"

    )

    dataset["trust_score"] = (
        dataset["trust_score"]
        .fillna(0)
    )


    # ------------------------------------------------------
    # Clean text columns
    # ------------------------------------------------------

    for column in [

        "source",
        "relay",
        "status",
        "AI_Prediction"

    ]:

        dataset[column] = (

            dataset[column]
            .astype(str)
            .str.strip()

        )


    return dataset


# ==========================================================
# DASHBOARD SUMMARY
# ==========================================================

@dashboard_bp.route(
    "/summary",
    methods=["GET"]
)
def dashboard_summary():

    dataset = prepare_dataset(
        load_dataset()
    )


    if dataset.empty:

        return jsonify({

            "total": 0,

            "normal": 0,

            "attacks": 0,

            "security_score": 100

        })


    total = len(dataset)


    normal = (

        dataset["status"]
        .str.lower()
        .eq("normal")
        .sum()

    )


    attacks = total - normal


    # ------------------------------------------------------
    # Security score
    # ------------------------------------------------------

    if total > 0:

        security_score = (
            normal / total
        ) * 100

    else:

        security_score = 100


    return jsonify({

        "total": int(total),

        "normal": int(normal),

        "attacks": int(attacks),

        "security_score": round(

            float(security_score),

            2

        )

    })


# ==========================================================
# COMMUNICATION RECORDS
# ==========================================================

@dashboard_bp.route(
    "/records",
    methods=["GET"]
)
def communication_records():

    dataset = prepare_dataset(
        load_dataset()
    )


    if dataset.empty:

        return jsonify([])


    records = []


    for _, row in dataset.iterrows():

        records.append({

            "source": str(
                row["source"]
            ),

            "relay": str(
                row["relay"]
            ),

            "status": str(
                row["status"]
            ),

            "trust_score": round(

                float(
                    row["trust_score"]
                ),

                2

            ),

            "AI_Prediction": str(

                row["AI_Prediction"]

            )

        })


    return jsonify(records)


# ==========================================================
# COMPLETE DASHBOARD DATA
# ==========================================================

@dashboard_bp.route(
    "/data",
    methods=["GET"]
)
def dashboard_data():

    dataset = prepare_dataset(
        load_dataset()
    )


    if dataset.empty:

        return jsonify({

            "summary": {

                "total": 0,

                "normal": 0,

                "attacks": 0,

                "security_score": 100

            },

            "records": []

        })


    total = len(dataset)


    normal = (

        dataset["status"]
        .str.lower()
        .eq("normal")
        .sum()

    )


    attacks = total - normal


    security_score = (

        (normal / total) * 100

        if total > 0

        else 100

    )


    records = []


    for _, row in dataset.iterrows():

        records.append({

            "source": str(
                row["source"]
            ),

            "relay": str(
                row["relay"]
            ),

            "status": str(
                row["status"]
            ),

            "trust_score": round(

                float(
                    row["trust_score"]
                ),

                2

            ),

            "AI_Prediction": str(

                row["AI_Prediction"]

            )

        })


    return jsonify({

        "summary": {

            "total": int(total),

            "normal": int(normal),

            "attacks": int(attacks),

            "security_score": round(

                float(
                    security_score
                ),

                2

            )

        },

        "records": records

    })


# ==========================================================
# ATTACK DISTRIBUTION
# ==========================================================

@dashboard_bp.route(
    "/attack-distribution",
    methods=["GET"]
)
def attack_distribution():

    dataset = prepare_dataset(
        load_dataset()
    )


    if dataset.empty:

        return jsonify({

            "normal": 0,

            "attacks": 0

        })


    normal = (

        dataset["status"]
        .str.lower()
        .eq("normal")
        .sum()

    )


    attacks = len(dataset) - normal


    return jsonify({

        "normal": int(normal),

        "attacks": int(attacks)

    })


# ==========================================================
# TRUST SCORES
# ==========================================================

@dashboard_bp.route(
    "/trust-scores",
    methods=["GET"]
)
def trust_scores():

    dataset = prepare_dataset(
        load_dataset()
    )


    if dataset.empty:

        return jsonify([])


    grouped = (

        dataset
        .groupby("source")["trust_score"]
        .mean()

    )


    result = []


    for source, score in grouped.items():

        result.append({

            "source": str(source),

            "trust_score": round(

                float(score),

                3

            )

        })


    return jsonify(result)


# ==========================================================
# REFRESH DASHBOARD
# ==========================================================

@dashboard_bp.route(
    "/refresh",
    methods=["GET"]
)
def refresh_dashboard():

    dataset = prepare_dataset(
        load_dataset()
    )


    if dataset.empty:

        return jsonify({

            "success": False,

            "message":
                "Dataset not found or empty."

        })


    return jsonify({

        "success": True,

        "message":
            "Dashboard refreshed successfully.",

        "records": int(
            len(dataset)
        )

    })


# ==========================================================
# EXPORT CSV
# ==========================================================

@dashboard_bp.route(
    "/export",
    methods=["GET"]
)
def export_csv():

    dataset = prepare_dataset(
        load_dataset()
    )


    if dataset.empty:

        return jsonify({

            "success": False,

            "message":
                "No dataset available."

        }), 404


    output = io.StringIO()


    dataset.to_csv(

        output,

        index=False

    )


    csv_data = output.getvalue()


    return Response(

        csv_data,

        mimetype="text/csv",

        headers={

            "Content-Disposition":

                "attachment; "
                "filename="
                "cybershield_communication_logs.csv"

        }

    )


# ==========================================================
# PYTHON HELPER
# ==========================================================

def get_dashboard_data():

    """
    Returns the cleaned communication dataset.

    This function can be imported by other
    Python modules in the project.
    """

    dataset = prepare_dataset(
        load_dataset()
    )

    return dataset


# ==========================================================
# END OF dashboard.py
# ==========================================================