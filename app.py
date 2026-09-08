"""
SIH26106 — AI-Powered Email Threat Detection & Forensic Intelligence Platform
Main Flask Application Server & SOC REST API
"""

import os
import time
import json
from flask import Flask, request, jsonify, render_template, send_from_directory

from engine.parser import EmailParser
from engine.threat_detector import ThreatDetector
from engine.threat_intel import ThreatIntelEngine
from engine.forensic_investigator import ForensicInvestigator
from engine.graph_engine import GraphEngine
from engine.ai_provider import AIProviderManager
from engine.samples import SAMPLE_EMAILS, get_all_samples, get_sample_by_id
from engine.case_store import CaseStore

app = Flask(__name__, template_folder="templates", static_folder="static")

# Initialize engines
parser = EmailParser()
threat_detector = ThreatDetector()
intel_engine = ThreatIntelEngine(mode="HYBRID")
forensic_investigator = ForensicInvestigator(intel_engine=intel_engine)
graph_engine = GraphEngine()
ai_manager = AIProviderManager.get_instance()
case_store = CaseStore(db_path="cases.db")


def seed_initial_samples():
    """Seeds the database with analyzed sample cases on initial startup if empty."""
    metrics = case_store.get_soc_metrics()
    if metrics.get("total_analyzed", 0) == 0:
        print("[*] Seeding sample cases into local SOC database...")
        for sample_key, sample in SAMPLE_EMAILS.items():
            try:
                raw_eml = sample["raw_eml"]
                parsed = parser.parse_raw_eml(raw_eml)
                threat = threat_detector.analyze(parsed)
                forensic = forensic_investigator.investigate(parsed)
                ai_rep = ai_manager.analyze(parsed, threat, forensic)
                
                case_id = f"CASE-SEED-{sample_key.upper()}"
                graph = graph_engine.build_email_graph(case_id, parsed, threat, forensic)

                dossier = {
                    "case_id": case_id,
                    "sample_id": sample_key,
                    "title": sample["title"],
                    "timestamp": time.time(),
                    "date_str": time.strftime("%Y-%m-%d %H:%M:%S UTC"),
                    "raw_eml": raw_eml,
                    "parsed_email": parsed,
                    "threat_detection": threat,
                    "forensic_investigation": forensic,
                    "ai_synthesis": ai_rep,
                    "graph_data": graph
                }
                case_store.save_case(dossier)
            except Exception as e:
                print(f"[!] Error seeding {sample_key}: {e}")
        print("[+] Seed complete.")


# Seed immediately
seed_initial_samples()


@app.route("/")
def index():
    """Serves the main SOC Analyst Dashboard."""
    return render_template("index.html")


@app.route("/api/samples", methods=["GET"])
def list_samples():
    """Returns metadata for built-in sample demonstration emails."""
    return jsonify({"status": "success", "samples": get_all_samples()})


@app.route("/api/samples/<sample_id>", methods=["GET"])
def get_sample(sample_id):
    """Retrieves full text of a specific sample email."""
    sample = get_sample_by_id(sample_id)
    if not sample:
        return jsonify({"status": "error", "message": "Sample not found"}), 404
    return jsonify({"status": "success", "sample": sample})


@app.route("/api/analyze", methods=["POST"])
def analyze_email():
    """
    Main analysis endpoint.
    Accepts raw .eml text or uploaded file.
    Executes:
    1. RFC 5322 MIME Parser
    2. Module 1: Threat & Fraud Detection Engine
    3. Module 2: Forensic Origin & Infrastructure Engine
    4. Pluggable AI Synthesis Engine
    5. Infrastructure Relationship & Correlation Graph Engine
    6. Local SQLite Case Persistence
    """
    try:
        raw_eml = ""
        source_type = "paste"
        
        # Check if file upload
        if "file" in request.files:
            uploaded_file = request.files["file"]
            raw_eml = uploaded_file.read().decode("utf-8", errors="replace")
            source_type = "upload"
        else:
            data = request.get_json(silent=True) or {}
            raw_eml = data.get("raw_eml", "")
            source_type = data.get("source", "paste")

        if not raw_eml.strip():
            return jsonify({"status": "error", "message": "Empty email content provided"}), 400

        # Step 1: Parse Email
        parsed = parser.parse_raw_eml(raw_eml)

        # Step 2: Module 1 Threat Detection
        threat_data = threat_detector.analyze(parsed)

        # Step 3: Module 2 Forensic Origin Investigation
        forensic_data = forensic_investigator.investigate(parsed)

        # Step 4: AI Layer Synthesis
        ai_synthesis = ai_manager.analyze(parsed, threat_data, forensic_data)

        # Step 5: Generate Case ID and Relationship Graph
        case_id = f"CASE-{int(time.time())}-{os.urandom(2).hex().upper()}"
        graph_data = graph_engine.build_email_graph(case_id, parsed, threat_data, forensic_data)

        # Step 6: Assemble Complete Dossier
        dossier = {
            "case_id": case_id,
            "source_type": source_type,
            "timestamp": time.time(),
            "date_str": time.strftime("%Y-%m-%d %H:%M:%S UTC"),
            "raw_eml": raw_eml,
            "parsed_email": parsed,
            "threat_detection": threat_data,
            "forensic_investigation": forensic_data,
            "ai_synthesis": ai_synthesis,
            "graph_data": graph_data
        }

        # Step 7: Persist Case locally
        case_store.save_case(dossier)

        return jsonify({
            "status": "success",
            "case_id": case_id,
            "dossier": dossier
        })

    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({"status": "error", "message": str(e)}), 500


@app.route("/api/cases", methods=["GET"])
def list_cases():
    """Returns list of previous investigation cases."""
    limit = request.args.get("limit", 50, type=int)
    cases = case_store.list_cases(limit=limit)
    return jsonify({"status": "success", "cases": cases})


@app.route("/api/cases/<case_id>", methods=["GET"])
def get_case(case_id):
    """Retrieves full case dossier."""
    case = case_store.get_case(case_id)
    if not case:
        return jsonify({"status": "error", "message": "Case not found"}), 404
    return jsonify({"status": "success", "case": case})


@app.route("/api/metrics", methods=["GET"])
def get_metrics():
    """Returns SOC dashboard aggregated metrics."""
    metrics = case_store.get_soc_metrics()
    return jsonify({"status": "success", "metrics": metrics})


@app.route("/api/graph/<case_id>", methods=["GET"])
def get_graph(case_id):
    """Returns interactive graph topology for a specific case."""
    case = case_store.get_case(case_id)
    if not case:
        return jsonify({"status": "error", "message": "Case not found"}), 404
    return jsonify({"status": "success", "graph": case.get("graph_data", {})})


@app.route("/api/settings", methods=["GET", "POST"])
def handle_settings():
    """Gets or updates AI provider and threat intelligence configuration."""
    if request.method == "POST":
        data = request.get_json() or {}
        mode = data.get("ai_mode", "HEURISTIC")
        api_key = data.get("api_key", "")
        ai_manager.set_provider(mode, api_key)
        return jsonify({"status": "success", "message": f"AI provider updated to {mode}"})
    else:
        return jsonify({
            "status": "success",
            "settings": {
                "ai_mode": ai_manager.provider_mode,
                "threat_intel_mode": intel_engine.mode,
                "active_ai_name": ai_manager.active_provider.__class__.__name__
            }
        })


if __name__ == "__main__":
    print("\n=======================================================")
    print("  SIH26106 Email Threat Detection & Forensic Platform")
    print("  SOC Analyst Cockpit online: http://127.0.0.1:5000")
    print("=======================================================\n")
    app.run(host="127.0.0.1", port=5000, debug=True)
