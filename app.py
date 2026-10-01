"""
SOAR Orchestrator - Projet SIEM/SOAR CDG Capital
Point d'entree Flask : recoit les alertes Wazuh (integration webhook
configuree dans wazuh_manager.conf) et les transmet au moteur de
playbooks pour execution automatisee.
"""
import logging
import os

from flask import Flask, request, jsonify

from lib.playbook_engine import PlaybookEngine

logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO"),
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[
        logging.FileHandler("/app/logs/soar.log"),
        logging.StreamHandler(),
    ],
)
logger = logging.getLogger("soar.app")

app = Flask(__name__)
engine = PlaybookEngine()


@app.route("/webhook/wazuh", methods=["POST"])
def wazuh_webhook():
    alert = request.get_json(force=True, silent=True)
    if not alert:
        return jsonify({"error": "payload JSON invalide"}), 400

    logger.info(
        "Alerte recue - rule.id=%s level=%s desc=%s",
        alert.get("rule", {}).get("id"),
        alert.get("rule", {}).get("level"),
        alert.get("rule", {}).get("description"),
    )

    result = engine.dispatch(alert)
    return jsonify(result), 200


@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "up", "playbooks_loaded": len(engine.playbooks)})


@app.route("/playbooks", methods=["GET"])
def list_playbooks():
    return jsonify([
        {"name": p["name"], "trigger_rule_ids": p.get("trigger_rule_ids", []), "file": p["_source_file"]}
        for p in engine.playbooks
    ])


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
