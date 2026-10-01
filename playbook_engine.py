"""
Moteur de playbooks SOAR.

Chaque playbook est un fichier YAML dans /app/playbooks decrivant :
  - trigger: la ou les regles Wazuh (rule.id) qui declenchent le playbook
  - steps: une sequence d'actions (enrich, create_case, notify, respond)

Ce moteur reste volontairement simple et lisible (pas de dependance a un
moteur de workflow externe) afin d'etre entierement compris, documente
et defendu dans le cadre du rapport de stage.
"""
import glob
import logging
import os

import yaml

from lib.thehive_client import TheHiveClient
from lib.cortex_client import CortexClient
from lib.notifier import notify

logger = logging.getLogger("soar.engine")

PLAYBOOK_DIR = os.path.join(os.path.dirname(__file__), "..", "playbooks")


class PlaybookEngine:
    def __init__(self):
        self.playbooks = self._load_playbooks()
        self.thehive = TheHiveClient(
            os.getenv("THEHIVE_URL", "http://thehive:9000"),
            os.getenv("THEHIVE_API_KEY", ""),
        )
        self.cortex = CortexClient(
            os.getenv("CORTEX_URL", "http://cortex:9001"),
            os.getenv("CORTEX_API_KEY", ""),
        )

    def _load_playbooks(self):
        playbooks = []
        for path in glob.glob(os.path.join(PLAYBOOK_DIR, "*.yml")) + \
                glob.glob(os.path.join(PLAYBOOK_DIR, "*.yaml")):
            with open(path, "r", encoding="utf-8") as f:
                pb = yaml.safe_load(f)
                pb["_source_file"] = os.path.basename(path)
                playbooks.append(pb)
        logger.info("Playbooks charges : %s", [p["name"] for p in playbooks])
        return playbooks

    def dispatch(self, alert: dict):
        """Recoit une alerte Wazuh (JSON) et execute tout playbook dont
        le trigger correspond a la regle declenchee."""
        rule_id = str(alert.get("rule", {}).get("id", ""))
        matched = [p for p in self.playbooks if rule_id in [str(r) for r in p.get("trigger_rule_ids", [])]]

        if not matched:
            logger.info("Aucun playbook associe a la regle %s - alerte journalisee sans action", rule_id)
            return {"status": "no_playbook", "rule_id": rule_id}

        results = []
        for pb in matched:
            logger.info("Execution du playbook '%s' pour la regle %s", pb["name"], rule_id)
            results.append(self._run_playbook(pb, alert))
        return {"status": "executed", "rule_id": rule_id, "playbooks": results}

    def _run_playbook(self, pb: dict, alert: dict):
        context = {"alert": alert, "case_id": None, "enrichment": {}}
        executed_steps = []

        for step in pb.get("steps", []):
            action = step.get("action")
            try:
                if action == "create_case":
                    self._step_create_case(step, context)
                elif action == "enrich":
                    self._step_enrich(step, context)
                elif action == "notify":
                    self._step_notify(step, context)
                elif action == "respond":
                    self._step_respond(step, context)
                else:
                    logger.warning("Action de playbook inconnue : %s", action)
                executed_steps.append({"action": action, "status": "ok"})
            except Exception as exc:  # noqa: BLE001
                logger.exception("Erreur pendant l'etape '%s' du playbook '%s'", action, pb["name"])
                executed_steps.append({"action": action, "status": "error", "detail": str(exc)})

        return {"playbook": pb["name"], "steps": executed_steps}

    # ---- Actions -------------------------------------------------

    def _step_create_case(self, step, context):
        alert = context["alert"]
        title = step.get("title_template", "Incident {rule_description}").format(
            rule_description=alert.get("rule", {}).get("description", "N/A")
        )
        description = (
            f"**Regle declenchee** : {alert.get('rule', {}).get('id')} - "
            f"{alert.get('rule', {}).get('description')}\n"
            f"**Niveau** : {alert.get('rule', {}).get('level')}\n"
            f"**Agent** : {alert.get('agent', {}).get('name')}\n"
            f"**Source** : {alert.get('data', {}).get('srcip', 'N/A')}\n"
            f"**MITRE ATT&CK** : {alert.get('rule', {}).get('mitre', {}).get('id', 'N/A')}\n"
        )
        case = self.thehive.create_case(
            title=title,
            description=description,
            severity=step.get("severity", 2),
            tags=step.get("tags", []) + ["cdg-capital", "auto-soar"],
        )
        if case:
            context["case_id"] = case.get("_id")

    def _step_enrich(self, step, context):
        alert = context["alert"]
        srcip = alert.get("data", {}).get("srcip")
        if not srcip:
            logger.info("Pas d'IP source a enrichir pour cette alerte")
            return
        analyzer_id = step.get("analyzer", "AbuseIPDB_1_0")
        report = self.cortex.run_analyzer(analyzer_id, srcip, "ip")
        context["enrichment"][srcip] = report
        if context.get("case_id"):
            self.thehive.add_observable(
                context["case_id"], "ip", srcip,
                message=f"Enrichissement automatique via {analyzer_id}",
            )

    def _step_notify(self, step, context):
        alert = context["alert"]
        subject = step.get("subject", "Alerte SOC").format(
            rule_description=alert.get("rule", {}).get("description", "N/A")
        )
        message = step.get("message", "Voir details dans TheHive.")
        if context.get("case_id"):
            message += f"\nCas TheHive : {context['case_id']}"
        notify(subject, message, severity=step.get("severity_label", "medium"))

    def _step_respond(self, step, context):
        """
        Trace l'action de reponse automatique.
        NOTE : le blocage IP / desactivation de compte reel est deja pris
        en charge nativement par Wazuh (active-response, cf.
        wazuh_manager.conf). Cette etape journalise la decision SOAR et
        met a jour le cas TheHive pour garder une piste d'audit unifiee.
        """
        action_desc = step.get("description", "Action de reponse automatique executee")
        logger.info("REPONSE AUTOMATIQUE : %s", action_desc)
        if context.get("case_id"):
            self.thehive.add_task_log(context["case_id"], f"[SOAR] {action_desc}")
