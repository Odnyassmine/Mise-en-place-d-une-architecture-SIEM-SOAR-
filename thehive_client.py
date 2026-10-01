"""
Client minimaliste pour l'API TheHive 5.
Utilise pour la creation automatique de cas d'incident depuis
les playbooks SOAR (traçabilite exigee pour le reporting AMMC/BAM).
"""
import logging
import requests

logger = logging.getLogger("soar.thehive")


class TheHiveClient:
    def __init__(self, base_url: str, api_key: str):
        self.base_url = base_url.rstrip("/")
        self.headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        }

    def create_case(self, title: str, description: str, severity: int = 2,
                     tags=None, tlp: int = 2, pap: int = 2):
        """
        severity: 1=low 2=medium 3=high 4=critical
        tlp/pap: Traffic Light Protocol / Permissible Actions Protocol
        """
        payload = {
            "title": title,
            "description": description,
            "severity": severity,
            "tlp": tlp,
            "pap": pap,
            "tags": tags or [],
        }
        try:
            resp = requests.post(
                f"{self.base_url}/api/v1/case",
                json=payload,
                headers=self.headers,
                timeout=10,
            )
            resp.raise_for_status()
            case = resp.json()
            logger.info("Cas TheHive cree : %s", case.get("_id"))
            return case
        except requests.RequestException as exc:
            logger.error("Echec creation cas TheHive : %s", exc)
            return None

    def add_observable(self, case_id: str, data_type: str, data: str, message: str = ""):
        payload = {
            "dataType": data_type,
            "data": data,
            "message": message,
            "ioc": True,
        }
        try:
            resp = requests.post(
                f"{self.base_url}/api/v1/case/{case_id}/observable",
                json=payload,
                headers=self.headers,
                timeout=10,
            )
            resp.raise_for_status()
            return resp.json()
        except requests.RequestException as exc:
            logger.error("Echec ajout observable TheHive : %s", exc)
            return None

    def add_task_log(self, case_id: str, message: str):
        """Ajoute une entree de log au fil du cas (piste d'audit)."""
        payload = {"message": message}
        try:
            resp = requests.post(
                f"{self.base_url}/api/v1/case/{case_id}/procedure",
                json=payload,
                headers=self.headers,
                timeout=10,
            )
            return resp.status_code < 300
        except requests.RequestException as exc:
            logger.error("Echec ajout log cas TheHive : %s", exc)
            return False
