"""
Client minimaliste pour l'API Cortex.
Permet de lancer des analyseurs d'enrichissement (reputation IP,
hash, domaine) depuis les playbooks. Les analyseurs concrets
(VirusTotal, AbuseIPDB, etc.) sont a configurer dans l'UI Cortex
avec les cles API du client (non fournies dans ce projet academique).
"""
import logging
import time
import requests

logger = logging.getLogger("soar.cortex")


class CortexClient:
    def __init__(self, base_url: str, api_key: str):
        self.base_url = base_url.rstrip("/")
        self.headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        }

    def run_analyzer(self, analyzer_id: str, data: str, data_type: str, tlp: int = 2):
        payload = {"data": data, "dataType": data_type, "tlp": tlp}
        try:
            resp = requests.post(
                f"{self.base_url}/api/analyzer/{analyzer_id}/run",
                json=payload,
                headers=self.headers,
                timeout=10,
            )
            resp.raise_for_status()
            job = resp.json()
            return self._wait_for_result(job["id"])
        except requests.RequestException as exc:
            logger.error("Echec lancement analyseur Cortex %s : %s", analyzer_id, exc)
            return None

    def _wait_for_result(self, job_id: str, max_wait: int = 30):
        elapsed = 0
        while elapsed < max_wait:
            try:
                resp = requests.get(
                    f"{self.base_url}/api/job/{job_id}/report",
                    headers=self.headers,
                    timeout=10,
                )
                if resp.status_code == 200:
                    report = resp.json()
                    if report.get("status") in ("Success", "Failure"):
                        return report
            except requests.RequestException as exc:
                logger.error("Erreur polling Cortex job %s : %s", job_id, exc)
                return None
            time.sleep(2)
            elapsed += 2
        logger.warning("Timeout en attente du resultat Cortex job %s", job_id)
        return None
