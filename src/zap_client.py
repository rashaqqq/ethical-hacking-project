import json
import os
import time

import requests


class ZapClient:
    def __init__(self, policy, audit, zap_url="http://127.0.0.1:8080", api_key=None):
        self.policy = policy
        self.audit = audit
        self.base = zap_url.rstrip("/")
        self.api_key = api_key or os.environ.get("ZAP_API_KEY", "")

    def _get(self, path, **params):
        if self.api_key:
            params["apikey"] = self.api_key
        r = requests.get(f"{self.base}/JSON/{path}/", params=params, timeout=30)
        r.raise_for_status()
        return r.json()

    def version(self):
        return self._get("core/view/version")["version"]

    def passive_scan(self, target, timeout=120):
        self.policy.check_network(target)
        self.audit.log("passive_scan_start", target=target)

        self._get("core/action/accessUrl", url=target, followRedirects="true")

        start = time.time()
        while int(self._get("pscan/view/recordsToScan")["recordsToScan"]) > 0:
            if time.time() - start > timeout:
                break
            time.sleep(1)

        alerts = self._get("core/view/alerts", baseurl=target)["alerts"]

        os.makedirs("data", exist_ok=True)
        with open("data/raw_alerts.json", "w") as f:
            json.dump(alerts, f, indent=2)

        self.audit.log("passive_scan_done", target=target, count=len(alerts))
        return alerts
