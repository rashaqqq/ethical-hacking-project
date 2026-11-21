import json
import os
import re
import time
from urllib.parse import urljoin, urlsplit

import requests

from scope import ScopeViolation


class ZapClient:
    def __init__(self, policy, audit, zap_url="http://127.0.0.1:8090", api_key=None):
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

    def validate_redirect_chain(self, start_url: str, max_hops: int = 5) -> str:
        """Follows HTTP redirects manually with allow_redirects=False and validates every hop against ScopeGuard."""
        current = start_url
        for _ in range(max_hops):
            self.policy.check_network(current)
            resp = requests.get(current, allow_redirects=False, timeout=10)
            if resp.status_code in (301, 302, 303, 307, 308) and "Location" in resp.headers:
                nxt = urljoin(current, resp.headers["Location"])
                self.policy.check_network(nxt)
                self.audit.log("redirect_allowed", frm=current, to=nxt)
                current = nxt
            else:
                break
        return current

    def _setup_protected_context(self, target: str) -> str:
        ctx = "securescope_ctx"
        netloc = re.escape(urlsplit(target).netloc)
        try:
            self._get("context/action/removeContext", contextName=ctx)
        except Exception:
            pass
        self._get("context/action/newContext", contextName=ctx)
        self._get("context/action/includeInContext", contextName=ctx, regex=rf"^http://{netloc}(/.*)?$")
        self._get("context/action/setContextInScope", contextName=ctx, booleanInScope="true")
        self._get("core/action/setMode", mode="protect")
        return ctx

    def passive_scan(self, target, timeout=120):
        safe_target = self.validate_redirect_chain(target)
        self.audit.log("passive_scan_start", target=safe_target)

        ctx = self._setup_protected_context(safe_target)
        self._get("core/action/accessUrl", url=safe_target, followRedirects="false")

        scan_resp = self._get("spider/action/scan", url=safe_target, contextName=ctx, subtreeOnly="true")
        sid = scan_resp.get("scan")
        start = time.time()
        if sid is not None:
            while int(self._get("spider/view/status", scanId=sid)["status"]) < 100:
                if time.time() - start > timeout:
                    self._get("spider/action/stop", scanId=sid)
                    break
                time.sleep(1)

        while int(self._get("pscan/view/recordsToScan")["recordsToScan"]) > 0:
            if time.time() - start > timeout:
                break
            time.sleep(1)

        raw_alerts = self._get("core/view/alerts", baseurl=safe_target)["alerts"]

        in_scope_alerts = []
        for a in raw_alerts:
            alert_url = a.get("url", "")
            try:
                self.policy.check_network(alert_url)
                in_scope_alerts.append({
                    "name": a.get("alert") or a.get("name") or "ZAP Alert",
                    "risk": a.get("risk", "Medium"),
                    "confidence": a.get("confidence", "Medium"),
                    "url": alert_url,
                    "parameter": a.get("param", ""),
                    "cwe_id": a.get("cweid", ""),
                    "evidence": a.get("evidence", ""),
                    "description": a.get("description", ""),
                    "solution": a.get("solution", ""),
                })
            except ScopeViolation as e:
                self.audit.log("post_scan_scope_dropped", url=alert_url, reason=str(e))

        os.makedirs("data", exist_ok=True)
        with open("data/raw_alerts.json", "w", encoding="utf-8") as f:
            json.dump(raw_alerts, f, indent=2, ensure_ascii=False)
        with open("data/findings.json", "w", encoding="utf-8") as f:
            json.dump(in_scope_alerts, f, indent=2, ensure_ascii=False)

        self.audit.log("passive_scan_done", target=safe_target, count=len(in_scope_alerts))
        return in_scope_alerts
