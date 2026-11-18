from dataclasses import dataclass
from urllib.parse import urlsplit

import yaml


class ScopeViolation(Exception):
    pass


@dataclass
class Target:
    host: str
    port: int
    name: str


class ScopeGuard:
    def __init__(self, allowed_schemes, allowed_targets, audit=None):
        self.allowed_schemes = set(allowed_schemes)
        self.allowed_targets = {(t["host"], int(t["port"])): t["name"] for t in allowed_targets}
        self.audit = audit

    @classmethod
    def from_config(cls, path, audit=None):
        cfg = yaml.safe_load(open(path, encoding="utf-8"))["scope"]
        return cls(cfg["allowed_schemes"], cfg["allowed_targets"], audit=audit)

    def _deny(self, url, reason):
        if self.audit:
            self.audit.log("scope_denied", url=url, reason=reason)
        raise ScopeViolation(reason)

    def validate(self, url: str) -> Target:
        if "%40" in url.lower() or "#" in url:
            return self._deny(url, "suspicious encoding or fragment in URL")

        parts = urlsplit(url)

        if parts.scheme not in self.allowed_schemes:
            return self._deny(url, f"scheme '{parts.scheme}' not allowed")
        if "@" in parts.netloc:
            return self._deny(url, "userinfo in URL is not allowed")

        try:
            hostname = parts.hostname
            port = parts.port
        except ValueError:
            return self._deny(url, "malformed host or port in URL")

        if hostname is None:
            return self._deny(url, "no hostname")

        port = port or (80 if parts.scheme == "http" else 443)
        key = (hostname, port)
        if key not in self.allowed_targets:
            return self._deny(url, f"{hostname}:{port} is not an allowed target")

        name = self.allowed_targets[key]
        if self.audit:
            self.audit.log("scope_allowed", url=url, target=name)
        return Target(host=hostname, port=port, name=name)
