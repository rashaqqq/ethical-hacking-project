import time
from zapv2 import ZAPv2


class ZapClient:
    def __init__(self, zap_url: str, api_key: str):
        self.zap = ZAPv2(
            apikey=api_key,
            proxies={
                "http": zap_url,
                "https": zap_url,
            },
        )

    def spider(self, target: str) -> None:
        spider_id = self.zap.spider.scan(target)

        while int(self.zap.spider.status(spider_id)) < 100:
            status = self.zap.spider.status(spider_id)
            print(f"Spider progress: {status}%")
            time.sleep(2)

    def wait_for_passive_scan(self) -> None:
        while int(self.zap.pscan.records_to_scan) > 0:
            remaining = self.zap.pscan.records_to_scan
            print(f"Passive records remaining: {remaining}")
            time.sleep(2)

    def get_alerts(self, target: str) -> list[dict]:
        return self.zap.core.alerts(baseurl=target)

    def scan(self, target: str) -> list[dict]:
        self.zap.urlopen(target)
        self.spider(target)
        self.wait_for_passive_scan()
        return self.get_alerts(target)
