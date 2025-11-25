# scanner/zap_api.py
import time
import os
import json
from zapv2 import ZAPv2

class ZapIntegrationError(Exception):
    pass

def connect_zap(apikey: str, host: str="127.0.0.1", port: int=8080, timeout: int=30):
    """Connecte à ZAP via l'API."""
    zap = ZAPv2(apikey=apikey, proxies={
        'http': f'http://{host}:{port}',
        'https': f'http://{host}:{port}'
    })
    # simple health check
    start = time.time()
    while True:
        try:
            _ = zap.core.version
            return zap
        except Exception as e:
            if time.time() - start > timeout:
                raise ZapIntegrationError(f"Impossible de joindre ZAP ({host}:{port}) : {e}")
            time.sleep(0.5)

def spider_and_wait(zap: ZAPv2, target: str, timeout: int = 120):
    sid = zap.spider.scan(target)
    start = time.time()
    while int(zap.spider.status(sid)) < 100:
        if time.time() - start > timeout:
            raise ZapIntegrationError("Timeout spider")
        time.sleep(1)
    # results: list of url strings
    return zap.spider.results(sid)

def active_scan_and_wait(zap: ZAPv2, target: str, timeout: int = 600):
    aid = zap.ascan.scan(target)
    start = time.time()
    while int(zap.ascan.status(aid)) < 100:
        if time.time() - start > timeout:
            raise ZapIntegrationError("Timeout active scan")
        time.sleep(2)
    return aid

def collect_alerts(zap: ZAPv2, baseurl: str = None):
    # returns list of alerts (dicts)
    try:
        return zap.core.alerts(baseurl) if baseurl else zap.core.alerts()
    except Exception:
        return []

def export_reports(zap: ZAPv2, out_dir: str, prefix: str="zap_report"):
    os.makedirs(out_dir, exist_ok=True)
    html_path = os.path.join(out_dir, f"{prefix}_zap.html")
    json_path = os.path.join(out_dir, f"{prefix}_zap.json")

    # HTML report via API
    try:
        html = zap.core.htmlreport()
        with open(html_path, "w", encoding="utf-8") as f:
            f.write(html)
    except Exception as e:
        html_path = None
    # JSON via alerts
    alerts = collect_alerts(zap)
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(alerts, f, indent=2, ensure_ascii=False)
    return {"html": html_path, "json": json_path}

def run_zap_scan(config: dict):
    """
    config keys:
      - target (str)
      - run_id (str)
      - result_dir (str)
      - zap_apikey (str)
      - zap_host (str)
      - zap_port (int)
      - use_spider (bool)
      - use_active (bool)
      - spider_timeout (int)
      - active_timeout (int)
    """
    zap = connect_zap(apikey=config.get("zap_apikey"),
                      host=config.get("zap_host","127.0.0.1"),
                      port=config.get("zap_port",8090))
    target = config["target"]
    if config.get("use_spider", True):
        spider_and_wait(zap, target, timeout=config.get("spider_timeout", 120))
    if config.get("use_active", False):
        active_scan_and_wait(zap, target, timeout=config.get("active_timeout", 600))
    alerts = collect_alerts(zap, baseurl=target)
    exported = export_reports(zap, config.get("result_dir", "results"), prefix=config.get("run_id","zap"))
    # summary counts
    summary = {"high":0,"medium":0,"low":0,"info":0}
    for a in alerts:
        r = (a.get("risk") or "Informational").lower()
        if "high" in r: summary["high"] += 1
        elif "medium" in r: summary["medium"] += 1
        elif "low" in r: summary["low"] += 1
        else: summary["info"] += 1
    return {"summary": summary, "alerts": alerts, "paths": exported}
