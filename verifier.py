import yaml
import tldextract
from urllib.parse import urlparse
from utils import normalize_url, levenshtein

def load_whitelist(path: str):
    with open(path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}
    reg_domains = set()
    name_to_domains = {}
    for name, domains in data.items():
        norm = []
        for d in domains or []:
            ext = tldextract.extract(d)
            if ext.registered_domain:
                reg = ext.registered_domain.lower()
                reg_domains.add(reg)
                norm.append(reg)
        name_to_domains[name] = norm
    return name_to_domains, reg_domains

def load_suspicious_tlds(path: str):
    tlds = set()
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip().lower()
            if not line or line.startswith("#"): 
                continue
            if line.startswith("."):
                line = line[1:]
            tlds.add(line)
    return tlds

def analyze_url(url: str, whitelist_map, official_domains_set, suspicious_tlds_set):
    original = url
    url = normalize_url(url)
    parsed = urlparse(url)
    scheme = parsed.scheme.lower()
    host = parsed.hostname or ""
    ext = tldextract.extract(host)
    registered = ext.registered_domain.lower() if ext.registered_domain else ""
    sld = ext.domain.lower() if ext.domain else ""
    tld = ext.suffix.lower() if ext.suffix else ""

    reasons = []
    risk = 50

    if scheme != "https":
        risk += 15
        reasons.append("Connection is not HTTPS.")

    if tld in suspicious_tlds_set:
        risk += 15
        reasons.append(f"TLD '.{tld}' is often abused.")

    matched_name = None
    matched_official = None
    if registered in official_domains_set:
        risk -= 40
        reasons.append(f"Domain matches official whitelist: {registered}.")
        for name, doms in whitelist_map.items():
            if registered in doms:
                matched_name = name
                matched_official = registered
                break
    else:
        best_dist = None
        closest = None
        for dom in official_domains_set:
            ext2 = tldextract.extract(dom)
            sld_off = ext2.domain.lower()
            d = levenshtein(sld, sld_off)
            if best_dist is None or d < best_dist:
                best_dist = d
                closest = dom
        if best_dist is not None and best_dist <= 2 and sld:
            risk += 20
            reasons.append(f"Possible typosquatting: '{sld}' close to '{closest}'.")

        host_lower = host.lower()
        for dom in official_domains_set:
            if dom in host_lower and not host_lower.endswith(dom):
                risk += 15
                reasons.append(f"Official domain string appears in host but not as registered domain: {host}.")
                break

        path_lower = (parsed.path or "").lower()
        shady_keywords = ["crack", "serial", "license-key", "keygen"]
        if any(k in path_lower for k in shady_keywords):
            risk += 20
            reasons.append("Shady keywords detected in path.")

    risk = max(0, min(100, risk))

    if risk <= 20:
        verdict = "LIKELY_OFFICIAL"
    elif risk >= 60:
        verdict = "SUSPICIOUS"
    else:
        verdict = "UNKNOWN"

    return {
        "input_url": original,
        "normalized_url": url,
        "scheme": scheme,
        "host": host,
        "registered_domain": registered,
        "tld": tld,
        "risk_score": risk,
        "verdict": verdict,
        "reasons": reasons,
        "matched_software": matched_name,
        "matched_official_domain": matched_official
    }
