"""Score the triage agent's verdicts against evidence-based ground truth.

Ground truth comes from Suricata eve.json (alerts + http events) using
Juice Shop-specific outcome rules, cross-checked with Juice Shop 'Solved' lines.

Usage:
  python3 -I scorecard.py --eve eve.jsonl --slack slack.txt \
      --since 2026-11-04T22:25 --until 2026-11-04T23:10

--slack takes either a copy of the Slack channel or the agent's own --dry-run output:
  python agent.py --follow --from-start --file <eve> --dry-run | tee after.txt
Once the agent writes verdicts to SQLite/JSON, swap parse_slack() for a loader of that store.
"""
import argparse
import json
import re
from collections import defaultdict

TARGET_IP = "192.168.60.10"
ADMIN_TOKEN_LEN = 784  # login response size for the admin account on this instance
CONFIDENTIAL_FTP = {"/ftp/acquisitions.md"}  # files that solve a challenge when read
SQLI_IN_URL = re.compile(r"(%27|')|union\s|union%20|drop%20|drop\s|or%201=1", re.I)


def load_eve(path, since, until):
    alerts, http = [], []
    bad = 0
    with open(path) as f:
        for line in f:
            try:
                e = json.loads(line)
            except ValueError:
                bad += 1
                continue
            t = e.get("timestamp", "")[:19]
            if not (since <= t < until):
                continue
            # attribute to the client side of the flow, not the raw src_ip
            src, dst = e.get("src_ip"), e.get("dest_ip")
            e["client"] = dst if src == TARGET_IP else src
            if e.get("event_type") == "alert":
                alerts.append(e)
            elif e.get("event_type") == "http":
                http.append(e)
    return alerts, http, bad


def ground_truth(alerts, http):
    """Return {client_ip: {"outcome": str, "findings": [str]}}."""
    per = defaultdict(lambda: {"succeeded": [], "attempted": [], "recon": []})

    sqli_login = defaultdict(lambda: defaultdict(int))
    for a in alerts:
        c, sig, h = a["client"], a["alert"]["signature"], a.get("http", {})
        if c is None:
            continue
        if "SQL" in sig and h.get("url") == "/rest/user/login":
            sqli_login[c][h.get("status")] += 1
        elif sig.startswith("ET SCAN"):
            per[c]["recon"].append("port scan")

    logins = defaultdict(lambda: defaultdict(int))
    for e in http:
        c, h = e["client"], e.get("http", {})
        url, st, ln, m = h.get("url", ""), h.get("status"), h.get("length"), h.get("http_method")
        if url == "/rest/user/login" and m == "POST":
            key = "admin200" if (st == 200 and ln == ADMIN_TOKEN_LEN) else st
            logins[c][key] += 1
        elif url.startswith("/rest/products/search?q=") and SQLI_IN_URL.search(url.split("?q=", 1)[1]):
            per[c]["attempted"].append(f"search SQLi -> {st}")
        elif url in CONFIDENTIAL_FTP and st == 200:
            per[c]["succeeded"].append(f"read {url}")
        elif url.startswith("/ftp/") and st == 403:
            per[c]["attempted"].append(f"blocked file {url}")
        elif url.startswith("/rest/user/authentication-details") and st == 200:
            per[c]["succeeded"].append("admin section (user list)")

    for c in set(sqli_login) | set(logins):
        s_ok = sqli_login[c].get(200, 0)
        s_fail = sum(v for k, v in sqli_login[c].items() if k != 200)
        admin_ok = logins[c].get("admin200", 0)
        if s_ok:
            per[c]["succeeded"].append(f"SQLi login bypass x{s_ok}")
        if admin_ok > s_ok:
            per[c]["succeeded"].append(f"admin login with no SQLi alert x{admin_ok - s_ok}")
        if s_fail:
            per[c]["attempted"].append(f"SQLi login failed x{s_fail}")
        if logins[c].get(500):
            per[c]["attempted"].append(f"login query error (500) x{logins[c][500]}")

    out = {}
    for c, d in per.items():
        if d["succeeded"]:
            outcome = "succeeded"
        elif d["attempted"]:
            outcome = "attempted"
        elif d["recon"]:
            outcome = "recon"
        else:
            continue
        findings = sorted(set(d["succeeded"])) + sorted(set(d["attempted"]))
        if d["recon"]:
            findings.append(f"port scan x{len(d['recon'])}")
        out[c] = {"outcome": outcome, "findings": findings}
    return out


def parse_slack(path):
    verdicts, cur = {}, None
    for line in open(path, encoding="utf-8"):
        m = re.search(r":(\w+?)_circle: \*?(\w+): .*\((succeeded|attempted|unknown|not an attack)", line)
        if m:
            cur = {"severity": m.group(2), "outcome": m.group(3)}
            continue
        m = re.match(r"\*?Attacker:\*?\s+(\S+)", line)
        if m and cur:
            verdicts[m.group(1)] = cur
            cur = None
    return verdicts


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--eve", required=True)
    ap.add_argument("--slack", required=True)
    ap.add_argument("--since", required=True)
    ap.add_argument("--until", required=True)
    a = ap.parse_args()

    alerts, http, bad = load_eve(a.eve, a.since, a.until)
    truth = ground_truth(alerts, http)
    agent = parse_slack(a.slack)
    clients = sorted({e["client"] for e in http if e["client"]} | set(truth), key=lambda ip: int(ip.split(".")[-1]))

    tally = defaultdict(int)
    print(f"{'client':<16}{'truth':<11}{'agent said':<26}{'result':<14}evidence")
    for c in clients:
        t = truth.get(c, {"outcome": "none", "findings": []})
        v = agent.get(c)
        said = f"{v['severity']} / {v['outcome']}" if v else "(silent)"
        if t["outcome"] == "none":
            result = "false alarm" if v and v["outcome"] != "not an attack" else "correct quiet"
        elif not v:
            result = "MISSED"
        elif v["outcome"] == t["outcome"] or (t["outcome"] == "recon" and v["outcome"] == "attempted"):
            result = "correct"
        elif v["outcome"] == "unknown":
            result = "unknown"
        elif v["outcome"] == "not an attack":
            result = "called benign"
        elif v["outcome"] == "succeeded":
            result = "over-called"
        else:
            result = "under-called"
        tally[result] += 1
        print(f"{c:<16}{t['outcome']:<11}{said:<26}{result:<14}{'; '.join(t['findings'])}")

    print("\nsummary:", dict(tally))
    print(f"malformed eve lines skipped: {bad}")


if __name__ == "__main__":
    main()
