"""
Traffic simulator: writes fake Suricata events into a file over time, the way the
real Suricata writes eve.json, so always-on mode can be tested without attacking anything.

    python simulate.py --out /tmp/sim_eve.json
    (second window)  python agent.py --follow --file /tmp/sim_eve.json --from-start --dry-run

Scene 1 sends the seven test alerts one at a time. Like real Suricata, each alert goes
out BEFORE the server's answer, followed by a separate web event carrying the status code.
Scene 2 sends a sqlmap-style burst of the same alert from one attacker.
"""

import argparse
import copy
import json
import time
from datetime import datetime, timezone


def now_ts() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f+0000")


def main() -> None:
    parser = argparse.ArgumentParser(description="Write fake Suricata events into a file over time.")
    parser.add_argument("--out", required=True, help="file to write to (the agent watches this)")
    parser.add_argument("--source", default="fake_eve.json", help="alerts to replay")
    parser.add_argument("--burst", type=int, default=40, help="alerts in the sqlmap-style burst")
    parser.add_argument("--gap", type=float, default=3, help="seconds between alerts in scene 1")
    args = parser.parse_args()

    with open(args.source, encoding="utf-8") as f:
        alerts = [json.loads(line) for line in f if line.strip()]

    def write(event: dict) -> None:
        with open(args.out, "a", encoding="utf-8") as f:
            f.write(json.dumps(event) + "\n")

    def send(alert: dict, tx_id: int) -> None:
        a = copy.deepcopy(alert)
        a.pop("lab_test", None)  # the answer key never goes into a log
        a["timestamp"] = now_ts()
        a["tx_id"] = tx_id
        http = a.get("http", {})
        status, length = http.pop("status", None), http.pop("length", None)
        write(a)  # the alert, without the server's answer yet
        if status is not None:
            write({
                "timestamp": now_ts(), "flow_id": a["flow_id"], "tx_id": tx_id, "event_type": "http",
                "src_ip": a["src_ip"], "dest_ip": a["dest_ip"], "dest_port": a["dest_port"],
                "http": {**http, "status": status, "length": length},
            })

    print(f"Writing simulated events to {args.out}")
    print("Scene 1: the seven test alerts, one at a time")
    for alert in alerts:
        send(alert, 0)
        print(f"  sent: {alert['alert']['signature']} from {alert['src_ip']}")
        time.sleep(args.gap)

    burst = next((a for a in alerts if "UNION" in a["alert"]["signature"]), alerts[0])
    print(f"Scene 2: a sqlmap-style burst of {args.burst} alerts from {burst['src_ip']}")
    for n in range(args.burst):
        send(burst, n + 1)
        time.sleep(0.05)
    print("Done. The burst should become ONE investigation, and later repeats should fold into the digest.")


if __name__ == "__main__":
    main()
