# Deploying the lab agent as an always-on service

The agent runs on the **overwatch VM** as a Linux service. It watches Suricata's
`eve.json`, bundles each attacker's alerts, asks the local model what happened,
and posts to Slack. Nobody has to start it: it comes up at boot and restarts itself.

Run every command **one at a time** on the overwatch VM (`ssh mucsc@192.168.1.154`)
unless a step says otherwise.

## Part 0: get the new code onto the overwatch VM

On your laptop, commit and push these files from VS Code (check `.env` isn't in the list).
Then on the overwatch VM:
```bash
git -C ~/AgenticHomeLab pull
ls ~/AgenticHomeLab/agent/deploy
```
You should see `60-lab-sniff.yaml` and `lab-agent.service`.

## Part A: keep the listening card up after reboots

The card on `vmbr1` was turned on by hand, which a reboot undoes. This file makes
it permanent, still with **no IP address**. Use your card's real name if it isn't `enp6s20`.

```bash
sudo cp ~/AgenticHomeLab/agent/deploy/60-lab-sniff.yaml /etc/netplan/
sudo chmod 600 /etc/netplan/60-lab-sniff.yaml
sudo netplan try
```
`netplan try` applies the change and waits. If your SSH session still works, press
**Enter** to keep it. If you lose SSH, do nothing: it undoes itself after 120 seconds.

Check: `ip -br addr show enp6s20` shows the card **UP with no address**.

## Part B: a dedicated user for the agent

```bash
sudo useradd --system --create-home --home-dir /opt/lab-agent --shell /usr/sbin/nologin labagent
sudo -u labagent -H git clone https://github.com/YOUR_GITHUB_USER/AgenticHomeLab.git /opt/lab-agent/repo
sudo -u labagent -H python3 -m venv /opt/lab-agent/.venv
sudo -u labagent -H /opt/lab-agent/.venv/bin/pip install -r /opt/lab-agent/repo/agent/requirements.txt
sudo cp ~/AgenticHomeLab/agent/.env /opt/lab-agent/repo/agent/.env
sudo chown labagent:labagent /opt/lab-agent/repo/agent/.env
sudo chmod 600 /opt/lab-agent/repo/agent/.env
```
The `.env` comes from the copy you already made; it is never in git.

## Part C: let the agent read Suricata's log

```bash
sudo apt install -y acl
sudo setfacl -m u:labagent:rx /var/log/suricata
sudo setfacl -d -m u:labagent:r /var/log/suricata
sudo setfacl -m u:labagent:r /var/log/suricata/eve.json
sudo -u labagent head -c 300 /var/log/suricata/eve.json
```
The last command should print the start of the log, not "Permission denied".
The `-d` line makes new log files (after rotation) readable too.

## Part D: try it in the foreground first

```bash
cd /opt/lab-agent/repo/agent
sudo -u labagent -H /opt/lab-agent/.venv/bin/python agent.py --follow --file /var/log/suricata/eve.json --dry-run
```
Run one attack from the `MUCSC-TARGET` Wi-Fi. After about 60 seconds the bundle is
investigated and the Slack message is printed (not sent). Press **Ctrl+C** to stop.

## Part E: install the service

```bash
sudo cp /opt/lab-agent/repo/agent/deploy/lab-agent.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now lab-agent
systemctl status lab-agent --no-pager
```
Slack should show **"Lab Agent is on watch."**

## Part F: prove it

1. Run an attack from `MUCSC-TARGET`. Within about a minute, a report lands in Slack.
2. Reboot the overwatch VM (`sudo reboot`). When it's back, Slack shows "on watch" again
   without you doing anything, and a new attack still gets reported.
3. In Proxmox, take a snapshot of VM 101.

## Day to day

| Task | Command |
| --- | --- |
| Is it running? | `systemctl status lab-agent --no-pager` |
| Watch it think | `journalctl -u lab-agent -f` |
| Restart | `sudo systemctl restart lab-agent` |
| Stop | `sudo systemctl stop lab-agent` |
| Update the code | `sudo -u labagent -H git -C /opt/lab-agent/repo pull` then restart |
| Change settings | `sudo nano /opt/lab-agent/repo/agent/.env` then restart |

Settings in `.env` (all optional): `WINDOW_SECONDS`, `COOLDOWN_MINUTES`,
`DIGEST_MINUTES`, `HEARTBEAT_HOURS`, `IGNORE_SIDS`. See `.env.example`.
