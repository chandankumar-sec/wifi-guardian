"""Response layer. Decides what to do about an alert and (only in auto mode with --apply) does it.

Modes
  monitor  record the recommended action, change nothing        (default)
  semi     record it as pending; a human approves in the dashboard/CLI
  auto     apply it. Without apply=True the nftables commands are only generated (dry run).

Protected targets (gateway, admin devices) are never blocked, in any mode.
The nftables commands are generated and unit-tested as strings. Applying them needs Linux, root and nft;
verify them on your own gateway VM before trusting auto mode.
"""
import ipaddress
import platform
import shlex
import subprocess

from .rules import RULES

TABLE = "inet wifiguardian"


def nft_ruleset():
    """Base ruleset to load once on the gateway. Quarantine is default-drop for listed MACs except the dashboard port."""
    return f"""table {TABLE} {{
  set quarantine_macs {{ type ether_addr; flags timeout; }}
  set blocked_src {{ type ipv4_addr; flags timeout; }}
  set blocked_dst {{ type ipv4_addr; flags timeout; }}
  set limited_src {{ type ipv4_addr; flags timeout; }}
  chain prerouting {{
    type filter hook prerouting priority raw; policy accept;
    ether saddr @quarantine_macs udp dport {{ 53, 67 }} accept
    ether saddr @quarantine_macs drop
    ip saddr @blocked_src drop
    ip daddr @blocked_dst drop
    ip saddr @limited_src limit rate over 20/second drop
    ct state invalid drop
  }}
}}"""


def commands_for(kind, target, timeout="1h"):
    if kind == "quarantine_mac":
        return [f"nft add element {TABLE} quarantine_macs {{ {target} timeout {timeout} }}"]
    if kind == "block_src":
        return [f"nft add element {TABLE} blocked_src {{ {target} timeout {timeout} }}"]
    if kind == "block_dst":
        return [f"nft add element {TABLE} blocked_dst {{ {target} timeout {timeout} }}"]
    if kind == "rate_limit_ip":
        return [f"nft add element {TABLE} limited_src {{ {target} timeout {timeout} }}"]
    return []


def undo_commands(kind, target):
    sets = {"quarantine_mac": "quarantine_macs", "block_src": "blocked_src",
            "block_dst": "blocked_dst", "rate_limit_ip": "limited_src"}
    return [f"nft delete element {TABLE} {sets[kind]} {{ {target} }}"] if kind in sets else []


def _is_ip(v):
    try:
        ipaddress.ip_address(v)
        return True
    except ValueError:
        return False


class Enforcer:
    def __init__(self, cfg, apply=False):
        self.mode = cfg["mode"]
        self.protected = set(cfg["protected"])
        self.apply = apply
        self.n = 0

    def decide(self, alert, mac, ip):
        """Return an action dict for this alert (always one, so the record shows what was considered)."""
        kind = RULES[alert["rule"]]["action"]
        target = {"quarantine_mac": mac, "rate_limit_ip": ip, "block_src": ip,
                  "block_dst": alert.get("target")}.get(kind)
        self.n += 1
        act = {"id": f"ACT-{self.n:04d}", "ts": alert["ts"], "alert_id": alert["id"], "kind": kind,
               "target": target or "", "commands": [], "reason": ""}
        if kind == "block_dst" and target and not _is_ip(target):
            act.update(kind="advise", state="advice_only", target=target,
                       reason=f"{target} is a domain: sinkhole or block it at the DNS resolver.")
            return act
        if kind == "advise" or not target:
            act.update(kind="advise", state="advice_only",
                       reason="No automatic network action fits this alert; follow the playbook.")
            return act
        if target in self.protected:
            act.update(state="skipped_protected", reason=f"{target} is on the protected list and is never blocked.")
            return act
        act["commands"] = commands_for(kind, target)
        if self.mode == "monitor":
            act.update(state="recommended", reason="Monitor-only mode: nothing was changed.")
        elif self.mode == "semi":
            act.update(state="pending_approval", reason="Waiting for analyst approval.")
        else:
            act.update(state="dry_run", reason="Auto mode without --apply: commands generated, not executed.")
            if self.apply:
                self._run(act)
        return act

    def approve(self, act):
        if act["state"] == "pending_approval":
            act["state"] = "dry_run"
            act["reason"] = "Approved by analyst."
            if self.apply:
                self._run(act)
        return act

    def undo(self, act):
        if act["state"] == "applied" and self.apply:
            for c in undo_commands(act["kind"], act["target"]):
                subprocess.run(shlex.split(c), check=False)
        act["state"] = "reverted"
        act["reason"] = "Reverted by analyst."
        return act

    def _run(self, act):
        if platform.system() != "Linux":
            act.update(state="failed", reason="nftables needs Linux; commands were not executed.")
            return
        try:
            for c in act["commands"]:
                subprocess.run(shlex.split(c), check=True, capture_output=True, timeout=10)
            act.update(state="applied", reason="Applied with nftables.")
        except (OSError, subprocess.SubprocessError) as exc:
            act.update(state="failed", reason=f"nft failed: {exc}")
