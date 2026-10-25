#!/usr/bin/env python3
"""whatfiltered — what does this machine's firewall actually let through?

Read-only auditor for nftables and iptables rulesets. Reports default
policies, which ports are reachable from where, rules shadowed by earlier
rules, rules that never matched, and (with --expose) cross-checks against
a whatserved JSON report. Stdlib only. No network. Nothing is modified.
"""

import argparse
import ipaddress
import json
import re
import shlex
import subprocess
import sys
from dataclasses import dataclass, field

VERSION = "1.0.0"

TERMINAL = ("accept", "drop", "reject")
RETURN_TRAFFIC = {"established", "related"}


# --------------------------------------------------------------------------
# normalized match model
# --------------------------------------------------------------------------

@dataclass
class Match:
    """One rule's conditions, normalized to what the analyzer can reason
    about. Any condition we cannot model lands in `opaque`, which makes
    the rule conservative: it never shadows anything and is never
    reported as shadowed."""
    proto: str = None                 # 'tcp' | 'udp' | 'icmp' | 'icmpv6'
    dports: list = None               # list of (lo, hi) or None = any
    sports: list = None
    saddrs: list = None               # list of ip network objects
    daddrs: list = None
    iif: set = None                   # incoming interface names
    oif: set = None
    states: set = None                # required ct states
    icmp: set = None                  # icmp/icmpv6 type|code constraints
    opaque: list = field(default_factory=list)

    def desc(self):
        bits = []
        if self.proto:
            bits.append(self.proto)
        if self.dports:
            bits.append("dport " + ",".join(_fmt_range(r) for r in self.dports))
        if self.sports:
            bits.append("sport " + ",".join(_fmt_range(r) for r in self.sports))
        if self.iif:
            bits.append("iif " + ",".join(sorted(self.iif)))
        if self.oif:
            bits.append("oif " + ",".join(sorted(self.oif)))
        if self.saddrs:
            bits.append("from " + ",".join(str(n) for n in self.saddrs))
        if self.daddrs:
            bits.append("to " + ",".join(str(n) for n in self.daddrs))
        if self.states:
            bits.append("ctstate " + ",".join(sorted(self.states)))
        if self.icmp:
            bits.append("icmp " + ",".join(sorted(self.icmp)))
        for o in self.opaque:
            bits.append("[" + o + "]")
        return " ".join(bits) if bits else "any"

    # -- containment: does self match everything other matches? ----------

    def shadows(self, other):
        """True if this match is a superset: every packet `other` matches,
        this one also matches."""
        if self.opaque or other.opaque:
            return False
        if self.proto and self.proto != other.proto:
            return False
        if not _ports_cover(self.dports, other.dports):
            return False
        if not _ports_cover(self.sports, other.sports):
            return False
        if not _nets_cover(self.saddrs, other.saddrs):
            return False
        if not _nets_cover(self.daddrs, other.daddrs):
            return False
        if self.iif is not None and (other.iif is None or not self.iif >= other.iif):
            return False
        if self.oif is not None and (other.oif is None or not self.oif >= other.oif):
            return False
        if self.states is not None and (other.states is None or not self.states <= other.states):
            return False
        if self.icmp is not None and (other.icmp is None or not self.icmp <= other.icmp):
            return False
        return True

    def covers_probe(self, proto, port, iface=None, state="new",
                     addr=None):
        """Does this match admit a probe packet (proto, dport, iface)?
        Rules with conditions we cannot model never cover a probe: the
        answer stays conservative and resolve() reports the skip."""
        if self.opaque:
            return False
        if self.proto and self.proto != proto:
            return False
        if self.dports and not any(lo <= port <= hi for lo, hi in self.dports):
            return False
        if self.iif is not None and (iface is None or iface not in self.iif):
            return False
        if self.saddrs:
            if addr is None:
                return False  # source-restricted: not open to anywhere
            if not any(addr in n for n in self.saddrs):
                return False
        if self.daddrs:
            if addr is None or not any(addr in n for n in self.daddrs):
                return False
        if self.states is not None and state not in self.states:
            return False
        if self.icmp and proto not in ("icmp", "icmpv6"):
            return False
        return True


def _fmt_range(r):
    lo, hi = r
    return str(lo) if lo == hi else "%d-%d" % (lo, hi)


def _ports_cover(sup, sub):
    """sup None = all ports. Every interval of sub must be covered by sup."""
    if sup is None:
        return True
    if sub is None:
        return False
    merged = sorted(sup)
    merged2 = []
    for lo, hi in merged:
        if merged2 and lo <= merged2[-1][1] + 1:
            merged2[-1] = (merged2[-1][0], max(merged2[-1][1], hi))
        else:
            merged2.append((lo, hi))
    for lo, hi in sub:
        if not any(slo <= lo and hi <= shi for slo, shi in merged2):
            return False
    return True


def _nets_cover(sup, sub):
    if sup is None:
        return True
    if sub is None:
        return False
    for net in sub:
        if not any(s.version == net.version and s.supernet_of(net)
                   for s in sup):
            return False
    return True


# --------------------------------------------------------------------------
# ruleset model
# --------------------------------------------------------------------------

@dataclass
class Rule:
    idx: int
    match: Match
    verdict: str          # accept|drop|reject|return|jump|goto|none
    target: str = None    # chain name for jump/goto
    counter: int = None   # packets, if known
    raw: str = ""

    def describe(self):
        v = self.verdict
        if v in ("jump", "goto"):
            v += " -> " + (self.target or "?")
        return "%s  %s" % (self.match.desc(), v)


@dataclass
class Chain:
    table: str
    name: str
    family: str
    hook: str = None      # input|output|forward (None = user chain)
    policy: str = None    # accept|drop for base chains
    dev: str = None
    rules: list = field(default_factory=list)


class Ruleset:
    def __init__(self, source):
        self.source = source
        self.chains = {}  # (table, name) -> Chain

    def chain(self, table, name):
        key = (table, name)
        if key not in self.chains:
            self.chains[key] = Chain(table, name, "?")
        return self.chains[key]

    def expand(self, table, name, depth=0, seen=None):
        """Flatten a chain, inlining jumps (cycle-guarded). Yields
        (owner_chain, rule) pairs so attribution survives inlining."""
        out = []
        ch = self.chains.get((table, name))
        if ch is None or depth > 12:
            return out
        seen = seen or set()
        if (table, name) in seen:
            return out
        seen = seen | {(table, name)}
        for r in ch.rules:
            if r.verdict in ("jump", "goto") and r.target:
                out.extend(self.expand(table, r.target, depth + 1, seen))
                if r.verdict == "goto":
                    break  # goto does not return
            else:
                out.append((ch, r))
                if r.verdict == "return":
                    break  # chain-local terminal: later rules not reached
                           # from this path (conservative at opaque returns)
        return out


# --------------------------------------------------------------------------
# nft JSON parser
# --------------------------------------------------------------------------

def parse_nft_json(doc):
    rs = Ruleset("nft")
    for entry in doc.get("nftables", []):
        if "chain" in entry:
            c = entry["chain"]
            ch = rs.chain(c["table"], c["name"])
            ch.family = c.get("family", "?")
            hook = c.get("hook")
            if isinstance(hook, dict):
                ch.hook = hook.get("hook")
                ch.policy = hook.get("policy", "accept")
                ch.dev = hook.get("dev")
            elif isinstance(hook, str):
                ch.hook = hook
                ch.policy = c.get("policy", "accept")
                ch.dev = c.get("dev")
        elif "rule" in entry:
            r = entry["rule"]
            ch = rs.chain(r["table"], r["chain"])
            if ch.family == "?":
                ch.family = r.get("family", "?")
            m, verdict, target = _nft_exprs(r.get("expr", []))
            cnt = None
            for e in r.get("expr", []):
                if "counter" in e and isinstance(e["counter"], dict):
                    cnt = e["counter"].get("packets")
            rule = Rule(idx=len(ch.rules), match=m, verdict=verdict,
                        target=target, counter=cnt)
            rule.raw = rule.describe()
            ch.rules.append(rule)
    return rs


def _net(value):
    if isinstance(value, str):
        try:
            return ipaddress.ip_network(value, strict=False)
        except ValueError:
            return None
    if isinstance(value, dict) and "prefix" in value:
        p = value["prefix"]
        plen = p.get("prefixlen", p.get("len"))
        try:
            return ipaddress.ip_network("%s/%s" % (p["addr"], plen),
                                        strict=False)
        except (ValueError, KeyError):
            return None
    return None


def _nets(right):
    """Normalize a saddr/daddr match right-hand side to a list of nets."""
    if isinstance(right, list):
        return [n for n in (_net(x) for x in right) if n]
    n = _net(right)
    return [n] if n else []


def _port_set(right):
    """Normalize a dport/sport match right-hand side to intervals."""
    if isinstance(right, int):
        return [(right, right)]
    if isinstance(right, str) and re.fullmatch(r"\d+(-\d+)?", right):
        lo, _, hi = right.partition("-")
        return [(int(lo), int(hi or lo))]
    if isinstance(right, list):
        out = []
        for el in right:
            out.extend(_port_set(el))
        return out or None
    if isinstance(right, dict) and "range" in right:
        rng = right["range"]
        if isinstance(rng, list) and len(rng) == 2:
            return [(int(rng[0]), int(rng[1]))]
    return None


def _nft_exprs(exprs):
    m = Match()
    verdict, target = "none", None
    for e in exprs:
        if "counter" in e or "quota" in e or "log" in e:
            continue
        if "match" in e:
            mt = e["match"]
            op, left, right = mt.get("op"), mt.get("left", {}), mt.get("right")
            if op not in ("==", "in"):
                m.opaque.append("op " + str(op))
                continue
            if isinstance(left, dict) and "payload" in left:
                p = left["payload"]
                proto, fld = p.get("protocol"), p.get("field")
                if fld == "dport":
                    ps = _port_set(right)
                    if ps is None:
                        m.opaque.append("dport?")
                    else:
                        m.proto = proto
                        m.dports = (m.dports or []) + ps if m.dports else ps
                elif fld == "sport":
                    ps = _port_set(right)
                    if ps is None:
                        m.opaque.append("sport?")
                    else:
                        m.proto = proto
                        m.sports = (m.sports or []) + ps if m.sports else ps
                elif fld == "daddr":
                    ns = _nets(right)
                    if ns:
                        m.daddrs = (m.daddrs or []) + ns
                    else:
                        m.opaque.append("daddr?")
                elif fld == "saddr":
                    ns = _nets(right)
                    if ns:
                        m.saddrs = (m.saddrs or []) + ns
                    else:
                        m.opaque.append("saddr?")
                elif fld in ("proto", "nexthdr", "protocol") and \
                        isinstance(right, str):
                    m.proto = right.lower()
                elif fld in ("type", "code") and proto in ("icmp", "icmpv6"):
                    m.proto = proto
                    m.icmp = (m.icmp or set()) | {"%s=%s" % (fld, right)}
                else:
                    m.opaque.append("%s.%s" % (proto, fld))
            elif isinstance(left, dict) and "meta" in left:
                key = left["meta"].get("key")
                if key in ("iifname", "iif") and isinstance(right, str):
                    m.iif = (m.iif or set()) | {right}
                elif key in ("oifname", "oif") and isinstance(right, str):
                    m.oif = (m.oif or set()) | {right}
                elif key in ("iifname", "iif") and isinstance(right, list):
                    m.iif = (m.iif or set()) | set(right)
                elif key in ("oifname", "oif") and isinstance(right, list):
                    m.oif = (m.oif or set()) | set(right)
                else:
                    m.opaque.append("meta." + str(key))
            elif isinstance(left, dict) and "ct" in left:
                if "state" in left["ct"] and isinstance(right, list):
                    m.states = (m.states or set()) | {str(s).lower() for s in right}
                else:
                    m.opaque.append("ct")
            elif isinstance(left, dict) and "fib" in left:
                m.opaque.append("fib")
            else:
                m.opaque.append("match?")
        elif "accept" in e:
            verdict = "accept"
        elif "drop" in e:
            verdict = "drop"
        elif "reject" in e:
            verdict = "reject"
        elif "return" in e:
            verdict = "return"
        elif "jump" in e:
            verdict, target = "jump", e["jump"].get("target")
        elif "goto" in e:
            verdict, target = "goto", e["goto"].get("target")
        elif any(k in e for k in ("set", "add", "update", "delete", "map",
                                  "queue", "notrack", "ct", "numgen", "exthdr")):
            m.opaque.append("stmt")
        else:
            m.opaque.append("expr?")
    return m, verdict, target


# --------------------------------------------------------------------------
# iptables-save parser
# --------------------------------------------------------------------------

def parse_iptables_save(text):
    rs = Ruleset("iptables")
    table = None
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("*"):
            table = line[1:]
            continue
        if line.startswith(":"):
            mch = re.match(r":([\w.-]+)\s+(\S+)", line)
            if mch and table:
                ch = rs.chain(table, mch.group(1))
                ch.family = {"filter": "ip", "nat": "ip",
                             "mangle": "ip"}.get(table, table)
                pol = mch.group(2)
                if pol in ("ACCEPT", "DROP"):
                    ch.policy = pol.lower()
                    ch.hook = {"INPUT": "input", "OUTPUT": "output",
                               "FORWARD": "forward"}.get(mch.group(1))
            continue
        if line.startswith(("-A", "-I", "-C")) and table:
            try:
                toks = shlex.split(line)
            except ValueError:
                continue
            ch = rs.chain(table, toks[1])
            m, verdict, target = _ipt_rule(toks[2:])
            rule = Rule(idx=len(ch.rules), match=m, verdict=verdict,
                        target=target)
            rule.raw = rule.describe()
            ch.rules.append(rule)
    return rs


_IPT_OPT = {
    "-p": "proto", "--protocol": "proto",
    "-s": "saddr", "--source": "saddr",
    "-d": "daddr", "--destination": "daddr",
    "--dport": "dport", "--sport": "sport",
    "-i": "iif", "-o": "oif",
    "-j": "jump", "-g": "goto",
    "-m": "mod",
}


def _ipt_rule(toks):
    m = Match()
    verdict, target = "none", None
    i = 0
    while i < len(toks):
        t = toks[i]
        kind = _IPT_OPT.get(t)
        if kind in ("proto", "saddr", "daddr", "iif", "oif", "jump", "goto") or \
           kind in ("dport", "sport"):
            if i + 1 >= len(toks):
                break
            val = toks[i + 1]
            i += 2
            if kind == "proto":
                m.proto = val.lower()
            elif kind == "saddr":
                m.saddrs = [ipaddress.ip_network(val, strict=False)]
            elif kind == "daddr":
                m.daddrs = [ipaddress.ip_network(val, strict=False)]
            elif kind == "iif":
                m.iif = {val}
            elif kind == "oif":
                m.oif = {val}
            elif kind in ("dport", "sport"):
                ps = _port_set(val)
                if ps:
                    if kind == "dport":
                        m.dports = (m.dports or []) + ps
                    else:
                        m.sports = (m.sports or []) + ps
            elif kind == "jump":
                if val in ("ACCEPT", "DROP", "REJECT", "RETURN"):
                    verdict = val.lower()
                else:
                    verdict, target = "jump", val
            elif kind == "goto":
                verdict, target = "goto", val
            continue
        if t == "-m" and i + 1 < len(toks) and toks[i + 1] == "conntrack":
            # --ctstate follows somewhere in this module's args
            j = i + 2
            while j < len(toks) and not toks[j].startswith("-j"):
                if toks[j] == "--ctstate" and j + 1 < len(toks):
                    m.states = {s.strip().lower()
                                for s in toks[j + 1].split(",")}
                    j += 2
                    continue
                j += 1
            i = j
            continue
        if t == "-m" and i + 1 < len(toks) and toks[i + 1] in ("tcp", "udp"):
            i += 2  # match module marker only; --dport/--sport follow
            continue
        if t == "-m" and i + 1 < len(toks) and toks[i + 1] == "state":
            j = i + 2
            while j < len(toks) and not toks[j].startswith("-j"):
                if toks[j] == "--state" and j + 1 < len(toks):
                    m.states = {s.strip().lower()
                                for s in toks[j + 1].split(",")}
                    j += 2
                    continue
                j += 1
            i = j
            continue
        if t == "-m" and i + 1 < len(toks) and toks[i + 1] == "comment":
            i += 2
            if i < len(toks) and toks[i] == "--comment":
                i += 2
            continue
        if t.startswith("!"):
            m.opaque.append("negation")
            continue
        m.opaque.append(t)
        i += 1
    return m, verdict, target


# --------------------------------------------------------------------------
# loading
# --------------------------------------------------------------------------

def load_ruleset(args):
    if args.file:
        text = sys.stdin.read() if args.file == "-" else open(args.file).read()
    elif args.nft or (not args.iptables):
        try:
            out = subprocess.run(["nft", "-j", "list", "ruleset"],
                                 capture_output=True, text=True, timeout=30)
            if out.returncode == 0 and out.stdout.strip():
                text = out.stdout
                args.nft = True
            else:
                raise FileNotFoundError(out.stderr.strip())
        except FileNotFoundError as exc:
            if args.nft:
                sys.exit("whatfiltered: nft not available: %s" % exc)
            out = subprocess.run(["iptables-save"], capture_output=True,
                                 text=True, timeout=30)
            if out.returncode != 0:
                sys.exit("whatfiltered: neither nft nor iptables-save "
                         "worked (try sudo): %s" % out.stderr.strip())
            text = out.stdout
            args.iptables = True
    else:
        out = subprocess.run(["iptables-save"], capture_output=True,
                             text=True, timeout=30)
        if out.returncode != 0:
            sys.exit("whatfiltered: iptables-save failed (try sudo): %s"
                     % out.stderr.strip())
        text = out.stdout
    if args.iptables or (text.lstrip().startswith("*") or
                         "# Generated by iptables-save" in text[:200]):
        return parse_iptables_save(text)
    try:
        return parse_nft_json(json.loads(text))
    except json.JSONDecodeError:
        return parse_iptables_save(text)


# --------------------------------------------------------------------------
# analysis
# --------------------------------------------------------------------------

def analyze(rs, probes=None, expose=None, addr=None):
    report = {"source": rs.source, "policies": [], "reachable": [],
              "forwarding": [], "shadowed": [], "never_matched": [],
              "probes": [], "listening": []}

    for ch in rs.chains.values():
        if ch.hook:
            report["policies"].append({
                "family": ch.family,
                "table": ch.table, "chain": ch.name, "hook": ch.hook,
                "policy": ch.policy or "accept", "dev": ch.dev})

    for ch in sorted(rs.chains.values(), key=lambda c: (c.table, c.name)):
        if not ch.hook:
            continue
        flat = rs.expand(ch.table, ch.name)
        bucket = "reachable" if ch.hook == "input" else \
                 "forwarding" if ch.hook == "forward" else None
        if bucket:
            for own, r in flat:
                if r.verdict != "accept":
                    continue
                if r.match.states and r.match.states <= RETURN_TRAFFIC:
                    continue  # return traffic, not an inbound opening
                scope = "anywhere"
                if r.match.iif:
                    scope = "iif " + ",".join(sorted(r.match.iif))
                elif r.match.saddrs:
                    scope = "from " + ",".join(str(n) for n in r.match.saddrs)
                elif r.match.opaque:
                    scope = "unclear"
                if r.match.daddrs:
                    scope += " to " + ",".join(str(n)
                                               for n in r.match.daddrs)
                report[bucket].append({
                    "chain": _label(own),
                    "via": _label(ch),
                    "proto": r.match.proto or "any",
                    "ports": [_fmt_range(p) for p in r.match.dports]
                             if r.match.dports else ["all"],
                    "scope": scope,
                    "rule": r.raw})
        # shadowed rules along this hook's flattened path
        for i, (own, r) in enumerate(flat):
            if r.verdict not in TERMINAL or r.match.opaque:
                continue
            for pown, p in flat[:i]:
                if p.verdict not in TERMINAL:
                    continue
                if p.match.shadows(r.match):
                    report["shadowed"].append({
                        "chain": _label(own),
                        "shadowed": "#%d %s" % (r.idx, r.raw),
                        "by": "#%d %s" % (p.idx, p.raw),
                        "note": "different verdict — the later rule can "
                                "never fire" if p.verdict != r.verdict else
                                "same verdict — redundant"})
                    break
        # never matched (nft counters)
        for r in ch.rules:
            if r.counter == 0 and r.verdict in TERMINAL + ("jump",):
                report["never_matched"].append({
                    "chain": _label(ch),
                    "rule": "#%d %s" % (r.idx, r.raw)})

    if probes:
        for p in probes:
            proto, port = p
            verdict, why = resolve(rs, proto, port, addr=addr)
            report["probes"].append({"proto": proto, "port": port,
                                     "verdict": verdict, "why": why})

    if expose:
        for svc in expose:
            port = svc.get("port")
            if not port or not svc.get("listening", True):
                continue
            verdict, why = resolve(rs, "tcp", int(port),
                                          addr=addr)
            report["listening"].append({
                "port": port,
                "process": (svc.get("process") or svc.get("name")
                            or svc.get("engine") or svc.get("cmd") or "?"),
                "verdict": verdict, "why": why})
    return report


def _label(ch):
    return "%s %s/%s" % (ch.family, ch.table, ch.name)


def resolve(rs, proto, port, iface=None, state="new", addr=None):
    """First terminal rule that covers an inbound probe, else policy.
    Rules with unmodelable conditions are skipped and counted so the
    answer is honest about its uncertainty."""
    for ch in rs.chains.values():
        if ch.hook != "input":
            continue
        uncertain = 0
        for own, r in rs.expand(ch.table, ch.name):
            if r.verdict not in TERMINAL:
                continue
            if r.match.opaque:
                uncertain += 1
                continue
            if r.match.covers_probe(proto, port, iface, state, addr):
                note = ""
                if uncertain:
                    note = " (%d uncertain rule%s skipped)" % (
                        uncertain, "" if uncertain == 1 else "s")
                return r.verdict.upper(), "%s #%d %s%s" % (
                    _label(own), r.idx, r.raw, note)
        note = ""
        if uncertain:
            note = " (%d uncertain rule%s skipped)" % (
                uncertain, "" if uncertain == 1 else "s")
        return (ch.policy or "accept").upper(), \
            "%s default policy%s" % (_label(ch), note)
    return "NO-INPUT-CHAIN", "no input hook found"


# --------------------------------------------------------------------------
# rendering
# --------------------------------------------------------------------------

def render(report, tty=True):
    out = []
    w = out.append
    w("whatfiltered %s — read-only firewall exposure audit" % VERSION)

    w("\n== default policies ==")
    for p in report["policies"]:
        dev = " dev " + p["dev"] if p["dev"] else ""
        flag = "  <-- permissive" if p["policy"] == "accept" and \
            p["hook"] == "input" else ""
        w("  %-8s %s %s/%s%s: %s%s" % (p["hook"], p.get("family", "?"),
                                    p["table"], p["chain"],
                                    dev, p["policy"].upper(), flag))

    w("\n== inbound accepts (what is reachable) ==")
    if not report["reachable"]:
        w("  none — no explicit accept rules on any input hook")
    for r in report["reachable"]:
        w("  %-5s %-14s %-10s  %s" % (r["proto"], ",".join(r["ports"]),
                                      r["scope"], r["chain"]))
        w("        rule: %s" % r["rule"])

    if report["forwarding"]:
        w("\n== forwarding accepts (this machine routes for others) ==")
        for r in report["forwarding"]:
            w("  %-5s %-14s %-10s  %s" % (r["proto"], ",".join(r["ports"]),
                                          r["scope"], r["chain"]))

    if report["shadowed"]:
        w("\n== shadowed / dead rules ==")
        for s in report["shadowed"]:
            w("  %s: %s" % (s["chain"], s["note"]))
            w("    dead: %s" % s["shadowed"])
            w("    by : %s" % s["by"])

    if report["never_matched"]:
        w("\n== rules with zero counters (never matched since boot) ==")
        for s in report["never_matched"]:
            w("  %s: %s" % (s["chain"], s["rule"]))

    if report["probes"]:
        w("\n== probes ==")
        for p in report["probes"]:
            w("  %s/%-5s %s   (%s)" % (p["proto"], p["port"],
                                       p["verdict"], p["why"]))

    if report["listening"]:
        w("\n== listening services vs firewall (from whatserved) ==")
        for l in report["listening"]:
            mark = "!!" if l["verdict"] == "ACCEPT" else "  "
            w("  %s tcp/%-5s %-12s %s" % (mark, l["port"], l["verdict"],
                                          l["process"]))
            w("     %s" % l["why"])
    return "\n".join(out)


def main(argv=None):
    ap = argparse.ArgumentParser(
        prog="whatfiltered",
        description="Report what this machine's firewall actually lets "
                    "through. Read-only; stdlib only.")
    ap.add_argument("--file", "-f", help="ruleset file: nft -j list ruleset "
                    "JSON or iptables-save output ('-' for stdin)")
    ap.add_argument("--nft", action="store_true", help="force nft JSON source")
    ap.add_argument("--iptables", action="store_true",
                    help="force iptables-save source")
    ap.add_argument("--probe", help="comma list of ports to resolve, "
                    "e.g. 22,80,8080 (optionally tcp/8080 or udp/53)")
    ap.add_argument("--from", dest="src", metavar="ADDR",
                    help="source address for probes (default: anywhere)")
    ap.add_argument("--expose", help="whatserved --json output file: "
                    "cross-check listening ports against the firewall")
    ap.add_argument("--format", choices=("text", "json"), default="text")
    ap.add_argument("--version", action="version", version=VERSION)
    args = ap.parse_args(argv)

    rs = load_ruleset(args)

    probes = []
    if args.probe:
        for tok in args.probe.split(","):
            tok = tok.strip()
            proto = "tcp"
            if "/" in tok:
                proto, tok = tok.split("/", 1)
            probes.append((proto.lower(), int(tok)))

    expose = None
    if args.expose:
        doc = json.load(open(args.expose))
        expose = doc.get("services", doc if isinstance(doc, list) else [])

    src_addr = None
    if args.src:
        src_addr = ipaddress.ip_address(args.src)
    report = analyze(rs, probes=probes, expose=expose, addr=src_addr)
    if args.format == "json":
        print(json.dumps(report, indent=2))
    else:
        print(render(report))
    return 0


if __name__ == "__main__":
    sys.exit(main())
