# whatfiltered

[![CI](https://github.com/Kiwi172/whatfiltered/actions/workflows/ci.yml/badge.svg)](https://github.com/Kiwi172/whatfiltered/actions/workflows/ci.yml)

**What does your firewall actually let through?** `whatfiltered` reads your
live nftables or iptables ruleset and answers the question the rule syntax
hides: which ports are reachable, from where, which rules can never fire,
and whether the service you just started is actually exposed. Read-only.
Stdlib only. No account, no upload, no network.

Firewall tools are written for people *writing* rules. `nft list ruleset`
dumps 4,000 lines of jump chains, named sets, and xtables compat stubs;
`iptables -S` prints a flat pile of flags. Neither tells you what a packet
from the internet would actually experience. Commercial rule analyzers
(Tufin, FireMon) do — as enterprise SaaS. Meanwhile the few open-source
"analyzers" are 2014-era visualization toys. `whatfiltered` flattens your
real ruleset — following jumps, inlining user chains, respecting `return`
and `goto` — and resolves the effective verdict per port, per source.

```
  nft -j list ruleset          iptables-save
          |                          |
          +----------> parse <--------+
                        |
              flatten: inline jumps, honor return/goto
                        |
        +---------------+----------------+
        |               |                |
   policies        reachable        shadowed/dead
   per hook       accepts w/       rules that can
                  scope              never fire
                        |
             resolve(port, source) -> ACCEPT | DROP
```

## Install

```sh
git clone https://github.com/Kiwi172/whatfiltered
cd whatfiltered
python3 whatfiltered.py            # audits the live ruleset (sudo for nft)
```

Or `pip install .` for a `whatfiltered` console script. Python ≥ 3.9,
zero dependencies.

## Use

```sh
sudo python3 whatfiltered.py                     # full audit
sudo python3 whatfiltered.py --probe 22,80,8080  # verdict per port
sudo python3 whatfiltered.py --probe 22 --from 10.0.0.5   # from a source
python3 whatfiltered.py -f ruleset.json          # audit a saved ruleset
python3 whatfiltered.py --format json            # machine-readable
```

Pair it with [whatserved](https://github.com/Kiwi172/whatserved) — that
finds what is *listening*, this finds what is *reachable*:

```sh
sudo whatserved --json > served.json
sudo whatfiltered --expose served.json
```

```
== listening services vs firewall (from whatserved) ==
  !! tcp/8080  ACCEPT   LM Studio-style API
     inet filter/input #7 tcp dport 8080  accept
```

Every listening port with an `ACCEPT` is a service the firewall hands to
the network. `!!` marks the ones you should look at first.

## Sample run (real Mullvad kill switch, captured from a VM)

```
== default policies ==
  input    inet mullvad/input: DROP
  forward  inet mullvad/forward: DROP

== inbound accepts (what is reachable) ==
  any   all            iif lo            inet mullvad/input
  udp   68             anywhere          inet mullvad/input
  udp   all            from 45.134.79.67/32  inet mullvad/input   (wg relay)
  any   all            iif wg0-mullvad   inet mullvad/input
  any   all            from 10.0.0.0/8   inet mullvad/input       (LAN allow)

== probes ==
  tcp/22    DROP     (inet mullvad/input default policy)
  tcp/22    ACCEPT   (--from 10.0.2.2: rule "from 10.0.0.0/8 accept")
```

Rules whose conditions the analyzer cannot model (xtables compat stubs,
named sets) are never guessed at: they are skipped and counted, so every
verdict says how uncertain it is — `(2 uncertain rules skipped)`.

## What it can tell you

| signal | how |
|---|---|
| effective verdict per port and source | first terminal rule covering the probe, else hook policy |
| what is reachable, from where | every `accept` on an input hook, with iif/source scope |
| rules that can never fire | shadowed by an earlier terminal rule that matches a superset |
| dead weight | rules with zero packet counters (nft) |
| exposure of running services | `--expose` cross-check against whatserved JSON |
| jump-chain truth | chains flattened; `return`/`goto` respected |

## Tests

```sh
python3 tests/test_whatfiltered.py   # standalone, no pytest needed
pytest -q
```

The suite includes a captured real-world ruleset (Mullvad kill switch) as
a regression fixture: the tool's verdicts must keep matching what the
network actually allows.

## License

MIT
