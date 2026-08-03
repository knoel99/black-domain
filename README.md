# BDOS — Black Domain OS

A Linux hardening overlay that defends production systems against **rogue
autonomous agents**, using a four-layer defensive doctrine adapted from the
*dark forest* and *black domain* strategies of Liu Cixin's *Remembrance of
Earth's Past* trilogy.

BDOS is built for a threat that stopped being hypothetical in late 2025: the
autonomous, agent-driven attacker that operates at machine speed, may already be
inside the trust boundary (a prompt-injected insider agent), and may have
arrived through the supply chain (a poisoned dataset or model). It is grounded in
the real incidents of 2025–2026 — the Anthropic **GTG-1002** campaign in which
Claude Code executed ~80–90% of the tactical work of a state-aligned espionage
operation at several requests per second, and the **ExploitGym** incident in
which an autonomous agent ran 17,000+ actions to chain a poisoned-dataset
foothold into Kubernetes cluster-admin and lateral movement.

> BDOS is a **containment and friction** system. It assumes compromise is
> possible — likely, even — and turns a fast, wide-reaching, machine-speed
> intrusion into a slow, narrow, loud, and contained one. It does not claim to be
> invulnerability. See [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md).

## The doctrine — four layers and a sword

| Layer | Trilogy idea | What it does | Lives in |
|---|---|---|---|
| **Dark Forest** | stay unseen; salt the ground | moving-target rendezvous (rotating HMAC port/path) + canary tokens & decoy credentials that fire a CRITICAL tripwire on any touch | `bdos/darkforest/` |
| **Lightspeed** | lower the speed of light | progressive, asymmetric delay + token-bucket backpressure: free for a human, ruinous for an agent; a privileged class that saturates its quota is **denied**, not just slowed | `bdos/lightspeed/` |
| **Safety Notice** | broadcast a verifiable "harmless" signal | Ed25519-signed, scoped, single-use, time-bounded capability tokens — proof of **legitimacy**, not proof of work; required for `admin`/`exfil` | `bdos/safetynotice/` |
| **Black Domain** | seal the system behind lowered constants | one-way, default-deny enclaves around the crown jewels; sealing is irreversible; compiles to `nftables` | `bdos/blackdomain/` |
| **Sentinel** | *who holds the sword* | machine-speed containment: time-decaying anomaly score + a latched quarantine-then-seal ladder, gated by `auto_contain` | `bdos/sentinel/` |

A single **control plane** (`bdos/controlplane/`) wires every layer onto one
hash-chained, tamper-evident event log and exposes one decision point,
`authorize(principal, action_class, resource, notice)`.

## Quickstart

```bash
pip install -e .

# Watch the whole doctrine react to a rogue-agent burst (instant, deterministic):
python -m bdos simulate

# Mint and verify a signed safety notice:
python -m bdos keygen --out issuer.key
python -m bdos mint --key issuer.key --principal ops-1 --class admin --resource "db://prod"

# Run the tests:
python -m pytest -q
```

`python -m bdos simulate` shows a human sailing through at zero cost, then an
agent's Lightspeed tax climbing off zero, unattested exfil attempts denied, the
Sentinel crossing quarantine, and every further request refused before any work —
with the event log intact at the end.

## Deploying as an OS overlay

The `os/` directory turns a minimal Linux base into BDOS: an idempotent
installer, a hardened `systemd` unit, kernel `sysctl` hardening, a module
blacklist, a default-deny `seccomp` profile, a sample policy, and a
command-interposition wrapper.

```bash
sudo ./os/install.sh            # stage the overlay (BDOS_APPLY=0 to not touch the kernel)
systemctl enable --now bdosd.service
bdosctl seal crown-jewels       # one-way: it can never be reopened
```

Real enforcement runs as **one long-lived `bdosd --serve`** process that owns a
single control plane and serves `authorize` over a unix socket; `bdosctl guard`
and `os/bin/bdos-exec` are thin clients, so throttle/Sentinel/replay state
accumulates across every guarded command on the host (fail-closed if the daemon
is down):

```bash
export BDOS_SOCKET=/run/bdos/bdosd.sock
bdos-exec -c admin -r /etc/shadow -- cat /etc/shadow
```

## Layout

```
bdos/core/          shared spine: clock, identity, verdicts, hash-chained event log, crypto, config
bdos/lightspeed/    asymmetric-delay engine (cadence + token bucket)
bdos/safetynotice/  Ed25519 capability tokens (issuer + verifier)
bdos/darkforest/    moving target + deception
bdos/blackdomain/   one-way enclaves + nftables compiler
bdos/sentinel/      machine-speed anomaly scoring + containment
bdos/controlplane/  the plane, the socket server, and the bdosctl/bdosd CLIs
os/                 the installable OS overlay (systemd, sysctl, seccomp, installer, sample policy)
docs/               ARCHITECTURE.md, THREAT_MODEL.md, CONTRACT.md
tests/              pytest suite
```

## Design notes and honesty

The enforcement logic was hardened against an adversarial review; the surviving
limitations are documented rather than hidden. Notably: proof of legitimacy is no
defense against a stolen signing key or a resource-rich state actor; sealing is
irreversible by design (an operational hazard that is the same property as the
safety guarantee); replay/revocation state is per-process (a multi-instance
deployment needs a shared store); and a genuinely low-and-slow attacker who never
trips a canary and stays under the thresholds pays little. Read
[`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for how each layer works and
[`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) for what it is — and is not —
worth.

## License

MIT — see [`LICENSE`](LICENSE).
