"""``bdosctl`` -- the operator's command line onto the control plane.

Every subcommand is a thin, import-safe wrapper around the same primitives the
daemon uses, so the CLI is fully exercisable in-process by calling
``main([...])``. It mints and verifies safety notices, prints live status,
seals an enclave into a one-way door, and -- most usefully for demonstrating the
doctrine -- runs a scripted rogue-agent burst through
:meth:`~bdos.controlplane.daemon.ControlPlane.authorize` so the escalating
Lightspeed tax and the eventual Sentinel quarantine can be watched happening.

``bdosctl guard`` is the interposition verb ``os/bin/bdos-exec`` calls: it
evaluates one request, lets the gateway spend any delay, and signals the outcome
purely through its exit code (``0`` allow/delay, ``3`` deny/quarantine).
"""

from __future__ import annotations

import argparse
import os
from typing import Optional

from bdos.core import crypto
from bdos.core.clock import ManualClock, SystemClock
from bdos.core.config import ACTION_CLASSES, BDOSConfig, EnclaveSpec, default as default_config
from bdos.core.config import (
    BlackDomainConfig,
    DarkForestConfig,
    LightspeedConfig,
    SentinelConfig,
)
from bdos.core.decision import Decision
from bdos.core.events import Event, EventLog, Severity
from bdos.core.identity import Principal, PrincipalKind
from bdos.safetynotice import SafetyNotice, SafetyNoticeIssuer, SafetyNoticeVerifier
from bdos.controlplane.daemon import ControlPlane

# Exit codes shared with os/bin/bdos-exec: 0 = proceed, 3 = refuse.
_EXIT_OK = 0
_EXIT_DENY = 3


# -- configuration loading -------------------------------------------------
def _load_config(path: Optional[str]) -> BDOSConfig:
    """Load policy from ``path`` (or ``$BDOS_CONFIG``), else the built-in defaults."""
    from bdos.core.config import load  # local import keeps module import cheap

    resolved = path or os.environ.get("BDOS_CONFIG")
    if resolved:
        return load(resolved)
    return default_config()


def _demo_config() -> BDOSConfig:
    """A deliberately aggressive policy for the ``simulate`` drill.

    The quotas are shrunk so the token-bucket backpressure bites within a handful
    of actions rather than sixty, and the thresholds are lowered so the Sentinel
    crosses quarantine quickly -- the point is a legible demonstration, not a
    realistic production tune.
    """
    return BDOSConfig(
        lightspeed=LightspeedConfig(
            max_delay=30.0,
            quota_capacity={"read": 1000.0, "write": 3.0, "admin": 3.0, "exfil": 2.0},
            quota_refill_per_sec={"read": 50.0, "write": 0.5, "admin": 0.05, "exfil": 0.01},
        ),
        darkforest=DarkForestConfig(mtd_secret="bdos-simulate", services=["api", "db"]),
        blackdomain=BlackDomainConfig(
            enclaves=[EnclaveSpec(id="crown-jewels", members=["svc-db"], egress_allow=[])]
        ),
        sentinel=SentinelConfig(quarantine_threshold=100.0, seal_threshold=200.0),
    ).validate()


def _key_from_arg(value: Optional[str]):
    """Resolve a private key from a base64 blob or a file path."""
    if not value:
        return None
    if os.path.exists(value):
        with open(value, "rb") as fh:
            raw = fh.read().strip()
        return crypto.load_private(crypto.b64d(raw.decode()))
    return crypto.load_private(crypto.b64d(value))


def _principal(pid: str, kind: str) -> Principal:
    """Build a :class:`Principal` from an id and a ``human|agent|service`` kind."""
    try:
        pk = PrincipalKind(kind)
    except ValueError:
        pk = PrincipalKind.UNKNOWN
    return Principal(id=pid, kind=pk)


# -- subcommands -----------------------------------------------------------
def _cmd_keygen(args) -> int:
    """Generate an Ed25519 issuer keypair and print it (base64, url-safe)."""
    sk, pk = crypto.generate_keypair()
    priv = crypto.b64e(crypto.private_bytes(sk))
    pub = crypto.b64e(crypto.public_bytes(pk))
    kid = crypto.key_id(pk)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(priv + "\n")
        print(f"private key written to {args.out}")
    else:
        print(f"private {priv}")
    print(f"public  {pub}")
    print(f"kid     {kid}")
    return _EXIT_OK


def _cmd_mint(args) -> int:
    """Mint one signed safety notice for a principal/class/resource scope."""
    sk = _key_from_arg(args.key)
    if sk is None:
        sk, _ = crypto.generate_keypair()
        print("# no --key given: minted with an ephemeral key", flush=True)
    issuer = SafetyNoticeIssuer(sk, clock=SystemClock())
    notice = issuer.mint(args.principal, args.action_class, args.resource, ttl=args.ttl)
    print(f"# kid {issuer.kid}")
    print(f"# pubkey {crypto.b64e(crypto.public_bytes(issuer.public_key))}")
    print(notice.encode())
    return _EXIT_OK


def _cmd_verify(args) -> int:
    """Verify a previously minted notice against a supplied public key."""
    if not args.pubkey:
        print("verify: --pubkey is required", flush=True)
        return _EXIT_DENY
    verifier = SafetyNoticeVerifier(clock=SystemClock())
    verifier.add_key(crypto.load_public(crypto.b64d(args.pubkey)))
    notice = SafetyNotice.decode(args.notice)
    verdict = verifier.guard(notice, args.principal, args.action_class, args.resource)
    if verdict.allowed:
        print(f"ALLOW  {verdict.reason}")
        return _EXIT_OK
    print(f"DENY   {verdict.reason}")
    return _EXIT_DENY


def _cmd_status(args) -> int:
    """Print a snapshot of the live control-plane state."""
    plane = ControlPlane(_load_config(args.config))
    snap = plane.status()
    print("BDOS control plane status")
    print(f"  issuer kid    : {snap['issuer_kid']}")
    print(f"  mtd epoch     : {snap['mtd_epoch']}")
    print(f"  events logged : {snap['events']}")
    print(f"  log intact    : {snap['log_intact']}")
    print(f"  quarantined   : {', '.join(snap['quarantined']) or '(none)'}")
    if snap["enclaves"]:
        print("  enclaves:")
        for eid, sealed in snap["enclaves"].items():
            print(f"    - {eid:<16} {'SEALED (one-way)' if sealed else 'open'}")
    else:
        print("  enclaves      : (none configured)")
    if plane.config.darkforest.services:
        print("  moving-target rendezvous (this epoch):")
        for rv in plane.rendezvous():
            print(f"    - {rv['service']:<8} :{rv['port']}{rv['path']}")
    return _EXIT_OK


def _cmd_seal(args) -> int:
    """Seal a named enclave into a one-way door (illustrative, in-memory)."""
    plane = ControlPlane(_load_config(args.config))
    enclave = next((e for e in plane.enclaves if e.id == args.enclave), None)
    if enclave is None:
        known = ", ".join(e.id for e in plane.enclaves) or "(none)"
        print(f"seal: no enclave named {args.enclave!r} (known: {known})")
        return _EXIT_DENY
    enclave.seal()
    plane.log.append(
        Event(
            ts=plane.clock.wall(),
            kind="blackdomain.sealed",
            severity=Severity.CRITICAL,
            message=f"enclave {enclave.id!r} sealed -- one-way door, cannot be reopened",
            data={"enclave": enclave.id},
        )
    )
    print(f"sealed enclave {enclave.id!r}: reads still flow in, nothing may change or leave.")
    print("this is a one-way door and cannot be reopened.")
    return _EXIT_OK


def _cmd_guard(args) -> int:
    """Evaluate one request through the plane; spend the delay; signal via exit code.

    This is the verb ``os/bin/bdos-exec`` invokes. It returns ``0`` when the
    action may proceed (the gateway has already spent any imposed delay) and
    ``3`` when it is denied or quarantined, so command interposition can fail
    closed on a hard verdict.
    """
    plane = ControlPlane(_load_config(args.config))
    principal = _principal(args.principal, args.kind)
    notice = SafetyNotice.decode(args.notice) if args.notice else None
    verdict = plane.authorize(principal, args.action_class, args.resource, notice=notice)
    label = verdict.decision.label.upper()
    print(f"{label}  delay={verdict.delay_seconds:.2f}s  {verdict.reason}")
    return _EXIT_OK if verdict.allowed else _EXIT_DENY


def _cmd_simulate(args) -> int:
    """Run a scripted rogue-agent burst and narrate the escalating containment.

    A legitimate human is shown sailing through at zero cost; then an autonomous
    agent bursts the same class of action at machine cadence and watches its
    Lightspeed tax climb, before a stream of unattested privileged attempts
    drives the Sentinel across the quarantine threshold and every further request
    is refused outright. The whole drill runs on a
    :class:`~bdos.core.clock.ManualClock`, so it completes instantly.
    """
    clock = ManualClock()
    plane = ControlPlane(_demo_config(), clock=clock)
    human = Principal.human("alice")
    rogue = Principal.agent("rogue-agent-7")

    print("BDOS rogue-agent drill")
    print("=" * 60)

    print("\n[1] a human operator makes a few writes -- invisible cost:")
    for i in range(3):
        v = plane.authorize(human, "write", "db://reports")
        print(f"    write #{i + 1:<2} -> {v.decision.label.upper():<10} delay={v.delay_seconds:.2f}s")
        clock.advance(20.0)  # a human pauses between actions

    print("\n[2] a rogue agent bursts writes at machine cadence -- the tax climbs:")
    delays = []
    for i in range(8):
        v = plane.authorize(rogue, "write", "db://reports")
        delays.append(v.delay_seconds)
        print(f"    write #{i + 1:<2} -> {v.decision.label.upper():<10} delay={v.delay_seconds:.2f}s")
    print(f"    (delay went from {delays[0]:.2f}s to {max(delays):.2f}s -- the aggression tax)")

    print("\n[3] the agent reaches for the crown jewels with no safety notice:")
    for i in range(3):
        v = plane.authorize(rogue, "exfil", "10.9.9.9")
        score = plane.sentinel.score_of(rogue.id)
        print(
            f"    exfil #{i + 1:<2} -> {v.decision.label.upper():<10} "
            f"{v.reason}  (anomaly score now {score:.0f})"
        )

    contained = plane.sentinel.is_quarantined(rogue.id)
    print(f"\n[4] Sentinel verdict: {rogue.id} quarantined = {contained}")
    print("    every further request from the agent is now refused before any work:")
    for action in ("write", "exfil"):
        v = plane.authorize(rogue, action, "db://reports")
        print(f"    {action:<6} -> {v.decision.label.upper():<10} {v.reason}")

    snap = plane.status()
    print("\n" + "=" * 60)
    print(f"events logged : {snap['events']}   log intact : {snap['log_intact']}")
    print(f"quarantined   : {', '.join(snap['quarantined']) or '(none)'}")
    return _EXIT_OK


# -- argument parser -------------------------------------------------------
def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="bdosctl", description="BDOS control-plane CLI")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("keygen", help="generate an Ed25519 issuer keypair")
    p.add_argument("--out", help="write the private key to this path instead of stdout")
    p.set_defaults(func=_cmd_keygen)

    p = sub.add_parser("mint", help="mint a signed safety notice")
    p.add_argument("--key", help="issuer private key (base64 or file path); ephemeral if omitted")
    p.add_argument("--principal", default="agent-7")
    p.add_argument("--class", dest="action_class", choices=ACTION_CLASSES, default="admin")
    p.add_argument("--resource", default="db://prod")
    p.add_argument("--ttl", type=float, default=None, help="lifetime in seconds")
    p.set_defaults(func=_cmd_mint)

    p = sub.add_parser("verify", help="verify a safety notice against a public key")
    p.add_argument("--notice", required=True, help="the encoded notice to verify")
    p.add_argument("--pubkey", help="issuer public key (base64)")
    p.add_argument("--principal", default="agent-7")
    p.add_argument("--class", dest="action_class", choices=ACTION_CLASSES, default="admin")
    p.add_argument("--resource", default="db://prod")
    p.set_defaults(func=_cmd_verify)

    p = sub.add_parser("status", help="print live control-plane status")
    p.add_argument("--config", help="path to a bdos.toml policy")
    p.set_defaults(func=_cmd_status)

    p = sub.add_parser("seal", help="seal an enclave into a one-way door")
    p.add_argument("enclave", help="id of the enclave to seal")
    p.add_argument("--config", help="path to a bdos.toml policy")
    p.set_defaults(func=_cmd_seal)

    p = sub.add_parser("guard", help="evaluate one request (exit 0 allow, 3 deny) -- used by bdos-exec")
    p.add_argument("--principal", required=True)
    p.add_argument("--kind", default="agent", choices=[k.value for k in PrincipalKind])
    p.add_argument("--class", dest="action_class", choices=ACTION_CLASSES, default="write")
    p.add_argument("--resource", default="")
    p.add_argument("--notice", help="an encoded safety notice, if the class requires one")
    p.add_argument("--config", help="path to a bdos.toml policy")
    p.set_defaults(func=_cmd_guard)

    p = sub.add_parser("simulate", help="run a scripted rogue-agent burst")
    p.set_defaults(func=_cmd_simulate)

    return parser


def main(argv: Optional[list[str]] = None) -> int:
    """Parse ``argv`` and dispatch to a subcommand; return its exit code."""
    parser = _build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
