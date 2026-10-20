"""``bdosctl`` -- the operator's command line onto the control plane.

Every subcommand is a thin, import-safe wrapper around the same primitives the
daemon uses, so the CLI is fully exercisable in-process by calling
``main([...])``. It mints and verifies safety notices, prints live status,
seals an enclave into a one-way door (behind an m-of-n quorum when the policy
asks for one), checks the control registry, and -- most usefully for demonstrating the
doctrine -- runs a scripted rogue-agent burst through
:meth:`~bdos.controlplane.daemon.ControlPlane.authorize` so the escalating
Lightspeed tax and the eventual Sentinel quarantine can be watched happening.

``bdosctl guard`` is the interposition verb ``os/bin/bdos-exec`` calls: it
evaluates one request, lets the gateway spend any delay, and signals the outcome
purely through its exit code (``0`` allow/delay, ``3`` deny/quarantine).
"""

from __future__ import annotations

import argparse
import json
import os
import socket
import sys
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
from bdos.quorum import ActionRequest, Approval

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
    """Print a snapshot of the live control-plane state.

    If a control-plane socket is configured (``--socket`` / ``$BDOS_SOCKET``) and
    reachable, this reports the *running* server's live state; otherwise it spins
    up a local plane and reports its (fresh) state.
    """
    socket_path = getattr(args, "socket", None) or os.environ.get("BDOS_SOCKET")
    if socket_path:
        try:
            snap = _socket_request(socket_path, {"op": "status"})
        except OSError as exc:
            print(f"status: control plane at {socket_path} unreachable ({exc})", file=sys.stderr)
        else:
            print("BDOS control plane status (live, via socket)")
            print(f"  issuer kid    : {snap.get('issuer_kid')}")
            print(f"  mtd epoch     : {snap.get('mtd_epoch')}")
            print(f"  events logged : {snap.get('events')}")
            print(f"  log intact    : {snap.get('log_intact')}")
            print(f"  quarantined   : {', '.join(snap.get('quarantined', [])) or '(none)'}")
            enclaves = snap.get("enclaves", {})
            if enclaves:
                print("  enclaves:")
                for eid, sealed in enclaves.items():
                    print(f"    - {eid:<16} {'SEALED (one-way)' if sealed else 'open'}")
            return _EXIT_OK

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
    """Seal a named enclave into a one-way door (illustrative, in-memory).

    When the policy sets ``quorum.seal_requires_quorum``, ``--request`` and
    enough ``--approval`` files must be given; otherwise the seal is refused.
    """
    plane = ControlPlane(_load_config(args.config))
    if not any(e.id == args.enclave for e in plane.enclaves):
        known = ", ".join(e.id for e in plane.enclaves) or "(none)"
        print(f"seal: no enclave named {args.enclave!r} (known: {known})")
        return _EXIT_DENY
    request = ActionRequest.from_dict(_read_json(args.request)) if args.request else None
    approvals = [Approval.from_dict(_read_json(path)) for path in args.approval or []]
    verdict = plane.seal(args.enclave, request, approvals)
    if not verdict.allowed:
        print(f"seal refused: {verdict.reason}")
        for line in verdict.metadata.get("rejected", []):
            print(f"  - {line}")
        return _EXIT_DENY
    print(f"sealed enclave {args.enclave!r}: reads still flow in, nothing may change or leave.")
    print("this is a one-way door and cannot be reopened.")
    return _EXIT_OK


def _read_json(path: str) -> dict:
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def _write_json(path: Optional[str], data: dict) -> None:
    text = json.dumps(data, indent=2, sort_keys=True)
    if path:
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(text + "\n")
        print(f"written to {path}")
    else:
        print(text)


def _cmd_quorum_request(args) -> int:
    """Describe one irreversible action so approvers can sign it."""
    request = ActionRequest(
        action=args.action,
        target=args.target,
        reason=args.reason,
        requested_by=args.requested_by,
        created=SystemClock().wall(),
    )
    _write_json(args.out, request.to_dict())
    print(f"# request digest {request.digest}", file=sys.stderr)
    return _EXIT_OK


def _cmd_quorum_approve(args) -> int:
    """Sign a request with one approver's own key."""
    request = ActionRequest.from_dict(_read_json(args.request))
    sk = _key_from_arg(args.key)
    if sk is None:
        print("approve: --key is required", file=sys.stderr)
        return _EXIT_DENY
    print(f"# approving {request.action} on {request.target}: {request.reason}", file=sys.stderr)
    approval = Approval.sign(request, args.approver, sk, SystemClock().wall())
    _write_json(args.out, approval.to_dict())
    return _EXIT_OK


def _cmd_registry(args) -> int:
    """Check a control registry, or print its coverage."""
    import datetime as _dt

    from bdos.core.errors import ConfigError
    from bdos.registry import ERROR, PRINCIPLES, check, coverage, load

    try:
        registry = load(args.file)
    except ConfigError as exc:
        print(f"registry: {exc}")
        return _EXIT_DENY
    today = _dt.date.fromisoformat(args.today) if args.today else None
    if args.registry_command == "coverage":
        cov = coverage(registry, today)
        print(f"controls            : {cov['controls']} ({cov['laws']} laws)")
        bare = cov["principles_without_control"]
        print(f"principles uncovered: {', '.join(f'{p} ({PRINCIPLES[p]})' for p in bare) or '(none)'}")
        detection = cov["effect_classes_detection_only"]
        print(f"detection-only      : {', '.join(detection) or '(none)'}")
        print(f"active exceptions   : {len(cov['active_exceptions'])}")
        for cid, eid, age in cov["active_exceptions"]:
            print(f"  - {cid} / {eid}" + (f" ({age} days old)" if age >= 0 else ""))
        return _EXIT_OK
    findings = check(registry, today)
    for finding in findings:
        print(finding)
    errors = sum(1 for f in findings if f.severity == ERROR)
    print(f"{len(registry.controls)} controls, {errors} errors, {len(findings) - errors} warnings")
    return _EXIT_DENY if errors else _EXIT_OK


def _socket_request(path: str, req: dict) -> dict:
    """Send one JSON request to a running ``bdosd`` and return its reply."""
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
        sock.settimeout(60.0)
        sock.connect(path)
        sock.sendall((json.dumps(req) + "\n").encode())
        reply = sock.makefile("r").readline()
    if not reply:
        raise OSError("empty reply from bdosd")
    return json.loads(reply)


def _cmd_guard(args) -> int:
    """Evaluate one request; signal the outcome via exit code (0 proceed, 3 refuse).

    This is the verb ``os/bin/bdos-exec`` invokes. When a control-plane socket is
    configured (``--socket`` or ``$BDOS_SOCKET``) the request is sent to the
    long-lived ``bdosd`` so throttle/Sentinel/replay state is shared across every
    call on the host -- the only correct way to enforce. If that socket is
    configured but unreachable the guard **fails closed** (exit 3) unless
    ``--local`` is given. With no socket configured it falls back to a local,
    *stateless* plane (a single-shot check that does not accumulate across
    invocations) and says so on stderr.
    """
    socket_path = args.socket or os.environ.get("BDOS_SOCKET")
    req = {
        "op": "authorize",
        "principal": args.principal,
        "kind": args.kind,
        "action_class": args.action_class,
        "resource": args.resource,
        "notice": args.notice or None,
    }

    if socket_path:
        try:
            resp = _socket_request(socket_path, req)
        except OSError as exc:
            if not args.local:
                print(
                    f"guard: control plane at {socket_path} unreachable ({exc}); failing closed",
                    file=sys.stderr,
                )
                return _EXIT_DENY
            print(
                f"guard: {socket_path} unreachable ({exc}); falling back to a local stateless check",
                file=sys.stderr,
            )
        else:
            label = str(resp.get("decision", "deny")).upper()
            print(f"{label}  delay={resp.get('delay_seconds', 0.0):.2f}s  {resp.get('reason', '')}")
            return _EXIT_OK if resp.get("allowed") else _EXIT_DENY

    # Local, stateless fallback: correct for a single request, but state does not
    # persist across invocations -- run `bdosd --serve` for real enforcement.
    print(
        "guard: using a local ephemeral plane (state is NOT shared across calls; "
        "run 'bdosd --serve' for stateful enforcement)",
        file=sys.stderr,
    )
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
    p.add_argument("--socket", help="query a running bdosd (default: $BDOS_SOCKET)")
    p.set_defaults(func=_cmd_status)

    p = sub.add_parser("seal", help="seal an enclave into a one-way door")
    p.add_argument("enclave", help="id of the enclave to seal")
    p.add_argument("--config", help="path to a bdos.toml policy")
    p.add_argument("--request", help="quorum request file (JSON), if the policy requires a quorum")
    p.add_argument("--approval", action="append", help="one approval file (JSON); repeat per approver")
    p.set_defaults(func=_cmd_seal)

    p = sub.add_parser("quorum", help="request or approve an irreversible action")
    qsub = p.add_subparsers(dest="quorum_command", required=True)
    q = qsub.add_parser("request", help="describe an irreversible action for approvers to sign")
    q.add_argument("--action", default="seal")
    q.add_argument("--target", required=True, help="e.g. the enclave id")
    q.add_argument("--reason", required=True)
    q.add_argument("--requested-by", dest="requested_by", required=True)
    q.add_argument("--out", help="write the request here instead of stdout")
    q.set_defaults(func=_cmd_quorum_request)
    q = qsub.add_parser("approve", help="sign a request with your own key")
    q.add_argument("--request", required=True)
    q.add_argument("--approver", required=True, help="your enrolled approver id")
    q.add_argument("--key", required=True, help="your private key (base64 or file path)")
    q.add_argument("--out", help="write the approval here instead of stdout")
    q.set_defaults(func=_cmd_quorum_approve)

    p = sub.add_parser("registry", help="check a control registry (controls.toml)")
    rsub = p.add_subparsers(dest="registry_command", required=True)
    for name, help_text in (("check", "report broken rules (exit 3 on any error)"),
                            ("coverage", "principles left bare, detection-only effect classes")):
        r = rsub.add_parser(name, help=help_text)
        r.add_argument("file")
        r.add_argument("--today", help="evaluate as of this ISO date (default: today)")
        r.set_defaults(func=_cmd_registry)

    p = sub.add_parser("guard", help="evaluate one request (exit 0 allow, 3 deny) -- used by bdos-exec")
    p.add_argument("--principal", required=True)
    p.add_argument("--kind", default="agent", choices=[k.value for k in PrincipalKind])
    p.add_argument("--class", dest="action_class", choices=ACTION_CLASSES, default="write")
    p.add_argument("--resource", default="")
    p.add_argument("--notice", help="an encoded safety notice, if the class requires one")
    p.add_argument("--config", help="path to a bdos.toml policy")
    p.add_argument("--socket", help="bdosd control-plane socket (default: $BDOS_SOCKET)")
    p.add_argument(
        "--local",
        action="store_true",
        help="fall back to a local stateless check if the socket is unreachable (default: fail closed)",
    )
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
