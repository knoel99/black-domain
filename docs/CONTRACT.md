# BDOS internal build contract

This file is the interface spec that every layer is built against. The core
spine (`bdos/core/`) and the reference Lightspeed layer (`bdos/lightspeed/`)
are already implemented and tested; treat them as fixed. Build your layer so
that `python3 -m pytest` passes for the whole repo.

## Environment / how to run tests

- Use `python3 -m pytest tests/test_<yourlayer>.py -q`. The interpreter at
  `/usr/local/bin/python3` has `cryptography` + `cffi` installed.
- The package is installed editable (`pip install -e .`), so `import bdos...`
  works from anywhere.
- Do **not** modify `bdos/core/*`, `bdos/lightspeed/*`, `pyproject.toml`, or
  another layer's files. Only create the files assigned to you.

## Fixed core API (import from here, do not reimplement)

```python
from bdos.core.clock import Clock, SystemClock, ManualClock
#   ManualClock(start_monotonic=0.0, start_wall=1_700_000_000.0)
#   .monotonic() .wall() .sleep(s)  # sleep advances time + records slept_total
#   .advance(s)                     # move time without counting as delay
from bdos.core.identity import Principal, PrincipalKind
#   Principal.human(id, **attrs) / .agent(...) / .service(...)
#   p.id, p.kind, p.attributes, p.is_agentic
from bdos.core.decision import Decision, Verdict
#   Decision.ALLOW < DELAY < DENY < QUARANTINE  (IntEnum; .label -> str)
#   Verdict.allow(reason="", **meta) / .delay(sec, ...) / .deny(...) / .quarantine(...)
#   v.decision, v.delay_seconds, v.reason, v.obligations, v.metadata, v.allowed
#   v.combine(other) -> most restrictive (delays sum when both are DELAY)
from bdos.core.events import Event, EventLog, LogRecord, Severity, GENESIS_HASH
#   Event(ts, kind, severity=Severity.INFO, principal_id="", action_class="",
#         message="", data={})
#   Severity: DEBUG INFO NOTICE WARNING ALERT CRITICAL (IntEnum)
#   EventLog(path=None): .append(event)->LogRecord, .subscribe(fn), .verify()->bool,
#                        .records, .head, len(), iter()
from bdos.core import crypto
#   generate_keypair()->(sk,pk); sign(sk,bytes)->bytes; verify(pk,sig,bytes)->bool
#   public_bytes/private_bytes/load_public/load_private; key_id(pk)->str
#   b64e(bytes)->str; b64d(str)->bytes
from bdos.core.errors import (BDOSError, ConfigError, PolicyViolation,
    AttestationError, ReplayError, ExpiredError, RevokedError, SealedEnclaveError)
from bdos.core.config import (BDOSConfig, LightspeedConfig, SafetyNoticeConfig,
    DarkForestConfig, BlackDomainConfig, EnclaveSpec, SentinelConfig,
    ACTION_CLASSES, default, from_dict, load)
from bdos.lightspeed import LightspeedThrottle, LightspeedGateway, TokenBucket, burst_score
#   LightspeedThrottle(cfg).evaluate(principal, action_class, at)->Verdict
#   .set_suspicion(principal_id, factor) / .clear_suspicion(principal_id)
```

`ACTION_CLASSES == ("read", "write", "admin", "exfil")`.

Every layer that emits events uses a dotted `kind` namespaced by layer, e.g.
`safetynotice.verified`, `darkforest.canary_tripped`, `blackdomain.egress_denied`,
`sentinel.quarantine`.

---

## Layer: Safety Notice  (owner file set: `bdos/safetynotice/`)

Proof of *legitimacy*, not proof of work: Ed25519-signed, non-replayable,
scoped capability tokens. Files: `__init__.py`, `tokens.py`, `issuer.py`,
`verifier.py`. Tests: `tests/test_safetynotice.py`.

- `tokens.py`
  - `@dataclass Capability`: `principal_id:str, action_class:str, resource:str,
    not_before:float, not_after:float, nonce:str, counter:int, issuer_kid:str`.
    Method `canonical()->bytes` (deterministic JSON, sorted keys).
  - `@dataclass SafetyNotice`: `capability:Capability, signature:bytes`.
    `encode()->str` (compact, URL-safe; e.g. b64 of a JSON envelope).
    `@classmethod decode(str)->SafetyNotice`.
- `issuer.py`
  - `SafetyNoticeIssuer(signing_key, clock=None, kid=None)`. `kid` defaults to
    `crypto.key_id(pubkey)`. Holds a monotonic `counter` (starts 0, ++ per mint).
  - `mint(principal_id, action_class, resource, ttl=None, now=None)->SafetyNotice`.
    `nonce` = `crypto.b64e(os.urandom(16))`. `not_before = now - skew?` no: use
    `now`; `not_after = now + (ttl or cfg default 300)`. Sign `capability.canonical()`.
  - `public_key` property.
- `verifier.py`
  - `SafetyNoticeVerifier(clock=None, cfg:SafetyNoticeConfig=None)`.
  - `add_key(pk, kid=None)`, `revoke_nonce(nonce)`, `revoke_key(kid)`.
  - `verify(notice, principal_id, action_class, resource, now=None)->Verdict`:
    ALLOW on success; **raise** the specific error otherwise: `AttestationError`
    (bad signature / unknown kid / scope mismatch), `ExpiredError` (outside
    [not_before-skew, not_after+skew]), `ReplayError` (nonce seen before),
    `RevokedError` (nonce or kid revoked). On success, record nonce in a bounded
    replay cache (size `cfg.replay_cache_size`).
  - `guard(notice, principal_id, action_class, resource, log=None, now=None)->Verdict`:
    never raises; returns `Verdict.deny(reason=...)` on failure and appends a
    `safetynotice.rejected` (Severity.ALERT) event; on success appends
    `safetynotice.verified` (Severity.NOTICE) and returns ALLOW.

Required test coverage: happy path; forged signature; expired; replay; scope
mismatch (wrong action_class/resource/principal); revocation; encode/decode
round-trip.

---

## Layer: Dark Forest  (owner file set: `bdos/darkforest/`)

Reduce legibility (moving target) and lay traps (deception). Files:
`__init__.py`, `mtd.py`, `deception.py`. Tests: `tests/test_darkforest.py`.

- `mtd.py` — `MovingTarget(secret:bytes, cfg:DarkForestConfig, clock=None)`:
  - `epoch(now=None)->int` = `int(wall // cfg.mtd_epoch_seconds)`.
  - `port_for(service:str, epoch:int|None=None)->int` — deterministic HMAC-SHA256
    of `f"{service}:{epoch}"` keyed by `secret`, mapped into
    `[cfg.mtd_port_low, cfg.mtd_port_high)`.
  - `path_for(service:str, epoch:int|None=None)->str` — `/` + first 16 hex of the
    same HMAC.
  - `current(service)->dict` = `{service, epoch, port, path}` for the live epoch.
  - Same service in the same epoch is stable; different epoch generally differs.
- `deception.py`
  - `@dataclass CanaryToken`: `id:str, secret:str, label:str`.
  - `Deception(log:EventLog|None=None, clock=None)`:
    - `mint_canary(label="")->CanaryToken` (random id+secret; registered).
    - `mint_decoy_credential(label="")->dict` (fake-looking username/password/token,
      registered as a canary under the hood).
    - `is_canary(token_id_or_secret)->bool`.
    - `trip(token, context:dict|None=None, principal_id="")->Event` — append a
      `darkforest.canary_tripped` event at `Severity.CRITICAL` and return it. Any
      access to a canary is by definition hostile (near-zero false positives).

Required tests: MTD determinism within an epoch; MTD rotation across epochs;
port in range; canary mint + trip emits CRITICAL event; decoy credential is
recognised as a canary; unknown token is not a canary.

---

## Layer: Black Domain  (owner file set: `bdos/blackdomain/`)

Seal crown-jewel enclaves behind one-way, default-deny segmentation. Files:
`__init__.py`, `enclave.py`, `compiler.py`. Tests: `tests/test_blackdomain.py`.

- `enclave.py` — `Enclave(spec:EnclaveSpec)`:
  - `contains(member:str)->bool`.
  - `decide_egress(dst:str)->Verdict` — ALLOW iff `dst` in `spec.egress_allow`
    (exact match ok) **and** not sealed; else DENY. Sealed => DENY all egress.
  - `decide_action(action_class:str)->Verdict` — if sealed and action_class in
    (`write`,`admin`,`exfil`) => DENY (reason mentions sealed). Reads always ALLOW.
  - `seal()` — set sealed True. Idempotent-safe but one-way: `unseal()` must raise
    `SealedEnclaveError` (a black domain is a one-way door). Emitting is the
    caller's job.
  - `sealed` property.
- `compiler.py`
  - `compile_nftables(enclaves:list[Enclave])->str` — produce a valid-looking
    nftables ruleset string: a `table inet bdos` with per-enclave chains that
    default-drop egress and allow only listed CIDRs/hosts. Deterministic output.
  - `EnclaveRouter(enclaves)`: `enclave_for(member)->Enclave|None`;
    `decide(member, dst)->Verdict` (finds enclave, applies `decide_egress`; if
    member in no enclave, ALLOW with reason "unsegmented").

Required tests: default-deny egress; allowlisted egress; seal blocks writes and
egress; unseal raises; nftables compilation contains each enclave + a drop
policy; router routes members correctly.

---

## Layer: Sentinel  (owner file set: `bdos/sentinel/`)

Machine-speed containment -- "who holds the sword". Files: `__init__.py`,
`sentinel.py`. Tests: `tests/test_sentinel.py`.

- `sentinel.py` — `Sentinel(cfg:SentinelConfig, clock=None, throttle=None,
  enclaves=None, log=None)`:
  - `enclaves` is an optional dict `{principal_id_or_enclave_id: Enclave}` or a
    list of Enclave; keep it simple and documented.
  - Subscribe to a log via `attach(log)` which calls `log.subscribe(self.observe)`.
  - `observe(event:Event)->None`: update a per-principal, time-decaying anomaly
    score. Scoring guide (tune as constants): `darkforest.canary_tripped` = +80;
    `safetynotice.rejected` = +40; a lightspeed event with `data.capped == True`
    = +15; `Severity.ALERT` = +25; `Severity.CRITICAL` = +50; benign INFO = 0.
    Score decays with half-life `cfg.decay_half_life_seconds`.
  - `score_of(principal_id, now=None)->float` (decayed).
  - Escalation ladder, evaluated after each observe:
    - score >= `cfg.quarantine_threshold` => quarantine: if `throttle`, call
      `throttle.set_suspicion(pid, cfg.suspicion_delay_factor)`; mark
      `is_quarantined(pid)` True; append `sentinel.quarantine` (ALERT). If
      `cfg.auto_contain` is False, append `sentinel.recommend_quarantine` (WARNING)
      instead and do NOT actually contain (the human holds the sword).
    - score >= `cfg.seal_threshold` => also seal the associated enclave (if any)
      via `enclave.seal()` and append `sentinel.seal` (CRITICAL) — again gated by
      `auto_contain`.
  - `is_quarantined(pid)->bool`; `quarantined` set.

Required tests: benign events don't quarantine; a canary trip + a couple of
attestation rejections crosses quarantine and sets throttle suspicion; decay
reduces score over time; `auto_contain=False` recommends but does not contain;
crossing seal threshold seals the enclave.

---

## Layer: Control plane  (owner file set: `bdos/controlplane/`) -- built last

Wires every layer together. Files: `__init__.py`, `daemon.py`, `cli.py`. Tests:
`tests/test_controlplane.py`. Implemented after the other layers exist.

- `daemon.py` — `ControlPlane(config:BDOSConfig=None, clock=None, log=None)`:
  builds EventLog, LightspeedThrottle+Gateway, SafetyNoticeIssuer+Verifier,
  MovingTarget, Deception, Enclaves (from config), Sentinel (attached to log).
  - `authorize(principal, action_class, resource, notice=None)->Verdict`:
    combine (in order, short-circuit on DENY/QUARANTINE): Sentinel quarantine
    check -> Black Domain enclave action/egress -> Safety Notice (if action_class
    in `cfg.safetynotice.require_for`, a valid notice is required) -> Lightspeed
    gateway (spends delay). Return the combined Verdict.
  - `main(argv=None)` entrypoint for `bdosd` (can just print status / run a
    simple loop; keep importable and non-blocking under tests).
- `cli.py` — `main(argv=None)` argparse `bdosctl` with subcommands: `keygen`,
  `mint`, `verify`, `status`, `seal <enclave>`, and `simulate` (runs a scripted
  rogue-agent burst through `ControlPlane.authorize` and prints the escalating
  delays + eventual quarantine). Must be import-safe and testable by calling
  `main([...])`.

Required tests: end-to-end authorize for a human (fast allow) vs a rogue agent
burst (delays climb, quarantine fires); a required-attestation admin action is
denied without a notice and allowed with a valid one; `cli.main(["simulate"])`
runs without error.
