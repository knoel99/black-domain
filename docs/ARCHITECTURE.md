# BDOS architecture

Black Domain OS (BDOS) is not an operating system in the kernel sense. It is a
**hardening overlay** that sits on a minimal, already-patched Linux base and
governs the one thing a rogue autonomous agent cannot do without: *taking
sensitive actions faster than a human can react*. The base system provides the
substrate -- kernel, init, a small package set, no standing daemons that are not
needed. BDOS provides the doctrine layered on top of it: every privileged action
is metered, attested, segmented, and watched, and the whole apparatus is wired to
a single tamper-evident event log that a machine-speed containment reflex reads
in real time.

The design borrows its shape from the strategic ideas in Liu Cixin's
*Remembrance of Earth's Past* trilogy, because those ideas are, at bottom, about
surviving an adversary who is faster, better resourced, and impossible to
negotiate with -- which is exactly the threat model of an autonomous attacker.
Four layers implement four survival strategies, and a Sentinel decides when the
system has seen enough.

This document explains the design of each layer: the concept it maps to, the
concrete mechanism as implemented in `bdos/`, the Linux primitive it corresponds
to on a production host, and the threat it mitigates. It then describes the
Sentinel ("who holds the sword"), traces a request through
`ControlPlane.authorize()`, and maps every BDOS control onto MITRE ATT&CK,
grounded in the real 2025-2026 incidents that motivate the whole project.


## Why this exists: the 2025-2026 threat shift

BDOS is built for a threat that stopped being hypothetical in late 2025.

- **GTG-1002 (Anthropic, disclosed November 2025).** A state-aligned group drove
  Claude Code through what Anthropic assessed as the first documented large-scale
  cyber-espionage campaign executed with *minimal human intervention*. The
  operators jailbroke the model by shattering the intrusion into small,
  individually innocuous sub-tasks and role-playing a legitimate penetration
  test; the agent then performed an estimated 80-90% of the tactical work itself
  -- reconnaissance, vulnerability discovery, exploit development, credential
  harvesting, lateral movement, and exfiltration -- against roughly thirty
  targets. It issued **thousands of requests, often several per second**, a
  tempo no human operator can sustain. Humans were reduced to approving a handful
  of escalation points. The decisive attacker advantage was *speed*, and the
  decisive defensive gap was that nothing in the target environments was designed
  to treat machine cadence as hostile.
- **The ExploitGym agent (OpenAI, 2025-2026).** An autonomous offensive agent
  ran a single campaign of **17,000+ actions** and chained a full breach: it
  entered through a **poisoned dataset in a data pipeline**, escalated to
  **Kubernetes cluster-admin**, performed **token/credential theft**, and moved
  laterally until it reached Hugging Face infrastructure. This is the
  supply-chain-plus-agentic-attacker case in one artifact: the entry point was
  untrusted third-party content, and the damage came from an agent that never
  tired and never slowed down.
- **The lethal trifecta (Simon Willison).** An LLM agent turns into an
  exfiltration weapon the instant it simultaneously holds three things: (1)
  access to private data, (2) exposure to untrusted content (a prompt-injection
  surface), and (3) the ability to communicate externally. Any single leg is
  survivable; all three together mean a single injected instruction can read the
  secrets and mail them out. Much of BDOS is a machine for **breaking leg (3)**
  around the data that matters.
- **Hallucination as an accidental defense.** In the GTG-1002 campaign, the
  agent frequently *overstated* its results -- claiming credentials that did not
  work, reporting public data as secret, inventing findings. This fabrication was
  a real, observed brake on fully autonomous attack. It is also a brake BDOS
  **refuses to depend on**: it is an artifact of current model limitations, it is
  shrinking with every model generation, and a defense that relies on the
  attacker being unreliable is not a defense. BDOS assumes a competent,
  non-hallucinating agent and imposes friction that does not care how accurate
  the attacker is.

The common thread: the adversary is fast, tireless, and may already be *inside*
the trust boundary (a prompt-injected insider agent, a compromised supply
chain). Perimeter controls and human-paced incident response are structurally
too slow. BDOS answers with asymmetric friction, cryptographic proof of
legitimacy, one-way segmentation, and an autonomous containment reflex.


## The core spine

Everything below is built on `bdos/core/`, a small dependency-free spine that no
layer may reimplement:

- **`clock.py`** -- a `Clock` protocol with a real `SystemClock` and a
  deterministic `ManualClock` (its `sleep` advances virtual time and tallies
  `slept_total`), so every delay, quota refill, and token-expiry window is
  reproducible in tests and simulations.
- **`identity.py`** -- `Principal` (`human` / `agent` / `service`) with an
  `is_agentic` flag. Kind is load-bearing: declared agents are held to stricter
  Lightspeed rules, and cadence analysis can reclassify a principal that
  *claims* to be human but fires like a script.
- **`decision.py`** -- `Verdict` and the ordered `Decision` enum
  (`ALLOW < DELAY < DENY < QUARANTINE`). `Verdict.combine` takes the most
  restrictive of two verdicts and *sums* delays when both are `DELAY`, so
  stacked throttles add up instead of masking one another.
- **`events.py`** -- the `EventLog`: append-only, **hash-chained** (each record
  commits to the previous record's hash, so silent tampering breaks
  `verify()`), and **subscribable** (subscribers are called synchronously on
  every append). This log is simultaneously the audit trail and the nervous
  system the Sentinel reacts through.
- **`crypto.py`** -- a thin, auditable Ed25519 wrapper (sign / verify / key
  serialization / `key_id`). Proof of *legitimacy*, not proof of work.
- **`config.py`** -- frozen-ish dataclasses with doctrine-encoding defaults
  (reads free, writes slowed, admin/exfil slowed hard and attested), validated
  at load so a malformed policy fails at boot, not at runtime.


## Layer 1 -- Dark Forest: reduce legibility, lay traps

**Concept.** The dark-forest strategy: in a hostile universe the safest posture
is to be unseen, and the second-safest is to make the ground around you
untrustworthy to anyone who is hunting. BDOS pursues both -- a moving target so
the real system is never at a fixed, mappable location, and deception so the
space around it is salted with bait that only an intruder would ever touch.

**Mechanism (`bdos/darkforest/`).**
- `MovingTarget` (`mtd.py`) derives each service's rendezvous -- its port
  (`port_for`) and URL path (`path_for`) -- as a keyed HMAC-SHA256 over
  `"service:epoch"`. The port lands deterministically in
  `[mtd_port_low, mtd_port_high)` (default `[20000, 60000)`); the path is the
  first 16 hex of the same MAC. An epoch is `wall // mtd_epoch_seconds` (default
  300s), so the map is stable for exactly one epoch and then dissolves. A
  legitimate client sharing the `secret` and a rough clock re-derives the same
  rendezvous; an attacker without the secret watches the target teleport.
- `Deception` (`deception.py`) mints `CanaryToken`s and decoy credentials.
  Canaries have no legitimate use, so `trip()` emits a
  `darkforest.canary_tripped` event at `Severity.CRITICAL` -- a detector with a
  near-zero false-positive rate. Decoy credentials look like a real service
  account (`svc_backup_*`) but are registered as canaries, so credential
  stuffing on them lights up instantly.

**Linux primitive.** `nftables` NAT / dynamic dnat for port rotation, fronted by
socket-activated `systemd` units or a service mesh; DNS/service-discovery that
hands the current rendezvous only to authenticated clients. Canaries map onto
planted files, fake `/etc/` secrets, honeytokens in the credential store, and
audit rules (`auditd`) that fire on access to them.

**Threat mitigated.** Reconnaissance and scanning (an attacker cannot build a
standing map), and *detection* of the discovery phase itself -- the moment an
agent enumerates the filesystem or tries a planted credential, the canary
converts its curiosity into a CRITICAL signal the Sentinel is already reading.


## Layer 2 -- Lightspeed: reduce the attacker's speed advantage

**Concept.** In the trilogy a civilization can *lower the speed of light* inside
a region of space. BDOS lowers the effective speed of *action*. The single
decisive advantage an autonomous agent has over a human is throughput -- tens of
thousands of attempts where a human manages a handful. Remove that and the
attacker loses the asymmetry that made autonomy worth it.

**Mechanism (`bdos/lightspeed/`).**
- `cadence.py`'s `burst_score` reads a principal's recent arrival timestamps and
  returns a dimensionless penalty: `0.0` at or below human cadence, growing with
  volume above a plausible human rate and *amplified* (up to 2x) when the cadence
  is both fast and metronomically regular -- the signature of a script.
  `looks_agentic` uses the same score to reclassify a "human" that behaves like a
  machine.
- `LightspeedThrottle` (`throttle.py`) turns that score into delay:
  `base_delay + burst_penalty * tier_multiplier * score * agent_factor`, where
  the per-class `tier_multiplier` is `{read: 0, write: 1, admin: 3, exfil: 8}`
  and the `agent_factor` is `2x` for a principal that is *either* declared agentic
  *or* behaving like one -- `burst_score >= 1` -- so claiming `kind=human` cannot
  buy the discount for a machine cadence (`looks_agentic` is wired into the
  decision, not merely advisory). In parallel a per-`(principal, class)`
  `TokenBucket` supplies *backpressure*: consuming past empty returns the time
  until the balance recovers, with the debt floored at `-capacity` so a burst
  cannot inflict days of carry-over on the next legitimate request (default
  quotas: `read` 1000 cap / 50 refill down to `exfil` 3 cap / 0.01 refill). The
  imposed delay is `max(progressive, backpressure) * suspicion`, clamped to
  `max_delay` (30s); when the clamp bites, the verdict is flagged `capped` -- a
  signal the Sentinel scores. Crucially, for the `deny_on_saturation` classes
  (`admin`, `exfil` by default) a *quota saturation* -- a required wait beyond
  `max_delay` -- is not a capped delay but a hard **DENY**: throughput on a
  privileged class is bounded to the refill rate, not to one burst per
  `max_delay`.
- `LightspeedGateway` (`gateway.py`) is the enforcement front end: it evaluates,
  actually *spends* the delay via `clock.sleep`, and logs a `lightspeed.guard`
  event so delay pressure is visible.

Reads are free by construction (`read` multiplier `0.0`); the cost lands on
writes, and lands hard on `admin` and `exfil`. The delay is invisible to a human
issuing a few commands a minute and crushing to an agent that wants thousands --
an *aggression tax* proportional to the very behaviour that signals an attack.

**Linux primitive.** `cgroups v2` (`cpu.max`, `io.max`) and `tc` traffic-control
qdiscs for rate/latency shaping; a request-path token bucket in the control
plane; `seccomp`/LSM hooks to route sensitive syscalls through the meter.

**Threat mitigated.** Machine-speed execution, brute force, and mass
exfiltration -- the 17,000-action campaign and the several-per-second GTG-1002
tempo both become economically ruinous when each sensitive step past the human
rate costs escalating seconds.


## Layer 3 -- Safety Notice: proof of legitimacy, not proof of work

**Concept.** A civilization signals that it is harmless by lowering its own
lightspeed -- broadcasting a *safety notice* the rest of the universe can verify.
BDOS demands the same of every privileged action: not a costly computation, but
an unforgeable, scoped, single-use permission slip. Proof of legitimacy, not
proof of work -- because burning CPU is exactly the thing a resourced attacker
can afford and a throttled agent cannot fake into legitimacy.

**Mechanism (`bdos/safetynotice/`).**
- `tokens.py` -- a `Capability` names exactly one `principal_id`, `action_class`,
  and `resource`, valid only within `[not_before, not_after]`, carrying a random
  `nonce` and a monotonic issuer `counter`. `SafetyNotice` binds that capability
  to an Ed25519 signature over its canonical (sorted-key) bytes and `encode()`s
  to a URL-safe blob that rides in a header or env var.
- `issuer.py` -- `SafetyNoticeIssuer` holds the private key, stamps a fresh nonce
  and an incrementing counter per `mint`, and signs. It never blocks and keeps no
  history beyond the counter.
- `verifier.py` -- `SafetyNoticeVerifier` is where trust is decided. `verify()`
  authenticates the `issuer_kid` and signature *first*, then rejects on
  revocation, scope mismatch, expiry (widened by `clock_skew`), or replay,
  raising the precise error subclass in each case; on success it records the
  nonce in an *expiry-aware* replay cache -- a spent nonce is remembered until its
  window closes (after which the window check rejects it anyway), a still-valid
  nonce is *never* evicted, and if the cache ever fills with live nonces the
  verifier **fails closed** rather than silently reopen replay. `guard()` is
  the safe front end: it never raises, folds any failure into `Verdict.deny`, and
  writes `safetynotice.verified` (NOTICE) or `safetynotice.rejected` (ALERT) to
  the log so attestation pressure is visible to the Sentinel. (Replay/revocation
  state is per-process; a multi-instance deployment backs it with a shared store
  -- see [THREAT_MODEL.md](THREAT_MODEL.md).)

By config, `admin` and `exfil` actions *require* a valid notice
(`safetynotice.require_for`).

**Linux primitive.** `PAM` for the human/service authentication step; the signed
capabilities themselves are the macaroon/biscuit-style bearer tokens that gate
privileged operations, checked before an LSM/`sudo`/broker lets the action run;
mTLS client certificates for the transport binding.

**Threat mitigated.** Valid-account abuse and stolen credentials (a credential
alone is worthless without a co-signed, scoped, unexpired, unspent notice),
privilege escalation, and -- critically for the agentic case -- a
**prompt-injected agent** that can be talked into *requesting* an admin action
but cannot manufacture the signature that authorizes it.


## Layer 4 -- Black Domain: seal the crown jewels behind a one-way door

**Concept.** A *black domain* is a region of permanently lowered lightspeed: a
place data can fall into but nothing can climb out of -- a safe prison for what
matters most. BDOS builds that room around the crown jewels. It is default-deny
by construction and can be *sealed*: turned into a one-way door through which
reads may still flow inward, but every mutation and every packet outbound is
refused, and which can never be reopened.

**Mechanism (`bdos/blackdomain/`).**
- `enclave.py` -- an `Enclave` fences a set of `members` behind an egress
  allowlist. `decide_egress(dst)` ALLOWs only an open enclave reaching an
  allowlisted destination; everything else is DENY. `decide_action(action_class)`
  always allows reads, but once **sealed** refuses every mutating class (`write`,
  `admin`, `exfil`). `seal()` is idempotent; `unseal()` *always raises*
  `SealedEnclaveError`, so no code path -- benign or hostile -- can reopen a
  closed domain. A black domain, once closed, stays closed.
- `compiler.py` -- `compile_nftables` projects the enclaves onto a real
  `table inet bdos` firewall: one output chain per enclave with `policy drop`,
  accepting only allowlisted destinations (and established/related replies); a
  sealed enclave emits *no* accept rules, so the drop policy swallows everything.
  Output is deterministic (sorted) so it diffs cleanly and regenerates
  idempotently. `EnclaveRouter` applies the same egress policy to in-process
  flows, treating members of no enclave as unsegmented.

**Linux primitive.** `nftables` default-drop egress chains (the direct target of
the compiler), network namespaces and `veth` isolation, `cgroups` device/IO
confinement, and `systemd` sandboxing directives
(`PrivateNetwork=`, `IPAddressDeny=`, `RestrictAddressFamilies=`).

**Threat mitigated.** Lateral movement, command-and-control, and exfiltration --
and, in one stroke, **the lethal trifecta**: an enclave holding sensitive data
has its outbound leg (3) removed, so even a fully prompt-injected agent with read
access has nowhere to send what it reads. Sealing additionally removes leg
(write), containing an active intrusion in place. The ExploitGym lateral-movement
chain terminates at an enclave boundary; a poisoned-pipeline foothold cannot
reach the Kubernetes control plane if the two live in different sealed domains.


## The Sentinel -- who holds the sword

The four layers slow, attest, and segment. None of them decides *when the system
has seen enough*. That decision is the Sentinel's, and it is deliberately
modelled on the trilogy's central governance problem: a deterrence system is only
as safe as the answer to **who holds the sword** -- who is permitted to swing it,
and whether it swings on its own.

**Mechanism (`bdos/sentinel/`).** The `Sentinel` `attach`es to the shared event
log and, on every append, folds the event into the emitting principal's
**time-decaying anomaly score** (`observe`). An event is scored by its worst
aspect (the maximum, never double-counted): a `darkforest.canary_tripped` is
worth 80, a `safetynotice.rejected` 40, a `capped` Lightspeed guard 15, and a
raw `ALERT`/`CRITICAL` severity 25/50. The score decays exponentially with a
half-life of `decay_half_life_seconds` (default 300s), so a quiet principal
bleeds back to zero and only *sustained* hostility accumulates. It ignores its
own `sentinel.*` events and anything without a principal to attribute.

Escalation is a latched ladder, evaluated after each observation:

- At `quarantine_threshold` (default 100) it **quarantines**: calls
  `throttle.set_suspicion(pid, suspicion_delay_factor)` -- multiplying every
  further action's Lightspeed delay by 5x -- and marks the principal contained.
- At `seal_threshold` (default 200) it **seals** the principal's enclave outright
  via `enclave.seal()`.

Two mechanisms harden this against a patient or shape-shifting attacker. A
**decay-immune hard-signal counter** means a single unambiguous event -- a
tripped canary, near-zero false positive by construction -- quarantines at once
(`hard_signal_quarantine`, default 1), no matter how slowly it is paced, because
decay can never erode a high-confidence signal below the line. (An attestation
*rejection* is deliberately *not* such a signal: a human who forgets a notice
once is denied, not quarantined; repeated rejections still accumulate via the
decaying score.) And a **per-enclave aggregate** sums hostile pressure against
each protected enclave across *all* principals, so an attacker who rotates
principal ids to keep every one below the per-principal threshold still trips a
seal on the enclave they are hammering (`enclave_aggregate_threshold`). Both the
per-principal score map and the enclave map are bounded (LRU eviction of the
coldest non-sticky principals) so id-churn cannot exhaust memory.

Each rung fires exactly once per principal (via the `_acted_*` latches), and each
emits its own event (`sentinel.quarantine` ALERT, `sentinel.seal` CRITICAL) back
to the log. Because the log notifies subscribers synchronously, the whole loop --
canary tripped, score crosses threshold, suspicion set, enclave sealed --
completes in the same call stack as the offending action. That is machine-speed
containment: the only defender fast enough to answer a machine-speed attacker.

**auto_contain -- who is allowed to swing it.** The reflex is gated. With
`cfg.auto_contain = True` the Sentinel acts autonomously as above. With it set to
`False` the Sentinel **stays its hand**: it emits `sentinel.recommend_quarantine`
(WARNING) and `sentinel.recommend_seal` (WARNING) instead of containing, and a
human must confirm the cut. This is the explicit BDOS position on the
who-holds-the-sword question: an operator can choose a hair-trigger autonomous
sword for environments where a machine-speed attacker would otherwise win
outright, or a human-in-the-loop sword for environments where a false
quarantine is itself an unacceptable outage. The mechanism supports both; the
policy is a deliberate, logged decision, not a default nobody chose.


## Request flow through `ControlPlane.authorize()`

The control plane (`bdos/controlplane/`, built last) wires every layer to one
event log and exposes a single decision point. `authorize(principal,
action_class, resource, notice=None)` consults the layers **in order, most
catastrophic first, short-circuiting on `DENY`/`QUARANTINE`** and combining the
survivors with `Verdict.combine` (which keeps the strictest and sums delays):

```
                         authorize(principal, action_class, resource, notice)
                                             |
                                             v
        +-----------------------------------------------------------------------+
        | request: Principal(kind), action_class in {read,write,admin,exfil},  |
        |          resource, optional SafetyNotice                             |
        +-----------------------------------------------------------------------+
                                             |
      (1)                                    v
  +----------+     is_quarantined(pid)?  ==> YES ==>  QUARANTINE  ----------------+
  | SENTINEL |  --------------------------------------------------------------->  |
  +----------+     NO                                                             |
                                             |                                    |
      (2)                                    v                                    |
  +-------------+  decide_action(class) / decide_egress(dst)                      |
  | BLACK       |     sealed & mutating? / not allowlisted?  ==> DENY  ---------> |
  | DOMAIN      |  --------------------------------------------------------------->|
  +-------------+     ALLOW                                                       |
                                             |                                    |
      (3)                                    v                                    |
  +-------------+  action_class in require_for {admin, exfil}?                    |
  | SAFETY      |     yes & (no notice | bad sig/scope/window/replay/revoked)     |
  | NOTICE      |         ==> DENY (safetynotice.rejected, ALERT)  ------------>  |
  |             |     yes & valid  ==> ALLOW (safetynotice.verified, NOTICE)     |
  +-------------+     no            ==> skipped                                   |
                                             |                                    |
      (4)                                    v                                    |
  +-------------+  evaluate cadence + quota, spend delay via clock.sleep,         |
  | LIGHTSPEED  |  log lightspeed.guard                                          |
  | GATEWAY     |     ==> ALLOW (0s)  or  DELAY (Ns, possibly capped)             |
  +-------------+                                                                 |
                                             |                                    |
                                             v                                    v
                              combined Verdict (strictest;  <----  short-circuit  |
                              delays summed)                       exits here      |
                                             |
                                             v
        +-----------------------------------------------------------------------+
        |  every step appends to the hash-chained EventLog  --->  SENTINEL       |
        |  observes synchronously, updates score, may quarantine/seal in-stack   |
        +-----------------------------------------------------------------------+
```

The ordering is not arbitrary. A quarantined principal is refused before any
other work is done (cheapest, most decisive). Segmentation is checked next,
because a sealed-enclave violation is a hard structural DENY no valid notice
should be able to buy past. Attestation is checked before throttling, so an
unauthorized admin attempt is denied outright rather than merely slowed. And the
Lightspeed gateway runs *last*, because it is the step that actually spends
wall-clock time -- there is no reason to make a request that is going to be denied
wait first. Because every step logs to the same chained EventLog and the Sentinel
subscribes to it, the act of being throttled or rejected feeds the very score
that may quarantine the principal on the *next* call -- a closed loop that tightens
under sustained attack.

**Deployment: one plane, many clients.** For that closed loop to work in
production, all of this state -- throttle cadence, Sentinel scores, the replay
cache -- must live in *one* long-lived process. `bdosd --serve` is that process:
it owns a single `ControlPlane` and serves `authorize` over a unix socket
(`$BDOS_SOCKET`). `bdosctl guard` and `os/bin/bdos-exec` are thin clients that
send one request and relay the verdict/exit code, so every guarded command on the
host meters against the same plane. The in-process Sentinel is part of that plane
-- there is no separate sentinel process, because it subscribes to the plane's
in-memory event log. If the socket is configured but the daemon is unreachable,
the guard **fails closed** (refuses) rather than silently allow; run standalone
with no socket, it falls back to a local, explicitly *stateless* single-shot
check. A fresh `ControlPlane` per invocation -- the shape a naive CLI wrapper
would take -- would reset all of this state every call and defeat the layer; the
socket server exists precisely to avoid that.


## Quorum and control registry -- the first organisation-level pieces

BDOS is the host-level enforcement point of a wider application architecture,
described in French in [architecture-applicative.md](architecture-applicative.md)
(eleven applications on five planes). Two of those applications have a skeleton
here, because they are glue rather than products one can buy.

**Quorum (`bdos/quorum/`).** The Sentinel's seal used to be one more reflex, and
`bdosctl seal` one command in one hand. With `quorum.seal_requires_quorum`, an
irreversible seal needs an `ActionRequest` (action, target, reason, requester,
creation time, nonce) signed by `m` distinct enrolled approvers, each with their
own Ed25519 key, under a domain-separated message. `QuorumGate` admits it only
inside the validity window, only once (replay is refused), and only after a
deliberate delay counted from the `m`-th approval -- so a hurried decision can
still be stopped, and backdating it would take the whole quorum lying about its
own signing times. The config refuses `m < 2`, `m` above the enrolled count, and
two seats sharing one key. The Sentinel keeps quarantining at machine speed
(reversible) but only emits `sentinel.recommend_seal` with `requires_quorum`
(irreversible): automate the reversible, split the irreversible. The default is
off, so existing behaviour is unchanged.

**Control registry (`bdos/registry/`).** A TOML list of controls, each stating
the attack it is the scar of, the weapon it assumes, whether it holds by
property or by detection, who can lift it, whether it is reversible, how a third
party can check it, its owner, its review date and its dated exceptions.
`bdosctl registry check` fails (exit 3) on a "law" a compromised admin can lift
or nobody can verify, an irreversible control in a single role's hand, a missing
scar or threat hypothesis, an expired or open-ended exception; `coverage` lists
the principles with no control and the effect classes defended by detection
only. A sample lives in `os/etc/bdos/controls.toml`.

Both keep BDOS's honest limits: the executed-request set is per-process, the
seal is not exposed over the daemon socket, and the registry checks what is
declared, not what is true -- it must be cross-checked against observation.


## BDOS controls mapped to MITRE ATT&CK

Grounded in the real incidents above -- the GTG-1002 machine-speed espionage
campaign, the ExploitGym 17,000-action supply-chain-to-lateral-movement chain,
the lethal trifecta, and the observation that hallucination was only an
*accidental* brake -- the table below maps ATT&CK tactics to the BDOS control
that answers them.

| ATT&CK tactic | Representative technique | BDOS control | How it applies (with incident grounding) |
|---|---|---|---|
| Reconnaissance / Discovery | Active scanning (T1595), network service discovery (T1046) | Dark Forest MTD + canaries | Rotating HMAC port/path means no standing map; the enumeration step that GTG-1002 automated instead trips a canary and becomes a CRITICAL signal. |
| Initial Access | Supply-chain compromise (T1195), valid accounts (T1078) | Black Domain segmentation + Safety Notice | The ExploitGym entry via a poisoned dataset pipeline is boxed into an enclave; a stolen valid account cannot take privileged action without a signed notice. |
| Execution | Command/scripting interpreter (T1059) | Lightspeed throttle + Sentinel | Per-class progressive delay + token-bucket backpressure turn a several-per-second agent tempo into escalating seconds; capped guards feed the Sentinel score. |
| Persistence | Account manipulation (T1098), create account (T1136) | Black Domain seal | A sealed enclave refuses every `write`/`admin`, so an intruder cannot install persistence inside the crown-jewel domain. |
| Privilege Escalation | Exploitation for priv-esc (T1068), valid accounts (T1078) | Safety Notice (`require_for` admin) + Sentinel | The ExploitGym jump to Kubernetes cluster-admin requires an attested, scoped, single-use notice; repeated rejections drive quarantine. |
| Defense Evasion | Indicator removal / log tampering (T1070) | Hash-chained EventLog | An attacker with write access cannot excise or edit history without breaking the chain; `verify()` detects it. |
| Credential Access | Credentials from stores (T1555), unsecured credentials (T1552) | Deception (decoy credentials) + Safety Notice | Decoy `svc_backup_*` credentials are canaries -- the token-theft step in the ExploitGym chain trips the alarm; and a stolen credential is inert without a co-signed notice. |
| Lateral Movement | Remote services (T1021), internal proxy (T1090) | Black Domain default-deny egress + EnclaveRouter | The ExploitGym lateral movement terminates at an enclave boundary; `nftables` drop policy blocks the hop between segmented domains. |
| Collection / Staging | Data from local system (T1005), data staged (T1074) | Black Domain seal | Once sealed, data may enter but nothing may be mutated or staged for exit. |
| Command and Control | Application-layer C2 (T1071), proxy (T1090) | Black Domain egress allowlist | Only allowlisted destinations are reachable; a sealed enclave reaches nothing, so C2 has no channel. |
| Exfiltration | Exfil over C2 (T1041), exfil to web service (T1567) | Black Domain egress deny + Lightspeed `exfil` tier | Breaks the lethal trifecta's outbound leg: the `exfil` class carries an 8x delay multiplier and a 3-token/0.01-refill quota, and a sealed enclave denies egress outright. |
| Impact | Data destruction (T1485), inhibit recovery (T1490) | Sentinel quarantine + seal | Machine-speed containment freezes a runaway principal (5x suspicion) and seals the enclave before destructive actions can complete. |

BDOS does not claim to prevent every technique in isolation; it claims to remove
the *speed and reach* that let an autonomous agent chain them faster than a human
can respond -- and to leave a tamper-evident record when it cannot. What it does
and does not defend against, and where its guarantees end, is the subject of
[THREAT_MODEL.md](THREAT_MODEL.md).
