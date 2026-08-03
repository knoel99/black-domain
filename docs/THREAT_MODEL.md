# BDOS threat model

This document states, as precisely and as honestly as the design allows, what
BDOS is defending, whom it is defending against, where its trust boundaries lie,
what it does *not* defend against, and the residual risks that survive a correct
deployment. It is a companion to [ARCHITECTURE.md](ARCHITECTURE.md), which
explains how the mechanisms work; here the question is what they are worth.

The guiding principle is the one that motivated the whole project: the modern
adversary is an autonomous or agent-driven attacker that operates at machine
speed, may already be inside the trust boundary (a prompt-injected insider
agent), and may have arrived through the supply chain (a poisoned dataset or
model). BDOS is built to survive that adversary, not to be invulnerable to it. An
honest threat model is therefore mostly a catalogue of where the survival margin
is thin.


## Assets

Ordered roughly by how much BDOS is willing to spend to protect them.

1. **Crown-jewel data and control planes.** The contents of Black Domain
   enclaves: signing keys, customer data, model weights, the Kubernetes/cluster
   control plane, credential stores. The entire architecture is arranged so
   that reaching these is slow, attested, segmented, and -- past a threshold --
   impossible (sealed).
2. **The Safety Notice signing key(s).** The Ed25519 private key(s) held by
   `SafetyNoticeIssuer`. Every legitimacy guarantee in the system reduces to the
   secrecy of these keys. They are a first-class asset in their own right.
3. **The integrity of the event log.** The hash-chained `EventLog` is both the
   audit record and the Sentinel's input. Its *integrity* (tamper-evidence) is
   an asset; note that its *availability and confidentiality* are weaker (see
   residual risks).
4. **The Sentinel's containment authority.** The ability to quarantine and seal
   at machine speed. If an attacker can suppress, mislead, or disable the
   Sentinel, the machine-speed defense is gone even while every other layer still
   appears to function.
5. **The MTD secret.** The `DarkForestConfig.mtd_secret` that makes the moving
   target's schedule unpredictable. Compromise degrades Dark Forest to a static,
   legible system.
6. **Human operator attention.** A scarce, slow, and therefore precious
   resource. BDOS spends it deliberately: canaries and Sentinel escalations are
   designed to be low-false-positive precisely so that an alert is worth a
   human's time.


## Adversaries

BDOS is designed against three overlapping adversary profiles. They are not
mutually exclusive; the worst case is all three at once.

### A. The autonomous / agentic attacker at machine speed
An LLM-driven agent (or fleet of agents) running an offensive campaign with
little or no human intervention -- the GTG-1002 and ExploitGym profile.
Characteristics:
- **Throughput** is its defining advantage: thousands of actions, several per
  second, sustained for hours -- the 17,000+-action ExploitGym campaign, the
  several-per-second GTG-1002 tempo.
- Tireless, patient, and cheap to re-run. It does not get bored, does not fear
  detection the way a human does, and can retry indefinitely.
- **What blunts it:** the Lightspeed layer directly attacks its one advantage
  (speed), turning throughput into an escalating time tax; the Sentinel contains
  it faster than a human could; canaries convert its indiscriminate curiosity
  into detection.

### B. The prompt-injected insider agent
A legitimate agent operating *inside* the trust boundary that has been
subverted by untrusted content -- the lethal-trifecta case. It holds valid
access, so perimeter authentication is already satisfied. The attacker's payload
arrives as data (a document, a web page, a tool result) and redirects the
agent's behaviour.
- It cannot be kept out, because it is already in. The defense must assume the
  actor is authenticated and must constrain what an authenticated-but-subverted
  actor can *do*.
- **What blunts it:** Safety Notice means the injected agent can be *told* to
  perform an admin/exfil action but cannot forge the signature that authorizes
  it; Black Domain removes the outbound leg of the trifecta so read access to
  secrets does not imply the ability to exfiltrate them; Lightspeed and the
  Sentinel bound the damage rate.

### C. The supply-chain adversary
A malicious dataset, model, dependency, or pipeline artifact -- the ExploitGym
entry vector (a poisoned dataset in a data pipeline). The hostile code or data
is *ingested* through a legitimate channel and executes with whatever privileges
that channel carries.
- The compromise is trusted by construction at ingest time; it is not caught by
  authentication because it came in the front door.
- **What blunts it:** Black Domain segmentation confines the ingest pipeline to
  its own enclave so a foothold there cannot reach the control plane; canaries in
  the pipeline's blast radius detect exploration; the Sentinel seals on
  escalation.

### Explicitly out of scope as an adversary
- A **malicious kernel or hypervisor** beneath BDOS. BDOS is an overlay; it
  trusts the base it runs on.
- A **malicious operator with legitimate root** who chooses to disable BDOS.
  BDOS raises the cost and leaves evidence, but a sufficiently privileged insider
  can turn it off (see residual risks).
- **Physical attacks** and side channels against the host hardware.


## Trust boundaries

- **Base OS / kernel (trusted).** BDOS assumes a minimal, patched Linux base
  with an uncompromised kernel, init, and firewall engine. `nftables` actually
  drops what the compiler tells it to; `cgroups`/`tc` actually throttle; the
  clock is not lying. If the base is subverted, BDOS's guarantees do not hold.
- **The core spine (trusted).** `bdos/core/` -- crypto, clock, event log,
  decisions -- is the TCB of the overlay. A bug here is a bug everywhere.
- **The signing key holder (trusted).** Whoever holds the issuer private key is
  trusted to mint only legitimate notices. The verifier trusts any correctly
  signed, in-scope, unexpired, unspent notice.
- **Principals (untrusted, graded).** Humans, agents, and services are all
  untrusted by default and graded by `kind`: agents and services face stricter
  Lightspeed rules than humans, and a "human" that behaves like a script can be
  reclassified. Authentication of the principal itself is *upstream* of BDOS
  (PAM/mTLS/etc.); BDOS governs what an authenticated principal may do.
- **Everything crossing an enclave egress boundary (untrusted).** Default-deny:
  a destination is untrusted unless explicitly allowlisted, and a sealed enclave
  trusts nothing outbound at all.
- **Ingested data and models (untrusted).** Datasets, model weights, tool
  outputs, and web content are treated as hostile input; the design assumes they
  may carry injection or exploit payloads.


## What BDOS defends against

Stated as concrete claims, each traceable to a mechanism:

- **Machine-speed action floods.** Progressive, asymmetric delay plus per-class
  token-bucket backpressure make a several-per-second or 17,000-action campaign
  economically ruinous, while a human at a few actions per minute pays nothing.
- **Unauthorized privileged action.** `admin` and `exfil` require an
  unforgeable, scoped, single-use, time-bounded Safety Notice; a stolen
  credential or a subverted agent cannot manufacture one.
- **Exfiltration and the lethal trifecta's outbound leg.** Black Domain
  default-deny egress and the punishing `exfil` tier mean read access to secrets
  does not confer the ability to send them out; sealing removes the channel
  entirely.
- **Lateral movement and C2.** Enclave segmentation and the compiled `nftables`
  drop policy terminate cross-domain hops and outbound C2 at the boundary.
- **Silent reconnaissance.** Moving-target rendezvous deny a standing map;
  canaries and decoy credentials turn the discovery phase into a high-confidence
  CRITICAL detection.
- **Log tampering.** The hash-chained event log makes silent excision or edit of
  history detectable via `verify()`.
- **Slow human response to a fast attack.** The Sentinel contains autonomously
  (when `auto_contain` is set) in the same call stack as the offending action,
  closing the response-time gap that human-paced incident response cannot.


## What BDOS does NOT defend against

Equally important, and stated without hedging:

- **A compromised base OS, kernel, or firewall engine.** If `nftables` does not
  actually drop, or the kernel is rooted, the overlay's guarantees evaporate.
  BDOS trusts its substrate.
- **Theft or misuse of the signing key.** An attacker who obtains the issuer
  private key can mint valid notices at will; the Safety Notice layer offers no
  protection against a legitimate-looking signature. Key custody (HSM, split
  keys, short-lived issuers) is out of band and out of scope for the code.
- **A malicious privileged operator.** Someone with root can stop the control
  plane, edit config, or replace binaries. BDOS makes this costly and evident,
  not impossible.
- **The initial exploitation of an application bug.** BDOS governs *action rate,
  authorization, and reach*; it is not a memory-safety tool, a WAF, or a
  vulnerability scanner. It bounds what an exploit can *do next*, not whether the
  exploit lands.
- **A patient attacker operating below the thresholds.** An adversary who keeps
  cadence at or under human rate, never trips a canary, and never crosses the
  anomaly threshold pays little Lightspeed tax and does not trigger the Sentinel.
  BDOS raises the price of *speed and noise*, not of patience. Low-and-slow is
  the design's blind spot by construction.
- **Confidentiality of the event log.** The log is tamper-*evident*, not
  tamper-*proof* and not secret. An attacker can read it (learning what BDOS
  sees) and can append or truncate it; what they cannot do is alter history
  without `verify()` noticing. Detection, not prevention.
- **Denial of service via the defense itself.** A false or attacker-induced
  quarantine/seal is an availability event. With `auto_contain` on, an adversary
  who can plausibly *impersonate* a target principal's hostile behaviour might
  provoke BDOS into contain a legitimate actor.
- **Prompt injection at the model layer.** BDOS constrains what a subverted agent
  can *do*; it does nothing to stop the injection itself. The agent's reasoning
  is outside the trust boundary and outside BDOS's reach.


## Residual risks and honest limitations

These survive a correct, complete deployment. They are the price of the design's
shape, not bugs to be fixed.

- **Proof of legitimacy is not proof against a resource-rich state actor.** The
  Safety Notice layer deliberately rejects proof-of-work: burning CPU is exactly
  what a well-funded adversary can afford. But the flip side is that BDOS offers
  *no* work-based deterrent. Against an actor who steals or coerces the signing
  key, or who compromises the issuer host, the legitimacy guarantee is only as
  strong as the key custody -- which BDOS does not provide. A state actor with the
  key is indistinguishable from the legitimate issuer.
- **The airgap-style guarantee has a productivity cost.** Black Domain sealing is
  a genuine one-way door: reads in, nothing out, nothing changed. That is exactly
  as inconvenient as it sounds. A sealed enclave cannot be patched, cannot push
  results, cannot participate in a workflow that needs to write. Sealing trades
  the enclave's usefulness for its safety, and the more of the system is
  protected this way, the more of the system stops doing useful work. Deployments
  must decide, per enclave, where on that curve to sit.
- **Sealing is irreversible.** `unseal()` always raises `SealedEnclaveError` by
  design -- a black domain that could be reopened is not a black domain. This
  means an erroneous or attacker-provoked seal is *permanent* for that enclave
  instance; recovery requires provisioning a fresh enclave and migrating, not
  flipping a switch. The safety property and the operational hazard are the same
  property. This is the sharpest argument for `auto_contain = False` in
  environments where a wrongful seal is more expensive than a slow human
  response.
- **Who holds the sword is an unavoidable trade, not a solved problem.** With
  `auto_contain` on, BDOS can contain a machine-speed attacker in milliseconds --
  and can also self-inflict a permanent seal on a false positive. With it off, no
  false-positive seal can occur -- and a real machine-speed attacker may finish
  before the human confirms. There is no setting that gives both machine-speed
  containment and zero autonomous action; the choice is a policy decision the
  operator must own, and BDOS only guarantees that the decision is explicit and
  logged.
- **Thresholds and scores are tunable, therefore fallible.** The anomaly weights
  (canary 80, rejection 40, capped 15), the decay half-life (300s), and the
  quarantine/seal thresholds (100/200) are heuristics. Set them too tight and
  legitimate bursts trip containment; too loose and an attacker paces under them.
  There is no universally correct setting, and an attacker who learns the
  configuration can operate just beneath it.
- **The MTD secret is a single point of legibility.** If `mtd_secret` leaks, the
  moving target stops moving from the attacker's perspective -- the schedule
  becomes as predictable to them as to a legitimate client. MTD degrades
  gracefully to "no worse than a static system," but no better.
- **Replay and revocation state are process-local.** The Safety Notice verifier
  remembers spent nonces and revocations *in memory*, in one process. A spent
  nonce is kept until its window closes (so it can never be replayed while still
  valid) and the cache *fails closed* if it ever fills with live nonces rather
  than silently forgetting one -- but that failure mode is itself an availability
  lever, and, more importantly, a second verifier instance or a restarted one
  does not share this state. A deployment that runs more than one verifier, or
  must survive restarts without a replay gap, has to back the nonce/revocation
  store with a shared, durable service (e.g. Redis keyed by nonce with a TTL of
  `not_after + clock_skew`). BDOS ships the correct single-process semantics, not
  the distributed store.
- **Containment state is sticky, and stickiness has a memory cost under
  id-rotation.** A quarantined or canary-flagged principal is never forgotten
  (forgetting an attacker would let them back in), so an adversary who rotates
  principal ids *and* trips a canary on each one can grow the quarantine set
  without bound. The design's answer is deliberate: non-sticky per-principal
  state is LRU-bounded, and the defense against id-rotation shifts to the
  *enclave aggregate* -- hostile pressure against a protected enclave is summed
  across all principals and seals the enclave once it crosses a threshold, a
  bound set by the (small, fixed) number of enclaves rather than the (unbounded)
  number of ids an attacker can invent. The residual is that the quarantine set
  itself is bounded only by the number of *real* escalations plus whatever churn
  an attacker is willing to pay a canary trip for.
- **A seal is durable only if the policy is persisted.** Sealing is one-way in
  memory and is reflected back onto the enclave spec, but surviving a host
  restart requires the operator to persist the updated policy (write
  `sealed = true` to `bdos.toml`). Until that is done, a restart of `bdosd`
  reopens an enclave the Sentinel had sealed at runtime. The one-way guarantee is
  absolute within a process lifetime; across restarts it is only as strong as
  policy persistence.
- **Stateful enforcement requires the running daemon.** Throttle cadence,
  Sentinel scores, and the replay cache live inside one long-lived `bdosd`
  process; `bdosctl guard` / `bdos-exec` are thin clients that must reach it over
  its unix socket for that state to accumulate across commands. Run standalone
  (no socket configured), each invocation is an isolated, stateless check -- still
  correct for a single decision, but with no cross-command memory. When a socket
  *is* configured and the daemon is down, the guard fails closed (refuses) rather
  than silently degrade; a wrongly-configured or crashed daemon is therefore an
  availability event, which is the intended direction to fail but an availability
  risk nonetheless.
- **Do not rely on the attacker being unreliable.** The GTG-1002 campaign was
  partially blunted because the agent *hallucinated* -- overstating findings,
  claiming credentials that did not work. That was luck, not defense: it is an
  artifact of current model limitations, it is shrinking with each model
  generation, and it will not be present in a capable adversary. BDOS is designed
  as though every attacking agent is accurate, calibrated, and never fabricates.
  Any margin gained from attacker hallucination is a bonus the design does not
  count on and no deployment should.
- **BDOS narrows blast radius; it does not guarantee prevention.** The honest
  summary is that BDOS is a *containment and friction* system. It assumes
  compromise is possible -- likely, even -- and invests in making a fast,
  wide-reaching, machine-speed intrusion into a slow, narrow, loud, and
  contained one. That is a meaningful improvement against the 2025-2026 adversary.
  It is not, and does not claim to be, invulnerability.
