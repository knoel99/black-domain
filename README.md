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

The repository also holds the doctrinal counterpart of BDOS: a long-form essay,
in French, on the black domain concept and the transposition of its principles
to cyber defence. See [the essay section](#essai--le-domaine-noir-et-la-cyberdéfense) below.

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

Two organisation-level pieces sit on top of the layers:

- **Quorum** (`bdos/quorum/`): with `quorum.seal_requires_quorum`, sealing an
  enclave needs `m` distinct Ed25519-signed approvals and a deliberate delay
  after quorum is reached; the Sentinel then quarantines on its own but only
  recommends the seal. *The key must not be a person.*
- **Control registry** (`bdos/registry/`): every control states its scar, the
  weapon it assumes, who can lift it and how a third party checks it;
  `bdosctl registry check` refuses a "law" a compromised admin can lift, an
  irreversible control in one hand, an expired exception.

## Quickstart

```bash
pip install -e .

# Watch the whole doctrine react to a rogue-agent burst (instant, deterministic):
python -m bdos simulate

# Mint and verify a signed safety notice:
python -m bdos keygen --out issuer.key
python -m bdos mint --key issuer.key --principal ops-1 --class admin --resource "db://prod"

# Check the sample control registry (two defects are planted on purpose):
python -m bdos.controlplane.cli registry check os/etc/bdos/controls.toml

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
bdos/quorum/        m-of-n signed approvals + deliberate delay in front of irreversible actions
bdos/registry/      control registry (TOML) and its checker
bdos/controlplane/  the plane, the socket server, and the bdosctl/bdosd CLIs
os/                 the installable OS overlay (systemd, sysctl, seccomp, installer, sample policy)
docs/               ARCHITECTURE.md, THREAT_MODEL.md, CONTRACT.md, the French essay and its application architecture (see below)
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

## Essai : « Le domaine noir et la cyberdéfense »

Réflexion, en français, sur le **domaine noir** (黑域, *black domain*) de Liu
Cixin et sur ce que ses principes apportent à la cyberdéfense. Dans *La Mort
immortelle*, une civilisation abaisse la vitesse de la lumière autour de son
étoile au-dessous de la vitesse de libération : plus rien n'en sort, et tout
l'univers peut lire dans cette prison volontaire la preuve qu'elle ne nuira
jamais à personne. L'essai prend l'image au sérieux, non comme un modèle à
construire mais comme une question à poser à chaque système d'information :
**qu'est-ce qui peut en sortir, et qui peut le prouver ?**

- [`docs/domaine-noir-cyberdefense.md`](docs/domaine-noir-cyberdefense.md) :
  l'essai complet.
- [`docs/index.html`](docs/index.html) : la même page en version web autonome
  (utilisable telle quelle avec GitHub Pages, branche `master`, dossier `/docs`).
- [`docs/architecture-applicative.md`](docs/architecture-applicative.md) et sa
  version web [`docs/architecture.html`](docs/architecture.html) : la suite de
  l'essai, une architecture d'applications pour mettre les principes en œuvre
  (cinq plans, onze applications, huit règles, quatre flux, feuille de route),
  avec un premier squelette de code dans `bdos/quorum/` et `bdos/registry/`.

### Plan de l'essai

1. **Pourquoi lire une fiction avec des yeux de défenseur** : ce qu'on gagne (des mécanismes isolés, un vocabulaire), ce qu'on risque (importer les axiomes avec les images), et la méthode suivie.
2. **Le cadre** : les deux axiomes de la sociologie cosmique, la chaîne de suspicion, l'explosion technologique, la forêt sombre ; les trois réponses de l'humanité (projet Bunker, plan Domaine noir, vaisseaux à vitesse-lumière) ; ce que le domaine noir est, ce qu'il coûte et la double inversion qu'il opère.
3. **Treize principes**, chacun en quatre volets (dans la trilogie, transposition, en pratique, où l'analogie casse) et refermé sur une question à poser à son propre système :
   - la sécurité se juge à ce qui sort, pas seulement à ce qui entre ;
   - une loi, pas une règle ; une preuve, pas une promesse ;
   - toute émission est une coordonnée : les Soleils involontaires et les coordonnées secondaires ;
   - une émission ne se rappelle pas : la durée de vie du secret ;
   - « Ne répondez pas ! » : la réponse est l'information ;
   - le sortilège : mesurer la forêt avec un leurre ;
   - sous les intellectrons : suspecter l'instrument, coordonner hors de portée, couper en un seul geste ;
   - la clé ne doit pas être une personne : le Porte-épée, le quorum et la main morte ;
   - le Bunker protégeait d'un photoïde : modèle de menace contre propriété ;
   - deux siècles sans défaite ne prouvent rien : l'adversaire a progressé pendant que vous ne regardiez pas ;
   - ne masse jamais la flotte, et garde un vaisseau qui peut partir ;
   - la chaîne de suspicion se déplace, elle ne s'abolit pas ;
   - le milieu : chaque arme dégrade le commun, et chaque règle est la cicatrice d'une attaque.
4. **Les limites de l'analogie** : quand un actif est réellement dans une forêt sombre et quand il ne l'est pas, ce que « cache-toi bien » fait mal comprendre d'Internet, pourquoi le domaine noir fabrique la vulnérabilité qu'il voulait éviter, et pourquoi la coopération est l'option que l'univers de Liu Cixin n'a pas.
5. **Synthèse** : une grille de lecture « domaine noir » (principe, question, contrôles de référence, indicateur), les quatre postures (s'enfermer, se cacher, dissuader, coopérer), par où commencer, et ce qu'un défenseur devrait retenir et refuser.
6. **Références** : romans, normes et cadres, textes juridiques, incidents et rapports, articles.

### Thèse en bref

La trilogie éclaire la cyberdéfense par une inversion : on protège en contrôlant la sortie plus que l'entrée, et l'on rassure par l'incapacité vérifiable plutôt que par la promesse. Elle décrit avec précision les modes d'échec de la dissuasion, de la surveillance et de la concentration. Mais elle se trompe sur un point décisif : le cyberespace possède ce que l'univers de Liu Cixin n'a pas, des institutions, des preuves partagées et un jeu répété. Lire la forêt sombre jusqu'au bout, c'est aussi apprendre à refuser le domaine noir comme conseil de désespoir.

## License

MIT — see [`LICENSE`](LICENSE).
