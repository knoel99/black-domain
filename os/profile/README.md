# Building a bootable BDOS image

BDOS is not a kernel; it is a **hardening overlay** that turns a minimal,
already-patched Linux base into a host that treats machine-speed action as
hostile. This directory documents how to bake that overlay into a bootable
image, how the enclaves are sealed on first boot, and why each piece of the
hardening exists. It is the operational companion to
[`docs/ARCHITECTURE.md`](../../docs/ARCHITECTURE.md); read that first for the
doctrine, then this for the build.

The philosophy of the base is stated in ARCHITECTURE.md: *"The base system
provides the substrate -- kernel, init, a small package set, no standing daemons
that are not needed. BDOS provides the doctrine layered on top of it."* So the
image is deliberately small. Everything that is not needed is a syscall, a
module, or a port an attacker can pivot through.


## What the overlay is made of

Everything under `os/` is data; `os/install.sh` is the one program that lays it
down. Building an image is therefore just: bootstrap a minimal rootfs, run
`os/install.sh` inside it, and make it bootable.

| Overlay piece | Installed to | Purpose |
|---|---|---|
| `systemd/bdosd.service` | `/etc/systemd/system/` | the control-plane daemon, run as the unprivileged `bdos` user, hardened with `NoNewPrivileges`, `ProtectSystem=strict`, `MemoryDenyWriteExecute`, an empty `CapabilityBoundingSet`, and a default-deny `SystemCallFilter` |
| `systemd/bdos-sentinel.service` | `/etc/systemd/system/` | the machine-speed containment reflex ("who holds the sword"), isolated in its own even-tighter unit (AF_UNIX only) |
| `sysctl/99-bdos-hardening.conf` | `/etc/sysctl.d/` | kernel hardening (`kptr_restrict`, `dmesg_restrict`, `unprivileged_bpf_disabled`, `kexec_load_disabled`, `yama.ptrace_scope=2`, `rp_filter`, `tcp_syncookies`, redirect/source-route drops, full ASLR) |
| `modprobe.d/bdos-blacklist.conf` | `/etc/modprobe.d/` | blacklists rare/attack-surface modules (`dccp`, `sctp`, `rds`, `tipc`, FireWire/Thunderbolt DMA, exotic protocols and filesystems; `usb-storage` optional) |
| `seccomp/bdos-default.json` | `/etc/bdos/seccomp/` | default-deny (`SCMP_ACT_ERRNO`) seccomp allowlist for the daemons and for `bdos-exec`-wrapped workloads |
| `bin/bdos-exec` | `/usr/local/bin/` | command-interposition wrapper that runs a real command behind the Lightspeed gateway |
| `etc/bdos/bdos.toml` | `/etc/bdos/` | the policy, validated at boot by `bdos.core.config.load` |

The overlay assumes the `bdos` Python package is installed (the installer runs
`pip install` from the repo root unless `BDOS_NO_PIP=1`), which provides the
`bdosd` and `bdosctl` entry points the units and wrapper call.


## Option A -- debootstrap (Debian/Ubuntu base)

`debootstrap` builds a minimal Debian rootfs into a directory you can then
`chroot` into, provision, and turn into an image.

```sh
# 1. Bootstrap a minimal base into a rootfs directory.
sudo debootstrap --variant=minbase \
     --include=systemd,systemd-sysv,ca-certificates,python3,python3-pip,nftables,kmod \
     bookworm ./rootfs http://deb.debian.org/debian

# 2. Bring the BDOS overlay + package source inside the rootfs.
sudo mkdir -p ./rootfs/opt/bdos
sudo cp -a . ./rootfs/opt/bdos          # this repo (contains os/ and the package)

# 3. Enter the rootfs and lay down the overlay.
sudo chroot ./rootfs /bin/bash -eux <<'CHROOT'
    cd /opt/bdos
    # Apply=0: we are in a chroot, so do not poke the *build host's* kernel.
    BDOS_APPLY=0 ./os/install.sh
    systemctl enable bdosd.service bdos-sentinel.service
    # Install a kernel + bootloader for a real image (grub/systemd-boot), set a
    # root password or provisioning key, configure networking, etc.
CHROOT

# 4. Turn the rootfs into a bootable artifact: a disk image (via
#    `virt-make-fs` / `guestfish`), a squashfs for a live/immutable image, or a
#    container base (`tar -C rootfs -c . | ...`).
```

Because `install.sh` is idempotent, you can re-run it to refresh the overlay in
an existing rootfs without rebuilding from scratch.


## Option B -- mkosi (declarative, reproducible)

[`mkosi`](https://github.com/systemd/mkosi) builds reproducible OS images from a
short declarative spec plus scripts. A minimal outline:

```ini
# mkosi.conf
[Distribution]
Distribution=debian
Release=bookworm

[Content]
Packages=systemd,python3,python3-pip,nftables,kmod,ca-certificates
# Immutable, verity-protected root pairs naturally with a sealed system.
Format=disk

[Output]
Bootable=yes
```

```sh
# mkosi.postinst  (runs inside the image during build)
#!/bin/sh
set -eux
cd /opt/bdos
BDOS_APPLY=0 ./os/install.sh
systemctl enable bdosd.service bdos-sentinel.service
```

Point `mkosi` at a copy of this repo under `/opt/bdos` (e.g. via
`mkosi.extra/opt/bdos/`) and run `mkosi build`. An immutable, dm-verity root is
the natural substrate for BDOS: it makes the base itself a read-only black
domain, so the only writable state is the daemon's own `/var/lib/bdos` and the
append-only, hash-chained event log in `/var/log/bdos`.


## First-boot sealing of enclaves

Sealing is a **one-way door** (`Enclave.seal()` sets `sealed`; `unseal()` always
raises `SealedEnclaveError`), so it must happen *after* first-boot provisioning
is complete -- once the crown-jewel enclave is sealed, nothing can write into it
or route out of it again, by design.

The recommended sequence, run once by a first-boot oneshot unit (or by hand):

1. Boot the image; `bdosd` and `bdos-sentinel` start but the crown-jewel enclave
   is still **open** (`sealed = false` in `bdos.toml`), so provisioning can
   populate it.
2. Provision: generate the Safety Notice issuer keypair (`bdosctl keygen`), load
   secrets/data into the enclave's members, run migrations, etc.
3. Set the Dark Forest MTD secret so rendezvous is reproducible across the fleet:
   put a real value in `darkforest.mtd_secret` (an empty value means a fresh
   secret is generated at every boot, which is fine for a single host but breaks
   client rendezvous across a fleet).
4. **Seal** the crown jewels: `bdosctl seal crown-jewels`. From this moment the
   enclave accepts reads inward but refuses every `write`/`admin`/`exfil` and all
   egress, and the door can never be reopened without rebuilding the image.
5. `bdosctl status` to confirm; `bdosctl simulate` to run a rogue-agent burst and
   watch the delays escalate into a quarantine.

A one-shot unit that automates steps 2-4 and then disables itself (`ExecStart`
that ends with `systemctl disable bdos-firstboot.service`) is the clean way to
make sealing part of the image's lifecycle rather than a manual ritual.


## Hardening rationale

Each layer of the overlay removes a category of attacker leverage; the mapping
to the BDOS doctrine and to MITRE ATT&CK is spelled out in
[`docs/ARCHITECTURE.md`](../../docs/ARCHITECTURE.md). In brief:

- **sysctl** closes kernel information leaks (`kptr_restrict`, `dmesg_restrict`),
  removes runtime-persistence and kernel-control primitives
  (`kexec_load_disabled`, `sysrq=0`, `unprivileged_bpf_disabled`), stops
  cross-process credential theft (`yama.ptrace_scope=2`), and hardens the
  network stack against spoofing and reconnaissance (`rp_filter`,
  `tcp_syncookies`, redirect and source-route drops). This is defense in depth
  under the layers: even a foothold finds fewer kernel primitives to pivot on.
- **modprobe blacklist** deletes attack surface wholesale. The autoload path
  (`request_module`) is a classic route from a foothold into a kernel CVE; a
  server has no use for DCCP, SCTP, RDS, TIPC, amateur-radio protocols, FireWire
  or Thunderbolt DMA, or a dozen legacy filesystems, so they are made
  unloadable. `usb-storage` is left commented for hosts that legitimately need
  removable media; uncomment it on kiosks and DMZ boxes to block both malware
  ingress and USB exfiltration.
- **seccomp** is the syscall-level expression of default-deny: the daemons and
  any `bdos-exec`-wrapped workload get exactly the syscalls a well-behaved
  network service needs and nothing else. `setuid`/`setgid` and the whole
  `@privileged`/`@module`/`@raw-io` families are absent, so a compromised process
  cannot escalate through them.
- **systemd sandboxing** enforces the same doctrine at the process boundary:
  `NoNewPrivileges`, an empty `CapabilityBoundingSet`, `ProtectSystem=strict`,
  `MemoryDenyWriteExecute` (W^X, so no injected executable pages), and
  `RestrictAddressFamilies` narrowed to exactly the sockets each daemon uses.
  The Sentinel -- the component allowed to *swing the sword* -- is isolated in
  its own unit, restricted to `AF_UNIX`, so its authority to contain never comes
  with authority to reach the network.

Together the overlay makes the base itself hostile ground to an intruder, so the
four BDOS layers (Lightspeed, Safety Notice, Dark Forest, Black Domain) and the
Sentinel are defending a system that gives an attacker almost nothing to stand
on in the first place.
