#!/usr/bin/env bash
#
# install.sh -- turn a minimal Linux base into BDOS (Black Domain OS).
#
# Installs the bdos Python package and drops the OS overlay into place: systemd
# units, kernel sysctl hardening, a modprobe blacklist, the default-deny seccomp
# profile, the command-interposition wrapper, and a sample policy. It creates an
# unprivileged `bdos` system user for the daemons and prints the next steps.
#
# The script is idempotent: re-running it converges to the same state without
# clobbering anything you have since edited. Destructive steps (overwriting an
# existing policy, applying sysctl live, reloading modules) are guarded and can
# be skipped. Nothing is applied to the running kernel unless you ask for it.
#
# Usage:
#   sudo ./os/install.sh                 # full install + live apply
#   sudo BDOS_APPLY=0 ./os/install.sh    # stage files only, do not touch kernel
#   sudo BDOS_DRY_RUN=1 ./os/install.sh  # print what would happen, change nothing
#   sudo BDOS_NO_PIP=1 ./os/install.sh   # skip the pip install of the package
#
set -euo pipefail

# -- knobs -------------------------------------------------------------------
DRY_RUN="${BDOS_DRY_RUN:-0}"   # 1 => describe actions, make no changes
APPLY="${BDOS_APPLY:-1}"       # 1 => apply sysctl / reload modules on this host
NO_PIP="${BDOS_NO_PIP:-0}"     # 1 => do not pip install the package
BDOS_USER="${BDOS_USER:-bdos}"

# -- layout ------------------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
OS_DIR="$SCRIPT_DIR"

DEST_SYSTEMD="/etc/systemd/system"
DEST_SYSCTL="/etc/sysctl.d"
DEST_MODPROBE="/etc/modprobe.d"
DEST_ETC="/etc/bdos"
DEST_SECCOMP="/etc/bdos/seccomp"
DEST_BIN="/usr/local/bin"
DEST_DOC="/usr/share/doc/bdos"
STATE_DIR="/var/lib/bdos"
LOG_DIR="/var/log/bdos"

# -- helpers -----------------------------------------------------------------
log()  { printf '\033[1;36m[bdos]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[bdos] WARN:\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31m[bdos] ERROR:\033[0m %s\n' "$*" >&2; exit 1; }

# run: echo-and-execute, or just echo under DRY_RUN.
run() {
    if [ "$DRY_RUN" = "1" ]; then
        printf '  would run: %s\n' "$*"
    else
        "$@"
    fi
}

need_root() {
    [ "$DRY_RUN" = "1" ] && return 0
    [ "$(id -u)" -eq 0 ] || die "must run as root (try: sudo $0)"
}

# install_file SRC DEST MODE -- copy a file, creating parents, preserving mode.
install_file() {
    local src="$1" dest="$2" mode="$3"
    [ -f "$src" ] || die "missing source file: $src"
    run install -D -m "$mode" "$src" "$dest"
    log "installed $dest ($mode)"
}

# --------------------------------------------------------------------------
main() {
    need_root
    log "BDOS installer  (repo=$REPO_ROOT dry_run=$DRY_RUN apply=$APPLY)"

    # 1) the bdos system user -- unprivileged, no shell, no home login.
    if id -u "$BDOS_USER" >/dev/null 2>&1; then
        log "user '$BDOS_USER' already exists -- leaving it as is"
    else
        log "creating system user '$BDOS_USER'"
        run useradd --system --no-create-home --shell /usr/sbin/nologin \
            --comment "BDOS control plane" "$BDOS_USER"
    fi

    # 2) state and log directories owned by the daemon user.
    run install -d -m 0750 "$STATE_DIR"
    run install -d -m 0750 "$LOG_DIR"
    if [ "$DRY_RUN" != "1" ]; then
        chown "$BDOS_USER:$BDOS_USER" "$STATE_DIR" "$LOG_DIR"
    fi

    # 3) the Python package (skippable; guarded so it is not required).
    if [ "$NO_PIP" = "1" ]; then
        log "skipping pip install (BDOS_NO_PIP=1)"
    elif command -v python3 >/dev/null 2>&1; then
        log "installing the bdos package from $REPO_ROOT"
        run python3 -m pip install --upgrade "$REPO_ROOT"
    else
        warn "python3 not found -- skipping package install; do it manually later"
    fi

    # 4) systemd unit. The Sentinel is not a separate service -- it runs
    #    in-process inside bdosd (it subscribes to the plane's in-memory log).
    install_file "$OS_DIR/systemd/bdosd.service"         "$DEST_SYSTEMD/bdosd.service"         0644

    # 5) kernel hardening + module blacklist + seccomp profile.
    install_file "$OS_DIR/sysctl/99-bdos-hardening.conf" "$DEST_SYSCTL/99-bdos-hardening.conf" 0644
    install_file "$OS_DIR/modprobe.d/bdos-blacklist.conf" "$DEST_MODPROBE/bdos-blacklist.conf" 0644
    install_file "$OS_DIR/seccomp/bdos-default.json"      "$DEST_SECCOMP/bdos-default.json"     0644

    # 6) command-interposition wrapper.
    install_file "$OS_DIR/bin/bdos-exec" "$DEST_BIN/bdos-exec" 0755

    # 7) documentation for the units' Documentation= line.
    for doc in ARCHITECTURE.md CONTRACT.md THREAT_MODEL.md; do
        [ -f "$REPO_ROOT/docs/$doc" ] && install_file "$REPO_ROOT/docs/$doc" "$DEST_DOC/$doc" 0644
    done

    # 8) sample policy -- NEVER overwrite an operator's edited config.
    run install -d -m 0755 "$DEST_ETC"
    if [ -f "$DEST_ETC/bdos.toml" ]; then
        warn "$DEST_ETC/bdos.toml exists -- keeping it; sample staged as bdos.toml.sample"
        install_file "$OS_DIR/etc/bdos/bdos.toml" "$DEST_ETC/bdos.toml.sample" 0644
    else
        install_file "$OS_DIR/etc/bdos/bdos.toml" "$DEST_ETC/bdos.toml" 0644
    fi

    # 9) validate the installed policy actually loads (fail fast at install time).
    if [ "$DRY_RUN" != "1" ] && command -v python3 >/dev/null 2>&1; then
        if python3 -c "import bdos.core.config" >/dev/null 2>&1; then
            if python3 -c "from bdos.core.config import load; load('$DEST_ETC/bdos.toml')" >/dev/null 2>&1; then
                log "policy $DEST_ETC/bdos.toml validated"
            else
                warn "policy $DEST_ETC/bdos.toml FAILED validation -- review before starting bdosd"
            fi
        else
            warn "bdos not importable yet -- skipping policy validation"
        fi
    fi

    # 10) apply to the running kernel (guarded).
    if [ "$APPLY" = "1" ]; then
        if command -v systemctl >/dev/null 2>&1; then
            log "reloading systemd unit definitions"
            run systemctl daemon-reload
        else
            warn "systemctl not found -- skipping daemon-reload"
        fi
        if command -v sysctl >/dev/null 2>&1; then
            log "applying sysctl hardening live"
            run sysctl --system >/dev/null || warn "some sysctl keys were rejected by this kernel"
        else
            warn "sysctl not found -- skipping live apply"
        fi
        if command -v depmod >/dev/null 2>&1; then
            log "refreshing module dependency map for the blacklist"
            run depmod -a || warn "depmod failed -- blacklist applies on next boot"
        fi
    else
        log "BDOS_APPLY=0 -- files staged but not applied to the running kernel"
    fi

    print_next_steps
}

print_next_steps() {
    cat <<'EOF'

BDOS overlay staged. Next steps:

  1. Review the policy:            $EDITOR /etc/bdos/bdos.toml
  2. Generate the issuer keypair:  bdosctl keygen
  3. Enable the enforcement daemon (the Sentinel runs inside it):
         systemctl enable --now bdosd.service
  4. Seal the crown-jewel enclave once first-boot provisioning is done:
         bdosctl seal crown-jewels          # one-way: it can never be reopened
  5. Sanity check:                 bdosctl status
  6. Run a rogue-agent drill:      bdosctl simulate

  Interpose a sensitive command through the running control plane with:
         export BDOS_SOCKET=/run/bdos/bdosd.sock
         bdos-exec -c admin -r /etc/shadow -- cat /etc/shadow
  (bdos-exec/bdosctl guard connect to that socket so throttle + Sentinel state
   is shared across every command; without a running bdosd they fail closed.)

  Hardening applied: sysctl (/etc/sysctl.d/99-bdos-hardening.conf),
  module blacklist (/etc/modprobe.d/bdos-blacklist.conf), and the default-deny
  seccomp profile (/etc/bdos/seccomp/bdos-default.json). A reboot is recommended
  so the module blacklist and every sysctl take effect from a clean state.

EOF
}

main "$@"
