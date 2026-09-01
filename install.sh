#!/usr/bin/env sh

# infishark CLI installer for Linux and macOS. Prefers a prebuilt version from GitHub Releases. Otherwise, builds from source with the local Rust toolchain.
#
# curl -fsSL https://cdn.infishark.com/install.sh | sh

set -eu

REPO="infishark/infishark"
BIN=infishark
DEST="${INFISHARK_BIN_DIR:-$HOME/.local/bin}"
OUT="$DEST/$BIN"

say()  { printf '\033[1m==>\033[0m %s\n' "$1"; }
warn() { printf '\033[33mnote:\033[0m %s\n' "$1"; }
die()  { printf '\033[31merror:\033[0m %s\n' "$1" >&2; exit 1; }

assert_bin() {
    [ -f "$1" ] || die "Expected binary missing: $1"
    [ -s "$1" ] || die "Expected binary is empty: $1"
}

sys_dir() {
    if [ "$os" = "Darwin" ]; then
        # /usr/bin is SIP-protected on macOS.
        printf '%s' /usr/local/bin
    else
        printf '%s' /usr/bin
    fi
}

system_link() {
    sysdir="$(sys_dir)"
    sysout="$sysdir/$BIN"
    case "$DEST" in
        "$sysdir"|/usr/bin|/usr/local/bin|/bin) return ;;
    esac
    if [ -L "$sysout" ]; then
        existing="$(readlink "$sysout" 2>/dev/null || true)"
        if [ "$existing" = "$OUT" ]; then
            say "System link already present: $sysout -> $OUT"
            return
        fi
    fi
    case "${INFISHARK_SYSTEM_LINK:-}" in
        0|false|no|N|n) return ;;
        1|true|yes|Y|y) ;;
        *)
            say "Recommended: link $BIN into $sysdir so sudo $BIN works (sudo ignores ~/.local/bin)."
            ans=
            if [ -e /dev/tty ] && printf 'Create %s -> %s? [Y/n] ' "$sysout" "$OUT" >/dev/tty 2>/dev/null; then
                IFS= read -r ans </dev/tty || ans=
            else
                warn "No TTY; skipping system link. Re-run with INFISHARK_SYSTEM_LINK=1 or: sudo ln -sfn \"$OUT\" \"$sysout\""
                return
            fi
            case "$ans" in
                ''|Y|y|yes|YES|Yes) ;;
                *)
                    warn "Skipped. You can add it later with: sudo ln -sfn \"$OUT\" \"$sysout\""
                    return
                    ;;
            esac
            ;;
    esac
    if [ -e "$sysout" ] && [ ! -L "$sysout" ]; then
        warn "$sysout already exists and is not a symlink; not overwriting"
        return
    fi
    say "Linking $sysout -> $OUT"
    if [ "$(id -u)" -eq 0 ]; then
        mkdir -p "$sysdir"
        ln -sfn "$OUT" "$sysout"
    else
        command -v sudo >/dev/null 2>&1 || {
            warn "sudo not found; create the link yourself: ln -sfn \"$OUT\" \"$sysout\""
            return
        }
        sudo mkdir -p "$sysdir"
        sudo ln -sfn "$OUT" "$sysout"
    fi
    say "Linked $sysout -> $OUT"
}

os="$(uname -s)"
arch="$(uname -m)"
case "$os-$arch" in
    Linux-x86_64)  target=x86_64-unknown-linux-gnu ;;
    Linux-aarch64) target=aarch64-unknown-linux-gnu ;;
    Darwin-x86_64) target=x86_64-apple-darwin ;;
    Darwin-arm64)  target=aarch64-apple-darwin ;;
    *)             target="" ;;
esac

mkdir -p "$DEST"

installed=
if [ -n "$target" ]; then
    url="https://github.com/$REPO/releases/latest/download/$BIN-$target.tar.gz"
    tmp="$(mktemp -d)"
    # shellcheck disable=SC2064
    trap 'rm -rf "$tmp"' EXIT
    if curl -fsSL "$url" -o "$tmp/pkg.tar.gz"; then
        say "Installing prebuilt $BIN ($target)"
        tar -xzf "$tmp/pkg.tar.gz" -C "$tmp"
        if [ ! -f "$tmp/$BIN" ] || [ ! -s "$tmp/$BIN" ]; then
            warn "prebuilt archive missing $BIN; trying source build"
        else
            install -m 0755 "$tmp/$BIN" "$OUT"
            assert_bin "$OUT"
            installed=1
        fi
    else
        warn "prebuilt unavailable for $target; trying source build"
    fi
    rm -rf "$tmp"
    trap - EXIT
fi

if [ -z "${installed:-}" ]; then
    command -v cargo >/dev/null 2>&1 \
        || die "No prebuilt binary for ${os}-${arch}, and Rust isn't installed. Install it from https://rustup.rs then re-run."
    if [ "$os" = "Linux" ] && ! pkg-config --exists libudev 2>/dev/null; then
        say "Installing Linux USB deps (libudev, pkg-config)"
        if   command -v apt-get >/dev/null 2>&1; then sudo apt-get install -y pkg-config libudev-dev
        elif command -v dnf     >/dev/null 2>&1; then sudo dnf install -y pkgconf-pkg-config systemd-devel
        elif command -v pacman  >/dev/null 2>&1; then sudo pacman -S --needed --noconfirm pkgconf systemd-libs
        else die "Install pkg-config + libudev-dev manually, then re-run."; fi
    fi
    say "Building $BIN from source"
    cargo install --git "https://github.com/$REPO" infishark-cli --root "$(dirname "$DEST")"
    assert_bin "$OUT"
fi

say "Installed $BIN to $DEST"
case ":$PATH:" in
    *":$DEST:"*) ;;
    *) warn "$DEST is not on your PATH. Add it: export PATH=\"$DEST:\$PATH\"" ;;
esac
system_link
say "Done. Run: $BIN ports"
