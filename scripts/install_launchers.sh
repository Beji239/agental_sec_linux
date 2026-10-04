#!/usr/bin/env bash
# scripts/install_launchers.sh
# Install the two desktop launchers, their icons, and the Start Menu entries.
#
# WHAT THIS PUTS WHERE, AND WHY EACH LOCATION
#
#   ~/.local/share/applications/agentalsec.desktop
#   ~/.local/share/applications/agentalsec-privileged.desktop
#       The Start Menu entries. Per-USER (not /usr/share) because the app
#       runs as you and its database, config and log live in this project
#       folder. A system-wide entry would offer the launcher to other
#       accounts that cannot use it.
#
#   ~/.local/share/icons/hicolor/<size>x<size>/apps/agentalsec*.png
#       The icon theme copy, so the launcher grid, the window list, Alt-Tab
#       and the panel all find a properly sized PNG. The .desktop also names
#       an absolute path to the .ico as a fallback, because icon-theme
#       caching on Cinnamon can lag a fresh install by a few seconds and a
#       launcher with a blank icon looks broken.
#
#   ~/Desktop/*.desktop
#       The two launchers on the desktop itself, marked executable and
#       trusted, which Nemo requires before it will RUN one rather than open
#       it in a text editor.
#
#   $APP_DIR/*.desktop        <- THE PROJECT FOLDER
#       The same two launchers, inside the project folder itself. A .ico is
#       a picture, and clicking one opens an image viewer, so the folder gets
#       real launchers whose Icon= points at the artwork.
#
# Run it again any time; it is idempotent and rewrites every entry.

set -uo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# Derived from where this script sits, so the installer works wherever the
# project was cloned. The artwork ships in assets/logo.
LOGO_DIR="$PROJECT_ROOT/assets/logo"
APP_DIR="$PROJECT_ROOT"
LAUNCH="$PROJECT_ROOT/scripts/agental_sec_launch.sh"

say() { printf '%s\n' "$*"; }
die() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }

[[ -f "$LAUNCH" ]] || die "missing $LAUNCH"
chmod +x "$LAUNCH" "$PROJECT_ROOT/scripts/run_elevated.sh"

NORMAL_ICO="$LOGO_DIR/agentalsec_orca_normal.ico"
PRIV_ICO="$LOGO_DIR/agentalsec_orca_privileged.ico"
for f in "$NORMAL_ICO" "$PRIV_ICO"; do
    [[ -f "$f" ]] || die "missing icon $f, restore assets/logo from the repository"
done

APPS="$HOME/.local/share/applications"
DESKTOP="$HOME/Desktop"
ICONS="$HOME/.local/share/icons/hicolor"
mkdir -p "$APPS" "$DESKTOP" "$ICONS"

# the icon theme copy
#
# hicolor is the fallback theme every desktop reads, so a PNG dropped here is
# found by NAME rather than by path. The two variants are installed under
# DIFFERENT names so nothing has to decide which one wins.
#
# AND THE NAMES ARE WHAT THE .desktop FILES NOW USE. 2026-09-18
#
# The entries used to point Icon= at an absolute path to a .ico. That path
# was correct and the file existed, and the icons still came out as two
# BLANK WHITE BOXES, because a .ico is an MS Windows resource and this
# machine's gdk-pixbuf refuses the PNG-compressed entries Pillow writes into
# one by default ("Compressed icons are not supported"). Nothing about the
# .desktop entry was wrong; the artwork's FORMAT was, and only the thing
# that renders it could tell.
#
# So the entries now name the icon the way every application on the system
# does (Icon=firefox, Icon=nemo) and it resolves through this ladder of
# PNGs, which is the format the Linux desktop reads natively and at the
# right size for each context. The .ico files stay in assets/logo/ as the
# Windows-facing artwork; they are no longer in the Linux launcher's path.
for s in 16 22 24 32 36 48 64 128 256; do
    d="$ICONS/${s}x${s}/apps"
    mkdir -p "$d"
    src_n="$LOGO_DIR/png/orca_tile_ink_${s}.png"
    src_p="$LOGO_DIR/png/orca_tile_ink_privileged_${s}.png"
    [[ -f "$src_n" ]] && cp -f "$src_n" "$d/agentalsec.png"
    [[ -f "$src_p" ]] && cp -f "$src_p" "$d/agentalsec-privileged.png"
done
command -v gtk-update-icon-cache >/dev/null 2>&1 && \
    gtk-update-icon-cache -f -t "$ICONS" >/dev/null 2>&1 || true

write_entry() {
    local path="$1" name="$2" comment="$3" icon="$4" exec_line="$5"
    cat > "$path" <<EOF
[Desktop Entry]
Type=Application
Version=1.0
Name=$name
Comment=$comment
Exec=$exec_line
Icon=$icon
Terminal=false
Categories=System;Security;Monitor;
Keywords=security;monitor;network;agental;
StartupNotify=false
EOF
}

# Icon= NAMES THE THEME ENTRY, NOT A FILE PATH
#
# Verified by reading the .desktop files, not by clicking: a path-based
# Icon= to a .ico renders as an empty box under gdk-pixbuf, and a name-based
# Icon= resolves through the hicolor ladder that this same script installs.
# Checked after install with a lookup that names the size and gets the file
# back (see the verification block at the end).
ICON_NORMAL="agentalsec"
ICON_PRIV="agentalsec-privileged"

# the Start Menu entries
#
# StartupNotify=false on purpose. It tells the desktop to put up a spinner
# until the app signals it has drawn a window, and this app signals nothing:
# it is a server that opens a browser. Leaving it on gives a launcher that
# appears to still be loading for as long as the app runs.

write_entry "$APPS/agentalsec.desktop" \
    "AgentalSec" \
    "Network security monitor (normal boot)" \
    "$ICON_NORMAL" \
    "\"$LAUNCH\" --in-terminal"

write_entry "$APPS/agentalsec-privileged.desktop" \
    "AgentalSec (privileged)" \
    "Network security monitor — starts as root so the packet sniffer works" \
    "$ICON_PRIV" \
    "\"$LAUNCH\" --elevated --in-terminal"

write_entry "$DESKTOP/agentalsec.desktop" \
    "AgentalSec" \
    "Network security monitor (normal boot)" \
    "$ICON_NORMAL" \
    "\"$LAUNCH\" --in-terminal"

write_entry "$DESKTOP/agentalsec-privileged.desktop" \
    "AgentalSec (privileged)" \
    "Network security monitor — starts as root so the packet sniffer works" \
    "$ICON_PRIV" \
    "\"$LAUNCH\" --elevated --in-terminal"

# THE SAME TWO LAUNCHERS, IN THE PROJECT FOLDER
#
# NAMED WITH A .desktop EXTENSION AND MARKED EXECUTABLE, because that pair is
# what makes a file double-clickable in Nemo. A .ico here would be a picture:
# clicking it opens an image viewer and starts nothing, which is exactly the
# confusion this block removes.
mkdir -p "$APP_DIR"
write_entry "$APP_DIR/agental_sec.desktop" \
    "AgentalSec" \
    "Network security monitor (normal boot)" \
    "$ICON_NORMAL" \
    "\"$LAUNCH\" --in-terminal"
write_entry "$APP_DIR/agental_sec-privileged.desktop" \
    "AgentalSec (privileged)" \
    "Network security monitor — starts as root so the packet sniffer works" \
    "$ICON_PRIV" \
    "\"$LAUNCH\" --elevated --in-terminal"

chmod +x "$DESKTOP/agentalsec.desktop" "$DESKTOP/agentalsec-privileged.desktop" \
          "$APPS/agentalsec.desktop" "$APPS/agentalsec-privileged.desktop" \
          "$APP_DIR/agental_sec.desktop" "$APP_DIR/agental_sec-privileged.desktop"

# Nemo: mark them trusted
#
# Without this, double-clicking a .desktop opens it in a text editor with a
# "this file is not trusted" bar. The metadata keys are GIO's and are what
# Nemo actually reads. Best-effort: a missing gio must not stop the install,
# it only costs the double-click.
if command -v gio >/dev/null 2>&1; then
    for f in "$DESKTOP/agentalsec.desktop" "$DESKTOP/agentalsec-privileged.desktop" \
             "$APP_DIR/agental_sec.desktop" "$APP_DIR/agental_sec-privileged.desktop"; do
        gio set "$f" metadata::trusted true >/dev/null 2>&1 || true
        # Older Nemo/GIO spell it differently; set both rather than guess.
        gio set "$f" metadata::caja-trusted-launchers true >/dev/null 2>&1 || true
    done
fi

# validate
if command -v desktop-file-validate >/dev/null 2>&1; then
    bad=0
    for f in "$APPS/agentalsec.desktop" "$APPS/agentalsec-privileged.desktop" \
             "$DESKTOP/agentalsec.desktop" "$DESKTOP/agentalsec-privileged.desktop" \
             "$APP_DIR/agental_sec.desktop" "$APP_DIR/agental_sec-privileged.desktop"; do
        if ! out=$(desktop-file-validate "$f" 2>&1); then
            say "INVALID: $f"
            say "$out"
            bad=1
        fi
    done
    [[ "$bad" == "0" ]] && say "desktop-file-validate: all six entries are valid"
else
    say "desktop-file-validate not installed; skipped the validity check."
fi

# THE ICON CHECK, WHICH IS A SEPARATE QUESTION FROM VALIDITY
#
# desktop-file-validate confirms the entry PARSES. It cannot tell whether the
# icon it names will DRAW. Both launchers passed every validity check for two
# days while rendering as blank white boxes, because the artwork was a .ico
# whose entries gdk-pixbuf refuses.
#
# So this asks the icon theme the question the desktop asks — "give me this
# name at this size" — and fails loudly if nothing comes back. It uses GTK's
# own lookup through the system python, because that IS the consumer; asking
# a different library would repeat the original mistake of measuring the
# wrong reader.
say ""
say "Icon check (the desktop's own lookup, not a file-exists test):"
icon_check_out=$(python3 - <<'PY'
import sys
try:
    import gi
    gi.require_version("Gtk", "3.0")
    from gi.repository import Gtk
except Exception as exc:
    print(f"  SKIP: GTK not importable here ({exc}) — run this by hand to be sure")
    sys.exit(0)

theme = Gtk.IconTheme.get_default()
if theme is None:
    print("  SKIP: no default icon theme in this environment")
    sys.exit(0)

missing = []
for name in ("agentalsec", "agentalsec-privileged"):
    got = []
    for size in (16, 24, 32, 48, 128, 256):
        info = theme.lookup_icon(name, size, 0)
        got.append((size, info.get_filename() if info else None))
    blank = [s for s, f in got if not f]
    if blank:
        missing.append((name, blank))
        print(f"  [FAIL] {name}: no icon at {blank}")
    else:
        print(f"  [PASS] {name}: found at 16/24/32/48/128/256")
        print(f"         e.g. {got[3][1]}")
sys.exit(1 if missing else 0)
PY
) || {
    printf '%s\n' "$icon_check_out"
    die "the icon theme cannot resolve the launcher icons, so they will show
as blank boxes. The PNG ladder under $ICONS is what they resolve through —
re-run this script."
}
printf '%s\n' "$icon_check_out"

say ""
say "Installed:"
say "  $APP_DIR/agental_sec.desktop             (in the project folder)"
say "  $APP_DIR/agental_sec-privileged.desktop  (in the project folder)"
say "  $DESKTOP/agentalsec.desktop              (desktop icon)"
say "  $DESKTOP/agentalsec-privileged.desktop   (desktop icon)"
say "  $APPS/agentalsec.desktop                 (Start Menu)"
say "  $APPS/agentalsec-privileged.desktop      (Start Menu)"
say ""
say "NOTE: the .ico files in assets/logo/ are the ICONS — pictures. Clicking"
say "one opens an image viewer and starts nothing. The files that LAUNCH the"
say "app are the .desktop ones listed above."
say ""
say "The privileged one asks for your password, then starts the app as root"
say "so packet capture, full journald, firewall writes, other users'"
say "command lines, port ownership and the raw SYN scan all work. The"
say "normal one starts it as you."
say ""
say "If an icon shows as blank or 'untrusted', log out and back in once so"
say "Cinnamon re-reads the icon theme. To remove the folder launchers only:"
say "  rm -f $APP_DIR/agental_sec*.desktop"
