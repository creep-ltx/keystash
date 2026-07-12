#!/usr/bin/env bash
# keystash-menu -- launcher-menu quick access to a KeyStash vault.
#
# Pops a password prompt, lists your credentials in rofi/fuzzel/dmenu,
# and either copies the chosen entry's password (KeyStash's own timed
# clipboard-clear applies) or types it into the focused window.
#
#   keystash-menu.sh          copy the selected entry's password
#   keystash-menu.sh --user   copy the selected entry's username
#   keystash-menu.sh --type   type the password into the focused window
#
# Requirements:
#   - keystash 0.4.5+ (for --password-stdin)
#   - a menu: rofi, fuzzel, or dmenu (dmenu CANNOT mask the password
#     prompt -- rofi/fuzzel strongly recommended)
#   - for --type: wtype (Wayland/wlroots), or ydotool (any Wayland; its
#     daemon needs /dev/uinput access -- a real permission, see README),
#     or xdotool (X11 only)
#
# Environment:
#   KEYSTASH          keystash binary (default: keystash from PATH)
#   KEYSTASH_ARGS     extra args, e.g. "--profile work"
#   KEYSTASH_MENU     override the menu command (mainly for testing)
#   KEYSTASH_PASSWORD master password override -- ONLY for testing or an
#                     agent you trust; exported env leaks to child
#                     processes and /proc, which is exactly what
#                     --password-stdin exists to avoid
#
# Bind it, e.g. sway:  bindsym $mod+p exec /path/to/keystash-menu.sh

set -euo pipefail

KEYSTASH=${KEYSTASH:-keystash}
# shellcheck disable=SC2086 # KEYSTASH_ARGS is deliberately word-split
ks() { $KEYSTASH ${KEYSTASH_ARGS:-} --no-sync --password-stdin "$@"; }

MODE="copy-password"
case "${1:-}" in
    "")       ;;
    --user)   MODE="copy-username" ;;
    --type)   MODE="type-password" ;;
    *) echo "usage: $0 [--user|--type]" >&2; exit 2 ;;
esac

menu() { # $1 = prompt; options on stdin; selection on stdout
    if [ -n "${KEYSTASH_MENU:-}" ]; then
        $KEYSTASH_MENU
    elif command -v rofi >/dev/null 2>&1; then
        rofi -dmenu -i -p "$1"
    elif command -v fuzzel >/dev/null 2>&1; then
        fuzzel --dmenu --prompt "$1: "
    elif command -v dmenu >/dev/null 2>&1; then
        dmenu -i -p "$1"
    else
        echo "keystash-menu: no menu tool found (install rofi, fuzzel, or dmenu)" >&2
        exit 1
    fi
}

ask_password() {
    if [ -n "${KEYSTASH_PASSWORD:-}" ]; then
        printf '%s' "$KEYSTASH_PASSWORD"
        return
    fi
    if [ -n "${KEYSTASH_MENU:-}" ]; then
        # Test override without KEYSTASH_PASSWORD: read from the tty/stdin.
        head -n 1
    elif command -v rofi >/dev/null 2>&1; then
        rofi -dmenu -password -p "KeyStash master password" </dev/null
    elif command -v fuzzel >/dev/null 2>&1; then
        fuzzel --dmenu --password --prompt "KeyStash master password: " </dev/null
    else
        # dmenu has no masking: the password is briefly VISIBLE on screen.
        dmenu -p "Master password (VISIBLE -- dmenu can't mask!)" </dev/null
    fi
}

type_text() { # $1 = text to type into the focused window
    if command -v wtype >/dev/null 2>&1; then
        wtype -- "$1"
    elif command -v ydotool >/dev/null 2>&1; then
        ydotool type -- "$1"
    elif command -v xdotool >/dev/null 2>&1; then
        xdotool type --clearmodifiers -- "$1"
    else
        echo "keystash-menu: no typing tool found (install wtype, ydotool, or xdotool)" >&2
        exit 1
    fi
}

master_pw=$(ask_password)
[ -n "$master_pw" ] || exit 1

# `keystash list` prints " ID | Title | Tags | Username | ..." -- drop the
# two header lines and show the rest. Field-splitting on ' | ' is safe as
# long as no title/tag/username itself contains " | " (edge case, accepted).
entries=$(printf '%s\n' "$master_pw" | ks list | tail -n +2 | grep -v '^-\+$' || true)
if [ -z "$entries" ]; then
    echo "keystash-menu: vault is empty or the master password was wrong" >&2
    unset master_pw
    exit 1
fi

selection=$(printf '%s\n' "$entries" | menu "KeyStash")
[ -n "$selection" ] || { unset master_pw; exit 0; }
id=${selection%%|*}
id=$(printf '%s' "$id" | tr -d '[:space:]')
case "$id" in *[!0-9]*|"") echo "keystash-menu: could not parse entry id from selection" >&2; exit 1 ;; esac

case "$MODE" in
    copy-password)
        # keystash's own copy command handles the clipboard AND the timed
        # auto-clear -- the script never touches the secret itself.
        printf '%s\n' "$master_pw" | ks copy "$id" password
        ;;
    copy-username)
        printf '%s\n' "$master_pw" | ks copy "$id" username
        ;;
    type-password)
        secret=$(printf '%s\n' "$master_pw" | ks show "$id" --reveal | sed -n 's/^Password: //p')
        if [ -z "$secret" ]; then
            echo "keystash-menu: could not read the password" >&2
            unset master_pw
            exit 1
        fi
        type_text "$secret"
        unset secret
        ;;
esac

unset master_pw
