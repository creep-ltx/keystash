# KeyStash contrib scripts

Optional desktop-integration helpers. Nothing here is required by KeyStash
itself — these are thin wrappers around the normal CLI, kept as scripts so
you can read every line before trusting them with a password manager.

## keystash-menu.sh — launcher-menu quick access

Press a keybinding → type your master password into a popup → pick an
entry → the password lands in your clipboard (with KeyStash's usual timed
auto-clear) or is typed straight into the focused window.

```bash
keystash-menu.sh          # copy the selected entry's password
keystash-menu.sh --user   # copy the selected entry's username
keystash-menu.sh --type   # type the password into the focused window
```

### Install

```bash
cp contrib/keystash-menu.sh ~/.local/bin/ && chmod +x ~/.local/bin/keystash-menu.sh
```

Then bind it in your compositor/WM, e.g. sway/i3:

```
bindsym $mod+p exec keystash-menu.sh
```

For a separate profile: `KEYSTASH_ARGS="--profile work" keystash-menu.sh`
(make a second keybinding per profile).

### Requirements

- **keystash 0.4.5+** — the script feeds your master password over stdin
  via `--password-stdin` (the `docker login --password-stdin` pattern:
  never in argv where `ps` sees it, never in the environment where
  `/proc` and child processes see it).
- **A menu tool:** [rofi](https://github.com/davatorium/rofi) or
  [fuzzel](https://codeberg.org/dnkl/fuzzel) recommended — both mask the
  password prompt. Plain dmenu works but **cannot mask input**: your
  master password is briefly visible on screen. The script warns in the
  prompt text when it falls back to dmenu.
- **For `--type` only,** one of:
  - [`wtype`](https://github.com/atx/wtype) — Wayland (wlroots
    compositors: sway, hyprland, river…). No special permissions.
    Does not work on GNOME's compositor.
  - [`ydotool`](https://github.com/ReimuNotMoe/ydotool) — works on any
    Wayland compositor **but** its daemon needs write access to
    `/dev/uinput`. That is a real permission grant, not a formality:
    a process that can write uinput can synthesize *any* input on your
    machine (a keylogger's sibling). Set it up deliberately — a udev
    rule plus a dedicated group is the usual pattern — and understand
    what you're enabling before choosing this route.
  - `xdotool` — X11 sessions only; does nothing under native Wayland
    (the reason it isn't the default suggestion).

### Security notes, honestly stated

- Your master password passes through the menu tool's stdin and a shell
  variable inside the script. Shell variables can't be zeroized the way
  KeyStash wipes its own memory — this is inherently a small step down
  from typing into KeyStash directly. The script `unset`s everything it
  can, uses `--no-sync` (no network from a popup), and never puts the
  *master password* in argv.
- **Known limitation (`--type` mode only):** the selected password is held
  in a script variable and currently passed to the typing tool
  (wtype/ydotool/xdotool) **as a command-line argument**, which is briefly
  visible in `/proc/<pid>/cmdline` to other local processes while the tool
  runs. A fix (feeding the tool via stdin) is planned; until then, prefer
  copy mode, which avoids all of this entirely: KeyStash's own `copy`
  command moves the secret process-to-clipboard without the script ever
  seeing it.
- Passwords containing newlines can't be typed correctly (`show`'s output
  is line-based); copy mode handles them fine.
- `KEYSTASH_PASSWORD` exists for testing/automation only — exported
  environment variables are visible to child processes and in
  `/proc/<pid>/environ`, which is exactly what `--password-stdin` avoids.
  Don't use it interactively.
