# KeyStash - Feature Roadmap & TODO List

This document outlines planned improvements, security enhancements, and user suggestions to be implemented in future releases.

---

## Planned Roadmap

### 1. Desktop Environment Auto-Fill Helpers (`contrib/`)
* **Description**: Offer integration templates and wrapper scripts for system-wide password auto-typing.
* **Implementation Plan**:
  * Add a `contrib/` directory containing wrapper scripts utilizing system tools (like `rofi` or `dmenu` for entry selection, and `xdotool` or `wtype`/`ydotool` for simulated keyboard input typing).

### 2. Alternative Cloud & SFTP Backups
* **Description**: Provide alternative synchronization mechanisms for users who do not want to use Git.
* **Implementation Plan**:
  * Support backup and restore using SFTP/SSH.
  * Add a configurable pre-exit/post-startup shell command hook (enabling easy `rclone` or custom backup script integration).

### 3. Multi-User Vault Profiles
* **Description**: Support maintaining multiple distinct vault databases (e.g. `work`, `personal`) within the configuration directory.
* **Implementation Plan**:
  * Add a `--profile <name>` CLI parameter to specify custom database filenames.
  * Integrate an interactive profile manager screen/dropdown inside the TUI.

---
