# pam_watchid

A lightweight PAM module for macOS that authenticates `sudo` requests via Apple Watch double-click.

Designed for Apple Silicon Macs operating without built-in or accessible Touch ID—such as a Mac mini, Mac Studio, or a MacBook docked in clamshell mode.

---

## Features

- **Apple Watch Companion Authentication:** Uses `LocalAuthentication.framework` (`LAPolicyDeviceOwnerAuthenticationWithCompanion`) to request wrist-based authorization.
- **Context-Aware Prompts:** Queries process arguments (`sysctl KERN_PROCARGS2`) and system configuration to display the exact command, target user, working directory, and parent process on the macOS authorization dialog.
- **Anti-Confused-Deputy Protection:** Validates against `SystemConfiguration` (`SCDynamicStoreCopyConsoleUser`) to ensure the calling process or target account matches the active WindowServer GUI console owner. Remote SSH sessions and mismatched users safely fall back to password authentication.
- **Responsive Terminal Interruption:** Traps `SIGINT` (Control-C) via Grand Central Dispatch, immediately invalidating the authentication context and dismissing prompts on both the Mac and Apple Watch without blocking.
- **Bounded Timeouts:** Enforces a configurable 30-second timeout to prevent terminal deadlocks in the event of dropped Bluetooth Continuity packets or unresponsive daemons.
- **OpenPAM Conformance:** Exports `pam_sm_authenticate`, `pam_sm_setcred`, and `pam_sm_acct_mgmt`, returning `PAM_SUCCESS` for credential and account stubs to match Apple's native `pam_tid.so.2` behavior.

---

## Requirements

- Apple Silicon Mac running macOS 15+ (Sequoia / Tahoe)
- Apple Watch running watchOS 10+ paired to the Mac
- Wrist detection enabled and watch unlocked
- **"Use your Apple Watch to unlock apps and your Mac"** enabled under **System Settings → Touch ID & Password**
- Xcode Command Line Tools (`xcode-select --install`)

---

## Build & Test

### 1. Compile

```bash
make
make verify
```

This compiles `build/pam_watchid.so` with `-Wall -Wextra -Werror` and verifies symbol exports.

### 2. Standalone Test (Zero-Risk)

Before touching system PAM configurations, you can test the module using the standalone harness:

```bash
make harness
./build/harness
```

This initiates an isolated PAM transaction, triggers the Apple Watch prompt, and verifies wrist approval and Control-C cancellation without modifying `/etc/pam.d/`.

---

## Installation

### Option A: Declarative Installation with nix-darwin (Recommended)

#### 1. Flake Configuration

Add `pam_watchid` as an input to your system `flake.nix`:

```nix
{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    nix-darwin.url = "github:LnL7/nix-darwin";
    pam-watchid.url = "github:pplanel/pam_watchid";
    pam-watchid.inputs.nixpkgs.follows = "nixpkgs";
  };

  outputs = { self, nixpkgs, nix-darwin, pam-watchid, ... }: {
    darwinConfigurations."my-mac" = nix-darwin.lib.darwinSystem {
      system = "aarch64-darwin";
      modules = [
        {
          nixpkgs.overlays = [ pam-watchid.overlays.default ];

          # Configure sudo_local
          security.pam.services.sudo_local.text = ''
            # Managed by Nix-Darwin
            auth       optional       ${pkgs.pam-reattach}/lib/pam/pam_reattach.so
            auth       sufficient     pam_tid.so
            auth       sufficient     ${pkgs.pam-watchid}/lib/pam/pam_watchid.so
          '';
        }
      ];
    };
  };
}
```

#### 2. Standalone Overlay (Without Flakes)

Import `pam-watchid.nix` in your configuration's `nixpkgs.overlays`:

```nix
nixpkgs.overlays = [
  (import ./pam-watchid.nix)
];
```

#### 3. Build Directly with Nix

```bash
# Build flake target from GitHub
nix build github:pplanel/pam_watchid

# Or build locally inside this repository
nix build
# or: nix-build
```

---

### Option B: Manual Installation (Without Nix)

#### 1. Copy the Module

```bash
sudo install -d -m 755 /usr/local/lib/pam
sudo install -m 444 build/pam_watchid.so /usr/local/lib/pam/pam_watchid.so.2
```

#### 2. Configure PAM for Sudo

macOS preserves `/etc/pam.d/sudo_local` across system updates. Create it from the template if it does not already exist:

```bash
sudo test -f /etc/pam.d/sudo_local || sudo cp /etc/pam.d/sudo_local.template /etc/pam.d/sudo_local
```

> **Warning:** A malformed PAM configuration can temporarily break `sudo`. Keep a root shell open (`sudo -s`) in a separate terminal window while configuring and testing.

Edit `/etc/pam.d/sudo_local`:

```text
# sudo_local: local authentication overrides
auth       sufficient     pam_tid.so
auth       sufficient     pam_watchid.so
```

*Note: Placing `pam_tid.so` first allows Touch ID to take precedence when a Touch ID sensor or Magic Keyboard is available; `pam_watchid.so` handles authentication when Touch ID is unavailable or the lid is closed.*

If you run terminal multiplexers like `tmux` or `screen`, place [pam-reattach](https://github.com/fabianishere/pam_reattach) at the top of the stack:

```text
auth       optional       pam_reattach.so
auth       sufficient     pam_tid.so
auth       sufficient     pam_watchid.so
```

#### 3. Verify

Open a new terminal window and run:

```bash
sudo -k && sudo true
```

Double-click the side button on your Apple Watch to authorize.

---

## Module Options

Options can be appended to the module entry in `/etc/pam.d/sudo_local`:

```text
auth       sufficient     pam_watchid.so debug timeout=15
```

| Option | Default | Description |
| :--- | :--- | :--- |
| `debug` | Off | Emits detailed diagnostic logs to unified logging (`subsystem: org.pam.watchid`). |
| `timeout=<seconds>` | `30` | Maximum wait duration before invalidating the prompt and failing open. |
| `reason=<string>` | Dynamic | Overrides the dynamic prompt with a fixed authorization reason. |

To inspect debug logs in real time:

```bash
log stream --predicate 'subsystem == "org.pam.watchid"' --level debug
```

---

## Troubleshooting

### Watch prompt disappears after ~1 second
This is a known macOS Bluetooth Continuity handshake issue. macOS requires strict RSSI proximity when initiating companion authentication.
1. Toggle **"Use your Apple Watch to unlock apps and your Mac"** off in **System Settings → Touch ID & Password**.
2. Restart both the Mac and Apple Watch.
3. Toggle the setting back on to refresh the Continuity pairing keys.
4. Ensure the watch band is snug to prevent intermittent wrist-detection drops.

### Apple Wallet opens when double-clicking
On watchOS, double-clicking the side button defaults to Apple Pay if the watchOS window server loses focus on the incoming companion authorization dialog.
- Ensure you double-click quickly once the prompt is visible.
- In the iPhone **Watch** app, go to **Wallet & Apple Pay** and disable **"Allow Payments on Mac"** if you do not use Apple Pay on the desktop.
- Alternatively, enable **AssistiveTouch** (**Settings → Accessibility → AssistiveTouch → Confirm with AssistiveTouch**) on your watch to approve prompts via a hand gesture instead of the physical button.

---

## Uninstallation

To remove `pam_watchid`:

1. Remove the `pam_watchid.so` line from `/etc/pam.d/sudo_local`.
2. Test that `sudo` continues to function with password authentication:
   ```bash
   sudo -k && sudo true
   ```
3. Remove the installed library:
   ```bash
   sudo rm /usr/local/lib/pam/pam_watchid.so.2
   ```

---

## License

[MIT](LICENSE)
