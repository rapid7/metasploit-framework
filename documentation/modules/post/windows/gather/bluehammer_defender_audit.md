## Vulnerable Application

This is a **defensive, read-only** post module. It audits a Windows host for its exposure to
**CVE-2026-33825 ("BlueHammer")**, a patched Time-Of-Check-To-Time-Of-Use (TOCTOU) flaw
(CWE-1220) in the Microsoft Defender Antimalware Platform that allowed a low-privileged local
user to read the SAM database (credential theft leading to indirect privilege escalation). The
issue is Microsoft-confirmed, CISA-KEV listed, and fixed in Defender Antimalware Platform build
**`4.18.26030.3011`** (released 14 April 2026).

**The module performs no exploitation.** It does not implement the TOCTOU primitive, access the
SAM database, or modify any Defender setting. Every operation reads state only. On an existing
session it answers three questions and prints a scored verdict:

* **(A) Vulnerable?** Is the installed Defender platform build below the fixed version? Three
  independent sources (PowerShell, the on-disk platform folder, and the platform binary
  version) are read and cross-checked; a genuine disagreement is flagged as a possible
  tampering / partial-update indicator.
* **(B) Exposed in practice?** Would Tamper Protection, real-time protection, signature
  currency, and Volume Shadow Copy state leave the host exploitable?
* **(C) Targeted?** Do Defender's own Operational logs (event IDs 1116/1117 for the
  `DfndrPEBluHmr` detection) or known indicators of compromise show the host was attacked?

Any Windows host running Microsoft Defender can be audited — no specially vulnerable target is
required, since this is an audit module rather than an exploit. A host whose platform build is
earlier than `4.18.26030.3011` is reported `VULNERABLE`. To exercise the version-comparison
logic on an already-patched host, override `FIXED_VERSION` (see Scenarios).

Tested against Windows 10/11 with Microsoft Defender over a Meterpreter session.

## Verification Steps

1. Obtain a Meterpreter session on a Windows target.
2. Do: `use post/windows/gather/bluehammer_defender_audit`
3. Do: `set SESSION [session-id]`
4. (Optional) To enable indicator matching, do: `set IOC_FILE /path/to/iocs.json`
5. Do: `run`
6. You should see the `(A)` version, `(B)` posture, and `(C)` targeting sections, followed by a
   `Verdict` line and a JSON snapshot written to loot.

## Options

### FIXED_VERSION

The Defender Antimalware Platform build that contains the CVE-2026-33825 fix. Installed builds
below this value are treated as vulnerable. Default: `4.18.26030.3011`. Raise it above the
installed build to validate the version-comparison logic on a patched host.

### HUNT_LOG

Whether to run the `(C)` hunt against the Windows Defender Operational log. Default: `true`.

### HUNT_DAYS

Look-back window, in days, for the log hunt. Default: `90`.

### IOC_FILE

Optional path to a local `iocs.json` file providing path-regex and SHA-256 indicators sourced
from defensive analysis. When set, executables found in user-writable directories are matched
against it. Keeping indicators in a data file (rather than in module code) makes them auditable
and easy to update. Default: blank (no indicator matching).

### STORE_LOOT

Whether to write a JSON audit snapshot to loot. Default: `true`.

## Scenarios

### Patched host with weak posture and an indicator present (Windows 11, Defender platform 4.18.26050.15)

A patched host with Tamper Protection disabled and a known-indicator executable staged under a
user's `Downloads` directory:

```
msf post(windows/gather/bluehammer_defender_audit) > set SESSION 1
SESSION => 1
msf post(windows/gather/bluehammer_defender_audit) > set IOC_FILE /home/ana/projects/defender-bluehammer-audit/research/iocs.json
IOC_FILE => /home/ana/projects/defender-bluehammer-audit/research/iocs.json
msf post(windows/gather/bluehammer_defender_audit) > run

[*] BlueHammer (CVE-2026-33825) defensive audit — read-only, no exploitation.

[*] == (A) Defender platform version ==
[*]   powershell: 4.18.26050.15
[*]   platform_dir: 4.18.26050.15-0
[*]   file: 4.18.26050.15
[+]   4.18.26050.15 includes the fix

[*] == (B) Posture ==
[*]   Tamper Protection: false   Real-time: true
[*]   Behavior monitor: true   On-access: true
[*]   Signature age (days): 0   Shadow copies present: false

[*] == (C) Targeting evidence ==
[*]   Defender detections in window (1116/1117): 65
[-]   IOC match: C:\Users\aust\Downloads\ks\undef.exe

[*] == Verdict ==
[+] Verdict: PATCHED-BUT-EXPOSED
[-] EVIDENCE-OF-TARGETING: Defender log / IOC hits present.
[+] Loot snapshot: /home/ana/.msf4/loot/20260929152000_default_192.168.133.135_bluehammer.audit_222674.json
[*] Post module execution completed
```

The verdict is `PATCHED-BUT-EXPOSED` because, although the platform build includes the fix,
Tamper Protection is off (weak posture). The `EVIDENCE-OF-TARGETING` overlay is raised by the
indicator match on `undef.exe`. Note the module reviewed 65 Defender detections in the window
but reported no BlueHammer signature hits — the signature filter does not false-positive on
unrelated detections.

### Validating the vulnerable-version branch (FIXED_VERSION override)

The same patched host, with the baseline raised above the installed build to exercise the
`VULNERABLE` comparison path (useful for verifying the module in a lab that has no genuinely
outdated Defender build available):

```
msf post(windows/gather/bluehammer_defender_audit) > set FIXED_VERSION 99.99.99.99
FIXED_VERSION => 99.99.99.99
msf post(windows/gather/bluehammer_defender_audit) > run

[*] BlueHammer (CVE-2026-33825) defensive audit — read-only, no exploitation.

[*] == (A) Defender platform version ==
[*]   powershell: 4.18.26050.15
[*]   platform_dir: 4.18.26050.15-0
[*]   file: 4.18.26050.15
[!]   4.18.26050.15 is BELOW fixed build 99.99.99.99

[*] == Verdict ==
[+] Verdict: VULNERABLE
[*] Post module execution completed
```

### Verdicts

| Verdict | Meaning |
| --- | --- |
| `HARDENED` | Patched build, Tamper Protection on, real-time protection on, signatures current |
| `PATCHED-BUT-EXPOSED` | Patched build, but weak posture (Tamper off, real-time off, signatures stale, or shadow copies present) |
| `VULNERABLE` | Defender platform build is below `FIXED_VERSION` |
| `UNKNOWN` | The Defender platform version could not be determined from any source |
| `EVIDENCE-OF-TARGETING` | Overlay on any verdict — a Defender detection (event 1116/1117) for the BlueHammer signature, or an IOC match from `IOC_FILE`, was found |
