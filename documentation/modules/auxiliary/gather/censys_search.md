## Vulnerable Application

The module use the Censys REST API to access the same data accessible through web interface.
The search endpoint allows searches against the current data in the IPv4, Top Million Websites, and Certificates indexes using the same search syntax as the primary site.

## Verification Steps

1. Do: `use auxiliary/gather/censys_search`
2. Do: `set CENSYS_UID XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX` (length: 32 (without dashes))
3. Do: `set CENSYS_SECRET XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX` (length: 32)
4. Do: `set CENSYS_SEARCHTYPE certificates`
5: Do: `set CENSYS_DORK query`
6: Do: `run`

## Scenarios

### Certificates Search

```
msf auxiliary(censys_search) > set CENSYS_DORK rapid7
CENSYS_DORK => rapid7
msf auxiliary(censys_search) > set CENSYS_SEARCHTYPE certificates
CENSYS_SEARCHTYPE => certificates
...
[+] 199.15.214.152 - C=US, ST=TX, L=Austin, O=Rapid7, CN=MetasploitSelfSignedCA
[+] 31.214.157.19 - C=US, ST=TX, L=Austin, O=Rapid7, CN=MetasploitSelfSignedCA
[+] 31.220.7.39 - C=US, ST=TX, L=Austin, O=Rapid7, CN=MetasploitSelfSignedCA
[+] 168.253.216.190 - C=US, ST=TX, L=Austin, O=Rapid7, CN=MetasploitSelfSignedCA
[+] 52.88.1.225 - C=US, ST=TX, L=Austin, O=Rapid7, CN=MetasploitSelfSignedCA
[+] 208.118.237.41 - C=US, ST=TX, L=Austin, O=Rapid7, CN=MetasploitSelfSignedCA
[+] 64.125.235.5 - C=US, ST=TX, L=Austin, O=Rapid7, CN=MetasploitSelfSignedCA
[+] 208.118.237.39 - C=US, ST=TX, L=Austin, O=Rapid7, CN=MetasploitSelfSignedCA
[+] 208.118.237.40 - C=US, ST=TX, L=Austin, O=Rapid7, CN=MetasploitSelfSignedCA
[+] 208.118.227.12 - C=US, ST=TX, L=Austin, O=Rapid7, CN=MetasploitSelfSignedCA
[+] 208.118.237.38 - C=US, ST=TX, L=Austin, O=Rapid7, CN=MetasploitSelfSignedCA
[+] 23.48.13.195 - C=US, ST=TX, L=Austin, O=Rapid7, CN=MetasploitSelfSignedCA
[+] 208.118.227.14 - C=US, ST=TX, L=Austin, O=Rapid7, CN=MetasploitSelfSignedCA
[+] 54.230.252.134 - C=US, ST=TX, L=Austin, O=Rapid7, CN=MetasploitSelfSignedCA
[+] 54.230.249.63 - C=US, ST=TX, L=Austin, O=Rapid7, CN=MetasploitSelfSignedCA
[+] 54.230.249.242 - C=US, ST=TX, L=Austin, O=Rapid7, CN=MetasploitSelfSignedCA
[+] 54.230.249.187 - C=US, ST=TX, L=Austin, O=Rapid7, CN=MetasploitSelfSignedCA
[+] 54.230.249.64 - C=US, ST=TX, L=Austin, O=Rapid7, CN=MetasploitSelfSignedCA
[+] 54.230.249.181 - C=US, ST=TX, L=Austin, O=Rapid7, CN=MetasploitSelfSignedCA
[+] 54.230.249.17 - C=US, ST=TX, L=Austin, O=Rapid7, CN=MetasploitSelfSignedCA
[+] 54.230.249.183 - C=US, ST=TX, L=Austin, O=Rapid7, CN=MetasploitSelfSignedCA
[+] 54.230.249.186 - C=US, ST=TX, L=Austin, O=Rapid7, CN=MetasploitSelfSignedCA
[+] 199.15.214.152 - C=US, ST=TX, L=Austin, O=Rapid7, CN=MetasploitSelfSignedCA
[+] 31.214.157.19 - C=US, ST=TX, L=Austin, O=Rapid7, CN=MetasploitSelfSignedCA
[+] 31.220.7.39 - C=US, ST=TX, L=Austin, O=Rapid7, CN=MetasploitSelfSignedCA
[+] 168.253.216.190 - C=US, ST=TX, L=Austin, O=Rapid7, CN=MetasploitSelfSignedCA
[+] 52.88.1.225 - C=US, ST=TX, L=Austin, O=Rapid7, CN=MetasploitSelfSignedCA
[+] 208.118.237.41 - C=US, ST=TX, L=Austin, O=Rapid7, CN=localhost
[+] 64.125.235.5 - C=US, ST=TX, L=Austin, O=Rapid7, CN=localhost
[+] 208.118.237.39 - C=US, ST=TX, L=Austin, O=Rapid7, CN=localhost
[+] 208.118.237.40 - C=US, ST=TX, L=Austin, O=Rapid7, CN=localhost
[+] 208.118.227.12 - C=US, ST=TX, L=Austin, O=Rapid7, CN=localhost
[+] 208.118.237.38 - C=US, ST=TX, L=Austin, O=Rapid7, CN=localhost
[+] 23.48.13.195 - C=US, ST=TX, L=Austin, O=Rapid7, CN=localhost
[+] 208.118.227.14 - C=US, ST=TX, L=Austin, O=Rapid7, CN=localhost
[+] 54.230.252.134 - C=US, ST=TX, L=Austin, O=Rapid7, CN=localhost
[+] 54.230.249.63 - C=US, ST=TX, L=Austin, O=Rapid7, CN=localhost
[+] 54.230.249.242 - C=US, ST=TX, L=Austin, O=Rapid7, CN=localhost
[+] 54.230.249.187 - C=US, ST=TX, L=Austin, O=Rapid7, CN=localhost
[+] 54.230.249.64 - C=US, ST=TX, L=Austin, O=Rapid7, CN=localhost
[+] 54.230.249.181 - C=US, ST=TX, L=Austin, O=Rapid7, CN=localhost
[+] 54.230.249.17 - C=US, ST=TX, L=Austin, O=Rapid7, CN=localhost
[+] 54.230.249.183 - C=US, ST=TX, L=Austin, O=Rapid7, CN=localhost
[+] 54.230.249.186 - C=US, ST=TX, L=Austin, O=Rapid7, CN=localhost
[+] 199.15.214.152 - C=US, ST=TX, L=Austin, O=Rapid7, CN=localhost
[+] 31.214.157.19 - C=US, ST=TX, L=Austin, O=Rapid7, CN=localhost
[+] 31.220.7.39 - C=US, ST=TX, L=Austin, O=Rapid7, CN=localhost
[+] 168.253.216.190 - C=US, ST=TX, L=Austin, O=Rapid7, CN=localhost
[+] 52.88.1.225 - C=US, ST=TX, L=Austin, O=Rapid7, CN=localhost
[+] 208.118.237.41 - CN=NeXpose Security Console, O=Rapid7
...

```

### IPv4 Search

```
msf auxiliary(censys_search) > set CENSYS_DORK rapid7
CENSYS_DORK => rapid7
msf auxiliary(censys_search) > set CENSYS_SEARCHTYPE ipv4
CENSYS_SEARCHTYPE => ipv4
[*] 197.117.5.36 - 443/https
[*] 208.118.237.81 - 443/https
[*] 206.19.237.19 - 443/https
[*] 54.214.49.70 - 80/http,443/https
[*] 208.118.237.241 - 443/https
[*] 162.220.246.141 - 443/https,22/ssh,80/http
[*] 31.214.157.19 - 443/https,22/ssh
[*] 52.88.1.225 - 443/https,22/ssh
[*] 208.118.227.12 - 25/smtp
[*] 38.107.201.41 - 443/https
[*] 52.44.56.126 - 80/http,443/https
[*] 52.54.227.6 - 443/https,80/http
[*] 23.217.253.242 - 443/https,80/http
[*] 96.6.3.45 - 80/http,443/https
[*] 23.6.73.47 - 443/https,80/http
[*] 23.78.99.243 - 80/http,443/https
[*] 23.53.51.170 - 80/http,443/https
[*] 23.62.201.47 - 443/https,80/http
[*] 2.23.50.157 - 443/https,80/http
[*] 118.215.191.13 - 80/http,443/https
[*] 2.19.185.28 - 80/http,443/https
[*] 2.18.195.99 - 443/https,80/http
[*] 23.197.196.25 - 443/https,80/http
[*] 95.100.104.181 - 443/https,80/http
[*] 2.20.37.130 - 80/http,443/https
[*] 23.194.237.34 - 443/https,80/http
[*] 2.17.140.86 - 443/https,80/http
[*] 64.125.235.5 - 25/smtp
[*] 208.118.227.32 - 80/http
[*] 2.21.129.149 - 80/http,443/https
[*] 2.20.167.33 - 80/http,443/https
[*] 95.100.139.218 - 80/http,443/https
[*] 23.38.88.202 - 443/https,80/http
[*] 2.17.184.80 - 443/https,80/http
[*] 23.59.119.23 - 80/http,443/https
[*] 2.16.14.225 - 443/https,80/http
[*] 104.113.122.33 - 443/https,80/http
[*] 23.223.44.164 - 80/http,443/https
[*] 88.221.120.214 - 443/https,80/http
[*] 23.47.36.145 - 443/https,80/http
[*] 2.23.21.254 - 80/http,443/https
[*] 208.118.237.39 - 443/https
[*] 208.118.237.40 - 443/https
[*] 208.118.237.41 - 443/https
[*] 23.54.217.47 - 80/http,443/https
[*] 96.17.254.188 - 443/https,80/http
[*] 184.25.129.65 - 443/https,80/http
[*] 104.121.167.123 - 443/https,80/http
[*] 104.94.110.63 - 443/https,80/http
[*] 104.91.11.216 - 80/http,443/https
[*] 23.38.233.47 - 80/http,443/https
[*] 52.86.110.89 - 80/http,443/https
[*] 69.192.73.47 - 443/https,80/http
[*] 184.86.57.47 - 443/https,80/http
[*] 104.86.45.180 - 443/https,80/http
[*] 184.87.72.153 - 80/http,443/https
[*] 23.66.25.47 - 80/http,443/https
[*] 23.56.162.76 - 80/http,443/https
[*] 184.87.133.242 - 443/https,80/http
[*] 23.55.74.28 - 80/http,443/https
[*] 23.6.225.84 - 80/http,443/https
[*] 23.46.133.153 - 443/https,80/http
[*] 23.10.121.47 - 443/https,80/http
[*] 104.109.35.169 - 80/http,443/https
[*] 172.227.101.182 - 80/http,443/https
[*] 184.27.23.104 - 80/http,443/https
[*] 23.49.185.47 - 80/http,443/https
[*] 23.67.172.177 - 80/http,443/https
[*] 23.62.170.161 - 443/https,80/http
[*] 23.219.71.35 - 443/https,80/http
[*] 104.82.94.233 - 443/https,80/http
[*] 184.26.73.47 - 80/http,443/https
[*] 104.68.108.237 - 80/http,443/https
[*] 23.60.39.77 - 80/http,443/https
[*] 23.66.100.92 - 80/http,443/https
[*] 23.61.28.182 - 443/https,80/http
[*] 23.42.116.233 - 80/http,443/https
[*] 104.105.14.197 - 80/http,443/https
[*] 104.103.203.240 - 80/http,443/https
[*] 104.65.57.235 - 80/http,443/https
[*] 23.41.83.224 - 80/http,443/https
[*] 184.51.185.47 - 80/http,443/https
[*] 23.67.231.142 - 80/http,443/https
[*] 208.118.237.38 - 443/https
[*] 104.76.25.28 - 80/http,443/https
[*] 23.196.125.176 - 443/https,80/http
[*] 23.40.154.224 - 80/http,443/https
[*] 23.77.33.204 - 443/https,80/http
[*] 104.88.21.48 - 80/http,443/https
[*] 173.223.134.47 - 80/http,443/https
[*] 23.4.98.72 - 80/http,443/https
[*] 23.44.97.3 - 80/http,443/https
[*] 23.203.66.142 - 443/https,80/http
[*] 23.42.216.251 - 443/https,80/http
[*] 23.42.85.25 - 80/http,443/https
[*] 173.255.195.131 - 80/http,23/telnet,25/smtp,110/pop3,53/dns,443/https,22/ssh
[*] 104.83.219.182 - 443/https,80/http
[*] 184.86.41.47 - 443/https,80/http
[*] 104.97.72.196 - 443/https,80/http
[*] 69.192.169.48 - 443/https,80/http
```

### Websites Search

```
msf auxiliary(censys_search) > set CENSYS_DORK rapid7
CENSYS_DORK => rapid7
msf auxiliary(censys_search) > set CENSYS_SEARCHTYPE websites
CENSYS_SEARCHTYPE => websites
msf auxiliary(censys_search) > run

[+] rapid7.com - [37743]
[+] logentries.com - [45346]
[+] venturefizz.com - [106102]
[+] gild.com - [116853]
[+] sectools.org - [122125]
[+] ericzhang.me - [155622]
[+] metasploit.com - [156435]
[+] datapipe.com - [209756]
[+] routerpwn.com - [317896]
[+] proxy-base.com - [507954]
[+] config.fr - [542346]
[+] winterwyman.com - [629471]
[+] gogrid.com - [741009]
[+] wesecure.nl - [997423]
[*] Auxiliary module execution completed
```
