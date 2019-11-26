## Vulnerable Application

Enumerate TCP services via the FTP bounce PORT/LIST method

## Verification Steps

1. Start msfconsole
2. Do: `use modules/auxiliary/scanner/portscan/ftpbounce`
3. Do: `set BOUNCEHOST [ip]`
4. Do: `set PORTS [number(s)]`
5. Do: `set RHOSTS [ip]`
6. Do: `SET FTPUSER [user]`
7. Do: `SET FTPPASS [password]`
8. Do: `run`

## Scenarios

Docker Usage:  `docker run -e "ADDED_FLAGS=-w -W -d -d" -e FTP_USER_NAME=bob -e FTP_USER_PASS=12345 -e FTP_USER_HOME=/home/bob stilliard/pure-ftpd`

### PureFTPd and Kali Linux 2019.3

  ```
  msf > use modules/auxiliary/scanner/portscan/ftpbounce
  msf auxiliary(scanner/portscan/ftpbounce) > set BOUNCEHOST 172.17.0.2
    BOUNCEHOST => 172.17.0.2
  msf auxiliary(scanner/portscan/ftpbounce) > set PORTS 8080
    BOUNCEPORT => 8080
  msf auxiliary(scanner/portscan/ftpbounce) > set RHOSTS 172.17.0.4
    RHOSTS => 172.17.0.4
  msf auxiliary(scanner/portscan/ftpbounce) > set FTPUSER bob
    FTPUSER => bob
  msf auxiliary(scanner/portscan/ftpbounce) > set FTPPASS 12345
    FTPPASS => 12345
  msf auxiliary(scanner/portscan/ftpbounce) > run

    [+] 172.17.0.2:21 -  TCP OPEN 172.17.0.4:8080
    [*] 172.17.0.2:21 - Scanned 1 of 1 hosts (100% complete)
    [*] Auxiliary module execution completed
  ```

#### Manual Exploitation

  ```
  root@ubuntu:~# nmap -p 8080 -v -b bob:12345@172.17.0.2 172.17.0.4 -Pn

    Starting Nmap 7.60 ( https://nmap.org ) at 2019-11-25 20:34 UTC
    Resolved FTP bounce attack proxy to 172.17.0.2 (172.17.0.2).
    Initiating Parallel DNS resolution of 1 host. at 20:34
    Completed Parallel DNS resolution of 1 host. at 20:34, 0.00s elapsed
    Attempting connection to ftp://bob:12345@172.17.0.2:21
    Connected:220---------- Welcome to Pure-FTPd [privsep] [TLS] ----------
    220-You are user number 1 of 5 allowed.
    220-Local time is now 20:34. Server port: 21.
    220-This is a private system - No anonymous login
    220-This server supports FXP transfers
    220-IPv6 connections are also welcome on this server.
    220 You will be disconnected after 15 minutes of inactivity.
    Login credentials accepted by FTP server!
    Initiating Bounce Scan at 20:34
    Discovered open port 8080/tcp on 172.17.0.4
    Completed Bounce Scan at 20:34, 0.00s elapsed (1 total ports)
    Nmap scan report for 172.17.0.4
    Host is up.

    PORT     STATE SERVICE
    8080/tcp open  http-proxy
  ```
