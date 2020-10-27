## Vulnerable Application

### General Notes

This module imports an Ubiquiti Unifi configuration file into the database.
This is similar to `post/multi/gather/ubiquiti_unifi_backup` only access isn't required,
and assumes you already have the file.

This module is able to take a unf file, from the controller and perform the following actions:

1. Decrypt the file
2. Fix the zip file if a `zip` utility is on the system
3. Extract db.gz
4. Unzip the db file
5. Import the db file

Or simply pass the db file for import directly.

## Verification Steps

1. Have a Ubiquiti Unifi configuration file (db or unf)
2. Start `msfconsole`
3. `use auxiliary/admin/networking/ubiquiti_config`
4. `set RHOST x.x.x.x`
5. `set CONFIG /tmp/file.unf`
6. `run`

## Options

### RHOST

Needed for setting services and items to.  This is relatively arbitrary.

### CONFIG

File path to the configuration unf or db file..

## Scenarios

### Unf File
```
resource (unifi_config.rb)> use auxiliary/admin/networking/ubiquiti_config
resource (unifi_config.rb)> set rhosts 127.0.0.1
rhosts => 127.0.0.1
resource (unifi_config.rb)> set config /root/.msf4/loot/20190825172544_default_1.1.1.1_ubiquiti.unifi.b_740136.unf
config => /root/.msf4/loot/20190825172544_default_1.1.1.1_ubiquiti.unifi.b_740136.unf
resource (unifi_config.rb)> run
[*] Running module against 127.0.0.1
[+] File DECRYPTED.  Still needs to be repaired
[*] Attempting to repair zip file (this is normal and takes some time)
[+] File DECRYPTED and REPAIRED and saved to /tmp/fixed_zip.zip20190825-6283-1merolj.
[*] extracting db.gz
[*] Converting config BSON to JSON
[+] Admin user unifiadmin with email admin@unifi.com found with password hash $6$R6qnBHgF$CHYrf4t.fXu0pcoloju5a85m3ujrjJLhIO.lN1xZqHZPQoUXXsJB98jgtsvt4Qo2/8t3epzbVLiba7Ls7GCVxcV.
[+] Radius server: 1.1.1.1:1812 with secret ''
[+] Mesh Wifi Network vwire-111117d211c1c1ea password 113b9b872b1114a9111f1a11ae11cdfe
[+] SSH user admin found with password lyxGYOF9UalubyyG and hash $6$37uelU/k$EkJuteQiAIP.CrRaJj4xC9gt61n95FJP3fQuQQmE9TqtFKtmIGsV5XSIJI.muBLOMKMkdlsPl8E3BvjJit.F21
[+] Config import successful
[*] Auxiliary module execution completed
```
### db File

```
resource (unifi_config.rb)> use auxiliary/admin/networking/ubiquiti_config
resource (unifi_config.rb)> set rhosts 127.0.0.1
rhosts => 127.0.0.1
msf5 auxiliary(admin/networking/ubiquiti_config) > set config /root/.msf4/loot/db
config => /root/.msf4/loot/db
msf5 auxiliary(admin/networking/ubiquiti_config) > run
[*] Running module against 127.0.0.1

[*] Converting config BSON to JSON
[+] Admin user unifiadmin with email admin@unifi.com found with password hash $6$R6qnBHgF$CHYrf4t.fXu0pcoloju5a85m3ujrjJLhIO.lN1xZqHZPQoUXXsJB98jgtsvt4Qo2/8t3epzbVLiba7Ls7GCVxcV.
[+] Radius server: 1.1.1.1:1812 with secret ''
[+] Mesh Wifi Network vwire-111117d211c1c1ea password 113b9b872b1114a9111f1a11ae11cdfe
[+] SSH user admin found with password lyxGYOF9UalubyyG and hash $6$37uelU/k$EkJuteQiAIP.CrRaJj4xC9gt61n95FJP3fQuQQmE9TqtFKtmIGsV5XSIJI.muBLOMKMkdlsPl8E3BvjJit.F21
[+] Config import successful
[*] Auxiliary module execution completed
```

