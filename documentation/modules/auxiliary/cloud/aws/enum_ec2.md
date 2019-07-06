## Vulnerable Application

Amazon Web Services (AWS) resources can be managed through an API that authenticates based on an `ACCESS_KEY_ID` and a `SECRET_ACCESS_KEY`.  With these two pieces of information, an attacker can gain privileges which may include enumerating resources within the AWS account.

This module authenticates to AWS EC2 (Elastic Compute Cloud) to identify compute instances that the credentials can see.  The instances themselves may be connected to the public Internet, but are likely to be protected by security groups and subnet network ACLs.  In any case, knowledge of the instances is the first step in evaluating their security.

## Verification Steps

### Create or acquire the credentials

  1. (If necessary) Create an AWS account.  Free trials are available.
  2. Login to the [AWS Console](https:\\console.aws.amazon.com\).
  3. Use the dropbown menu in the top-right with your username, then click on "My Security Credentials".
  4. Expand the "Access Keys" pane and click  "Create New Access Key".
  5. Follow the steps in the AWS console, making sure to record both the 'access key ID' and 'secret access key'.  (The 'secret access key' is only shown once, then can never be retrieved.)

### Enumerate AWS resources using the credentials

  1. Start msfconsole
  2. `use auxiliary/cloud/aws/enum_ec2`
  3. Set the `ACCESS_KEY_ID` and `SECRET_ACCESS_KEY` options.
  4. Optionally, set the `REGION` and `LIMIT` options.
  5. `run`

## Options

  **ACCESS_KEY_ID**

  This AWS credential is like a username.  It uniquely identifies the user, and is paired with a 'secret access key'.  The access key ID is retrievable through the AWS console.
  
  An example `ACCESS_KEY_ID` would be `AKIA5C76TR3KXHXA5CRC`

  **SECRET_ACCESS_KEY**

  This AWS credential is like a password, and should be treated as such.  It is paired with a 'access key ID'.  The access key ID cannot be retrieved from AWS after it has been generated, but it may be discoverable through environment variables, configuration files, source code, or backups.
  
  An example `SECRET_ACCESS_KEY` would be `EKfx3wOWWiGk1WgBTAZfF\2dq3SbDsQj4jdyOMOv`.

## Scenarios

### Provided a valid 'access key ID' and 'secret access key' with sufficient privileges 

```
msf5 auxiliary(cloud/aws/enum_iam) > run

[+] Found 3 users.
[+]   User Name:       test1
[+]   User ID:         AIDA5C76TR3KTTO3PTAJ7
[+]   Creation Date:   2019-06-14 18:18:23 UTC
[+]   Tags:            []
[+]   Groups:          []
[+]   SSH Pub Keys:    []
[+]   Policies:        IAMUserChangePassword
[+]   Signing certs:   []
[+]   Password Used:   2019-06-17 19:55:57 UTC
[+]   AWS Access Keys: AKIA5C76TR3K3JN3FYUE (Active)
[+]   Console login:   Enabled
[+]   Two-factor auth: Enabled on 2019-06-17 20:01:05 UTC
[*] 
[+]   User Name:       test2
[+]   User ID:         AIDA5C76TR3KVHWFEQSDL
[+]   Creation Date:   2019-06-14 18:18:35 UTC
[+]   Tags:            []
[+]   Groups:          ["mygroup", "mygroup2"]
[+]   SSH Pub Keys:    []
[+]   Policies:        IAMUserChangePassword
[+]   Signing certs:   []
[+]   Password Used:   (Never)
[+]   AWS Access Keys: AKIA5C76TR3KXHXA5CRC (Inactive)
[+]   Console login:   Enabled
[+]   Two-factor auth: Disabled
[*] 
[+]   User Name:       test3
[+]   User ID:         AIDA5C76TR3KYI2HC4MOL
[+]   Creation Date:   2019-06-14 18:18:44 UTC
[+]   Tags:            []
[+]   Groups:          ["mygroup"]
[+]   SSH Pub Keys:    []
[+]   Policies:        []
[+]   Signing certs:   []
[+]   Password Used:   (Never)
[+]   AWS Access Keys: AKIA5C76TR3KWWADYZNB (Active)
[+]   Console login:   Disabled
[+]   Two-factor auth: Disabled
[*] 
[*] Auxiliary module execution completed
```
  
### Provided an invalid or inactive 'access key ID'

```
msf5 auxiliary(cloud/aws/enum_iam) > run

[-] Auxiliary aborted due to failure: unexpected-reply: The security token included in the request is invalid.
[*] Auxiliary module execution completed
msf5 auxiliary(cloud/aws/enum_iam) >
```
  
### Provided an invalid 'secret access key'

```
msf5 auxiliary(cloud/aws/enum_iam) > run

[-] Auxiliary aborted due to failure: unexpected-reply: The request signature we calculated does not match the signature you provided. Check your AWS Secret Access Key and signing method. Consult the service documentation for details.
[*] Auxiliary module execution completed
msf5 auxiliary(cloud/aws/enum_iam) > 
```

### Provided an 'access key ID' or 'secret access key' with insufficient privileges

```
msf5 auxiliary(cloud\aws\enum_ec2) > run

[-] Auxiliary aborted due to failure: unexpected-reply: User: arn:aws:iam::899712345657:user/test1 is not authorized to perform: iam:ListUsers on resource: arn:aws:iam::899712345657:user/
[*] Auxiliary module execution completed
msf5 auxiliary(cloud\aws\enum_ec2) > 
```
