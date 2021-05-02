## Vulnerable Application

Amazon Web Services (AWS) resources can be managed through an API that authenticates based on an `ACCESS_KEY_ID` and a `SECRET_ACCESS_KEY`.  With these two pieces of information, an attacker can gain privileges which may include enumerating resources within the AWS account.

This module authenticates to AWS IAM (Identify Access Module) to identify user accounts that the credentials can see.  The users themselves are likely protected with different credentials, including passwords or MFA tokens.  In any case, knowledge of the users is the first step in evaluating their security.

## Verification Steps

### Create or acquire the credentials

  1. (If necessary) Create an AWS account.  Free trials are available.
  2. Login to the [AWS Console](https:\\console.aws.amazon.com\).
  3. Use the dropbown menu in the top-right with your username, then click on "My Security Credentials".
  4. Expand the "Access Keys" pane and click  "Create New Access Key".
  5. Follow the steps in the AWS console, making sure to record both the 'access key ID' and 'secret access key'.  (The 'secret access key' is only shown once, then can never be retrieved.)

### Enumerate AWS resources using the credentials

  1. Start msfconsole
  2. `use auxiliary/cloud/aws/enum_iam`
  3. Set the `ACCESS_KEY_ID` and `SECRET_ACCESS_KEY` options.
  4. `run`

## Options

  **ACCESS_KEY_ID**

  This AWS credential is like a username.  It uniquely identifies the user, and is paired with a 'secret access key'.  The access key ID is retrievable through the AWS console.
  
  An example `ACCESS_KEY_ID` would be `AKIA5C76TR3KXHXA5CRC`

  **SECRET_ACCESS_KEY**

  This AWS credential is like a password, and should be treated as such.  It is paired with a 'access key ID'.  The access key ID cannot be retrieved from AWS after it has been generated, but it may be discoverable through environment variables, configuration files, source code, or backups.
  
  An example `SECRET_ACCESS_KEY` would be `EKfx3wOWWiGk1WgBTAZfF\2dq3SbDsQj4jdyOMOv`.

  **REGION**

  AWS resources are located in regions.  Optionally, this module's output can be filtered based on region to minimize the query to AWS.  Alternatively, `REGION` can be left blank, such that all regions will be checked.
  
  An example region would be `us-west-2`.

  **LIMIT**

  Some AWS API calls support limiting output, such that the module will only reutrn the number of instances, without detailing the configuration of each instance.  Optionally, this module's output can be filtered to minimize the query to AWS and the user output.  Alternatively, `LIMIT` can be left blank, such that all EC2 instances will be detailed.
  
  Note that the `LIMIT` parameter is imposed per region, so the total number of results may be higher than the user-specified limit, but the maximum number of results for a single region will not exceed `LIMIT`.  This behavior is due to the AWS API.
  
  An example `LIMIT` would be `10`.

## Scenarios

### Provided a valid 'access key ID' and 'secret access key' with sufficient privileges 

```
msf5 auxiliary(cloud/aws/enum_ec2) > run

[*] Found 0 instances in eu-north-1
[*] Found 0 instances in ap-south-1
[*] Found 0 instances in eu-west-3
[*] Found 0 instances in eu-west-2
[*] Found 0 instances in eu-west-1
[*] Found 0 instances in ap-northeast-2
[*] Found 0 instances in ap-northeast-1
[*] Found 0 instances in sa-east-1
[*] Found 0 instances in ca-central-1
[*] Found 0 instances in ap-southeast-1
[*] Found 0 instances in ap-southeast-2
[*] Found 0 instances in eu-central-1
[*] Found 0 instances in us-east-1
[*] Found 0 instances in us-east-2
[*] Found 0 instances in us-west-1
[*] Found 1 instances in us-west-2
[+]   i-0f8bb3bbb06faf58d (running)
[+]     Creation Date:  2019-06-11 23:14:48 UTC
[+]     Public IP:      18.236.87.255 (ec2-18-236-87-255.us-west-2.compute.amazonaws.com)
[+]     Private IP:     18.236.87.255 (ip-172-31-30-21.us-west-2.compute.internal)
[+]     Security Group: sg-0d52cc35aaf82aff5
[*] Auxiliary module execution completed
msf5 auxiliary(cloud/aws/enum_ec2) > 
```
  
### Provided an invalid or inactive 'access key ID', or an invalid 'secret access key'

```
msf5 auxiliary(cloud\aws\enum_ec2) > run

[-] Auxiliary aborted due to failure: unexpected-reply: AWS was not able to validate the provided access credentials
[*] Auxiliary module execution completed
msf5 auxiliary(cloud\aws\enum_ec2) > 
```

### Provided an 'access key ID' or 'secret access key' with insufficient privileges

```
msf5 auxiliary(cloud\aws\enum_ec2) > run

[-] Auxiliary aborted due to failure: unexpected-reply: You are not authorized to perform this operation.
[*] Auxiliary module execution completed
msf5 auxiliary(cloud\aws\enum_ec2) > 
```
