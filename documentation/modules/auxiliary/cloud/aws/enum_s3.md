## Vulnerable Application

Amazon Web Services is a cloud-based hosting solution for servers, files, and countless specialized tools.  AWS resources can be managed through an API that authenticates based on an `ACCESS_KEY_ID` and a `SECRET_ACCESS_KEY`.  With these two pieces of information, an attacker can gain privileges which may include enumerating resources within the AWS account.

This module authenticates to AWS S3 (Simple Storage Service), to identify buckets that the account can see.  The files contained within buckets may be publicly readable and/or writable, or they may be locked down.  In any case, knowledge of the buckets is the first step in evaluating their security.

## Verification Steps

### Create or acquire the credentials

  1. (If necessary) Create an AWS account.  Free trials are available.
  2. Login to the [AWS Console](https://console.aws.amazon.com/).
  3. Use the dropbown menu in the top-right with your username, then click on "My Security Credentials".
  4. Expand the "Access Keys" pane and click  "Create New Access Key".
  5. Follow the steps in the AWS console, making sure to record both the 'access key ID' and 'secret access key'.  (The 'secret access key' is only shown once, then can never be retrieved.)

### Enumerate AWS resources using the credentials

  1. Start msfconsole
  2. `use auxiliary/cloud/aws/enum_s3`
  3. Set ACCESS_KEY_ID and SECRET_ACCESS_KEY options.
  4. `run`

## Options

  **ACCESS_KEY_ID**

  This AWS credential is like a username.  It uniquely identifies the user, and is paired with a 'secret access key'.  The access key ID is retrievable through the AWS console.
  
  An example `ACCESS_KEY_ID` would be `AKIA5C76TR3KXHXA5CRC`

  **SECRET_ACCESS_KEY**

  This AWS credential is like a password, and should be treated as such.  It is paired with a 'access key ID'.  The access key ID cannot be retrieved from AWS after it has been generated, but it may be discoverable through environment variables, configuration files, source code, or backups.\
  
  An example `SECRET_ACCESS_KEY` would be `EKfx3wOWWiGk1WgBTAZfF/2dq3SbDsQj4jdyOMOv`.

  **REGION**

  AWS resources are located in regions.  Optionally, this module's output can be filtered based on region to minimize the query to AWS.  Alternatively, `REGION` can be left blank, such that all regions will be checked.
  
  An example region would be `us-west-2`.

## Scenarios

### Provided a valid 'access key ID' and 'secret access key' with sufficient privileges 

```
msf5 auxiliary(cloud/aws/enum_s3) > run
[+] Found 1 buckets.
[+]   Name:           asoto-secret-demo-bucket
[+]   Creation Date:  2019-06-13 23:30:26 UTC
[+]   # of Objects:   0
[+]   Region:         us-west-2
[+]   Website:        /index.html
[+]   Owner:          asoto
[+]   Permissions:
[+]                   User 'asoto' granted FULL_CONTROL
[+]                   Group '' (http://acs.amazonaws.com/groups/s3/LogDelivery) granted READ
[*] 
[*] Done.
[*] Auxiliary module execution completed
msf5 auxiliary(cloud/aws/enum_s3) > exit
```
  
### Provided an invalid or inactive 'access key ID'

```
msf5 auxiliary(cloud/aws/enum_s3) > run

[-] Auxiliary aborted due to failure: unexpected-reply: The AWS Access Key Id you provided does not exist in our records.
[*] Auxiliary module execution completed
msf5 auxiliary(cloud/aws/enum_s3) >
```
  
### Provided an invalid 'secret access key'

```
msf5 auxiliary(cloud/aws/enum_s3) > run

[-] Auxiliary aborted due to failure: unexpected-reply: The request signature we calculated does not match the signature you provided. Check your key and signing method.
[*] Auxiliary module execution completed
msf5 auxiliary(cloud/aws/enum_s3) > 
```

### Provided an 'access key ID' or 'secret access key' with insufficient privileges

```
msf5 auxiliary(cloud/aws/enum_s3) > run

[-] Auxiliary aborted due to failure: unexpected-reply: Access Denied
[*] Auxiliary module execution completed
msf5 auxiliary(cloud/aws/enum_s3) > 
```
