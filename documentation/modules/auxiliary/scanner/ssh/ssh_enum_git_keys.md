## Introduction

This module attempts to authenticate to Git servers using compromised SSH private keys. This module can be used to check a single key or recursively look through a directory.

## Setup

1. `ssh-keygen -b 2048 -t rsa`
2. Add the RSA pubic key to a GitHub or GitLab account (Public ends in .pub)
3. Follow the usage instructions below
4. Either use KEY_FILE or KEY_DIR to specify the generated SSH private key
5. Run the module
6. Observe that it will identify the GitHub/GitLab user that this key belongs to

## Usage

```
msf5 > use auxiliary/scanner/ssh/ssh_enum_git_keys
msf5 auxiliary(scanner/ssh/ssh_enum_git_keys) > set KEY_DIR /Users/w/.ssh
KEY_DIR => /Users/w/.ssh
msf5 auxiliary(scanner/ssh/ssh_enum_git_keys) > run

Git Access Data
===============

Key Location              User Access
------------              -----------
/Users/w/.ssh/id_ed25519  wdahlenburg
```
## Post Exploitation

Once you have identified a Git user from an SSH key, there are two immediate possibilities.

1. Download private repositories that the owner knows
2. Modify public repositories and inject a backdoor

