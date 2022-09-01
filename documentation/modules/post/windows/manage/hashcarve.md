## Overview
This module changes a user's password by carving a hash in the windows registry. 

1. It doesn't change the "password last changed" field
2. You can set a hash directly, so you can change a user's password and revert it without cracking it's hash.
3. It bypasses the password complexity requirements

## Options
- **USER** - This option allows you to specify the user you wish to change the password of. 
- **PASS** - This option allows you to specify the password to be set in the form of a clear text password, a single NT hash, or a couple of LM:NT hashes.  

## Module Process
Here is the process that the module follows:

- Retrieves list of users from the registry.
- If the user is found it attempts to:
    - load the user key from the registry
    - check if the lm and nt hashes exit in the key
    - replace the hashes if they exist
    - write they user key back into the registry

## Recommandations
I would recommand to use hashdump before using the module to backup the user hashes
Use at your own risk.

## Limitations

At some point, Windows 10 stopped storing users in that exact way, users whose password was set after that change would not be vulnerable. This will be updated once someone figures how the hashes are now stored.

The module does not modify the user key architecture, you cannot set a hash on a user that does not have a password.

## Usage
- run post/windows/manage/hashcarve user=test pass=password
- run post/windows/manage/hashcarve user=test pass=nthash
- run post/windows/manage/hashcarve user=test pass=lmhash:nthash
