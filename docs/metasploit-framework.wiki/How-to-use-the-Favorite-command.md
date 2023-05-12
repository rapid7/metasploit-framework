# Using the Favorite Command

`favorite` is an `msfconsole` command that allows users to easily keep track of their most-used modules. The favorites list is stored in the `.msf4/fav_modules` file.

### Adding modules to the favorites list

There are two methods of adding a module to the favorites list. The first way is via simply calling `favorite` when there is an active module:

```shell
msf6 exploit(multi/handler) > favorite
[+] Added exploit/multi/handler to the favorite modules file
```


Using the active module without an active module will print the `favorite` command help output:

```shell
msf6 > favorite
[-] No module has been provided to favorite.
Usage: favorite [mod1 mod2 ...]

Add one or multiple modules to the list of favorite modules stored in /home/msf/.msf4/fav_modules
If no module name is specified, the command will add the active module if there is one

OPTIONS:

    -c        Clear the contents of the favorite modules file
    -d        Delete module(s) or the current active module from the favorite modules file
    -h        Help banner
    -l        Print the list of favorite modules (alias for `show favorites`)
```



The second method of adding favorites allows adding multiple modules at once:

```msf
msf6 > favorite exploit/multi/handler exploit/windows/smb/psexec
[+] Added exploit/multi/handler to the favorite modules file
[+] Added exploit/windows/smb/psexec to the favorite modules file
msf6 > show favorites

Favorites
=========

   #  Name                        Disclosure Date  Rank    Check  Description
   -  ----                        ---------------  ----    -----  -----------
   0  exploit/multi/handler                        manual  No     Generic Payload Handler
   1  exploit/windows/smb/psexec  1999-01-01       manual  No     Microsoft Windows Authenticated User Code Execution


```


### Deleting modules from the favorites list

Modules can be deleted from the favorites list individually or by clearing the contents of the list. For the former, simply use the `-d` flag and either supply the module name or use the currently active module if that module is in the favorites list. For the latter, supply the `-c` flag.

#### Deleting an active module from favorites list

```shell
msf6 exploit(multi/handler) > favorite -d
[*] Removing exploit/multi/handler from the favorite modules file
```

#### Specifying module(s) to delete

```shell
msf6 > favorite -d exploit/multi/handler exploit/windows/smb/psexec
[*] Removing exploit/multi/handler from the favorite modules file
[*] Removing exploit/windows/smb/psexec from the favorite modules file
```

#### Clearing the favorites list

```msf
msf6 > show favorites

Favorites
=========

   #  Name                        Disclosure Date  Rank    Check  Description
   -  ----                        ---------------  ----    -----  -----------
   0  exploit/multi/handler                        manual  No     Generic Payload Handler
   1  exploit/windows/smb/psexec  1999-01-01       manual  No     Microsoft Windows Authenticated User Code Execution

msf6 > favorite -c
[+] Favorite modules file cleared
msf6 > show favorites
[!] The favorite modules file is empty
```

### Printing the list of favorite modules

The list of favorite modules can be printed by supplying the `-l` flag. This is an alias for the `show favorites` and `favorites` commands.

```shell
msf6 > favorite -l

Favorites
=========

   #  Name                        Disclosure Date  Rank    Check  Description
   -  ----                        ---------------  ----    -----  -----------
   0  exploit/multi/handler                        manual  No     Generic Payload Handler
   1  exploit/windows/smb/psexec  1999-01-01       manual  No     Microsoft Windows Authenticated User Code Execution
```