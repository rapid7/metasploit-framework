## What is msfdb?
msfdb is a script included with all installations of Metasploit that allows you to easily setup and control both a database and a Web Service capable of connecting this database with Metasploit.

While msfdb is the simplest method for setting up a database, you can also set one up manually. Instructions on manual setup can be found [here](https://metasploit.help.rapid7.com/docs/managing-the-database).

## Why should I use msfdb?
It's not mandatory to use a database with Metasploit, it can run perfectly fine without one. However, a lot of the features that makes Metasploit so great require a database, and msfdb is the simplest way to setup a Metasploit compatible database.

The Metasploit features that require a connected database include:
* Recording other machines on a network that are found with a nmap scan via the `db_nmap` command are stored as "Hosts".
  * Hosts can be viewed with the `hosts` command
* Storing credentials successfully extracted by exploits are stored as "creds".
  * Credentials are viewed with the `creds` command.
* Keeping track of successful exploitation attempts are recorded as "Vulnerabilities".
  * Successful exploitations can be viewed with the `vulns` command.
  * The `vulns` command also tracks unsuccessful exploitation attempts
* Storing services detected on remote hosts by `db_nmap` are recorded as "Services"
  * Remote services are viewed with the `services` command
* Tracking multiple remote sessions opened by exploit payloads
  * These sessions can be managed and tracked with the `sessions` command.
* Storing any difficult to define information returned by successful exploits as "Loot"
  * Viewable with the `loot` command
* Keeping track of "Ping back payloads", a non-interactive payload type that provides users with confirmation of remote execution on a target
* Pivot through a network with "Routes" comprised of active sessions
  * Viewable with the `routes` command
* Building reports comprising all of the above information (Restricted to Pro users)

All of the above features can also be logically separated within workspaces. By using the `workspace` command, you can place the results of certain operations in different workspaces. This helps keep any data generated or recorded during your use of Metasploit organized and easy to follow.

## Using msfdb

Using msfdb is simple. If you are starting the database for the first time navigate to the folder Metasploit is saved to, and run `./msfdb init`
```
Creating database at /Users/your_current_account_name/.msf4/db
Starting database at /Users/your_current_account_name/.msf4/db...success
Creating database users
Writing client authentication configuration file /Users/your_current_account_name/.msf4/db/pg_hba.conf
Starting database at /Users/your_current_account_name/.msf4/db...success
Creating initial database schema
```

This looks like a lot of information, but all it's saying is that it's creating the database Metasploit will use to store information.  If you start up msfconsole now it should automatically connect to the database, and if you run `db_status` you should see something like this:

```
msf6 > db_status
[*] Connected to msf. Connection type: postgresql.
```

You can also setup a Web Service, which Metasploit can use to connect to the database you have just created.  Msfdb needs to establish the credentials that are used in the Web Service. If you run `msfdb --component webservice init` the first prompt asks you what username you want to use to connect to the database:

```
[?] Initial MSF web service account username? [your_current_account_name]:
```

Then the password used to authenticate to the Web Service:

```
[?] Initial MSF web service account password? (Leave blank for random password):
```

Hitting `enter` for both these prompts will setup up the Web Service correctly. You can change these defaults and use a specific username and password if you want, but it's not necessary.

After these two prompts are dealt with, your Web Service will start!

```
Generating SSL key and certificate for MSF web service
Attempting to start MSF web service...success
MSF web service started and online
Creating MSF web service user your_current_account_name

    ############################################################
    ##              MSF Web Service Credentials               ##
    ##                                                        ##
    ##        Please store these credentials securely.        ##
    ##    You will need them to connect to the webservice.    ##
    ############################################################

MSF web service username: your_current_account_name
MSF web service password: super_secret_password
MSF web service user API token: super_secret_api_token


MSF web service configuration complete
The web service has been configured as your default data service in msfconsole with the name "local-https-data-service"

If needed, manually reconnect to the data service in msfconsole using the command:
db_connect --token super_secret_api_token --cert /Users/your_current_account_name/.msf4/msf-ws-cert.pem --skip-verify https://localhost:5443

The username and password are credentials for the API account:
https://localhost:5443/api/v1/auth/account
```

Again, this is a lot of information to process, but it's not nearly as complicated as it looks. The Username, Password, and API token used to connect to the Web Service is displayed:

```
MSF web service username: your_current_account_name
MSF web service password: super_secret_password
MSF web service user API token: super_secret_api_token
```

Followed by instructions on how to connect to your database with Metasploit via the Web Service:

```
If needed, manually reconnect to the data service in msfconsole using the command:
db_connect --token super_secret_api_token --cert /Users/your_current_account_name/.msf4/msf-ws-cert.pem --skip-verify https://localhost:5443
```

And the URL you can visit with your browser in order to connect to the Web Service  This is useful for checking if the Web Service is running:

```
The username and password are credentials for the API account:
https://localhost:5443/api/v1/auth/account
```

All this information is loaded by Metasploit automatically at startup from the ~/.msf4 folder. You should copy the credentials to a file in case you need them in the future. If you forget or lose the credentials but you can always run `./msfdb reinit` and reset the Web Service authentication details. **Just make sure to say no to the prompt asking you if you want to delete the Database contents!**

## msfdb commands

The commands for msfdb are as follows:
*   `./msfdb init`     Creates and begins execution of a database & web service. Additional prompts displayed after this command is executed allows optional configuration of both the username and the password used to connect to the database via the web service. Web service usernames and passwords can be set to a default value, or a value of the users choice.
*   `./msfdb delete`   Deletes the web service and database configuration files. You will also be prompted to delete the database's contents, but this is not mandatory.
*   `./msfdb reinit`   The same as running `./msfdb delete` followed immediately by `./msfdb init`.
*   `./msfdb status`   Displays if the database & web service are currently active. If the database is active it displays the path to its location. If the web service is active, the Process ID it has been assigned will be displayed.
*   `./msfdb start`    Start the database & web service.
*   `./msfdb stop`     Stop the database & web service.
*   `./msfdb restart`  The same as running `./msfdb stop` followed immediately by `./msfdb start`.

## msfdb errors

In the case of any of the above commands printing either a stack trace or error, your first step should be to run `./msfdb reinit` (again making sure to say no to the prompt asking you if you want to delete the Database contents) and reattempt the command that caused the error. If the error persists, copy the command you executed, the output generated, and paste it into an [error ticket](https://github.com/rapid7/metasploit-framework/issues/new/choose).

## What's next?
That's it for the simple high level explanation of how to setup a database for metasploit. If that wasn't enough detail for you you can check out our more in depth explanation [[here|./Metasploit-Web-Service.md]].

If you want to get started hacking but don't know how to, here are a few guides we really like:
* [The easiest metasploit guide you'll ever read](https://www.exploit-db.com/docs/english/44040-the-easiest-metasploit-guide-you%E2%80%99ll-ever-read.pdf) - A great, easy to follow guide on how to set up Metasploit and Metasploitable (Our intentionally vulnerable Linux virtual machine used to for security training) for VMs. Also has a fantastic guide on penetration testing Metasploitable 2, from information gathering right up to exploitation.
* [Offensive Security: Metasploit Unleashed](https://www.offensive-security.com/metasploit-unleashed/) - Still dealing with Metasploitable 2, this guide covers similar content as the [The easiest metasploit guide you'll ever read](https://www.exploit-db.com/docs/english/44040-the-easiest-metasploit-guide-you%E2%80%99ll-ever-read.pdf), but with much more detail.

However, if you're confident in your knowledge of Metasploit and just want to get stuck in, then get stuck in! Good luck, be nice and have fun.

