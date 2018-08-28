The Metasploit Remote Data service is a tool that allows you to host a web service to interact
with Metasploit's various data models through a REST API.

### Requirements
To use the remote data service you will need a PostgreSQL database running to serve as the backend. You can find more information on setting that up on the 
[Metasploit help page](https://metasploit.help.rapid7.com/docs/managing-the-database).

### Starting Up
To start up the web server, navigate to the root directory of metasploit-framework and run the
following command: `./msfdb_ws`

Command line options:

 - `-i`,`--interface` Specify the interface for the web service to listen on. Default: 0.0.0.0
 - `-p`,`--port` Specify the port for the web service to listen on. Default: 8080
 - `-s`,`--ssl` Enable SSL on the web server.
 - `-c`,`--cert /path/to/cert_file` Path to SSL certificate file. Required if `-s` is set.
 - `-k`,`--key /path/to/key_file` Path to SSL Key file.
 - `-h`,`--help` Display the help information.
 
### Accessing the API
The API can be accessed by utilizing your preferred HTTP client of choice. You can find more
information on the data models and various endpoints by connecting to the following URL:

http://\<interface\>:\<port\>/api/v1/api-docs

## Utilizing the Data Service in msfconsole

### Connecting
You can use the `db_connect` command to connect to the desired data service. Please note that you can only be connected to one data service at a time. The `db_disconnect` command will need to be used before switching to a new data service. You can use `db_status` to see information about the currently connected data service.

**Usage:**
* `db_connect <options> <url>`
* Options:
  * `-l`,`--list-services` - List the available data services that have been previously saved.")
  * `-n`,`--name` - Connect to a previously saved data service by specifying the name.")
  * `-c`,`--cert` - Certificate file matching the remote data server's certificate. Needed when using self-signed SSL cert.
  * `-t`,`--token` - The API token used to authenticate to the remote data service.
  * `--skip-verify` - Skip validating authenticity of server's certificate. NOT RECOMMENDED.
* Examples:
  * `db_connect http://localhost:8080` - Connect to the Metasploit REST API instance at localhost running on port 8080
  * `db_connect -c ~/.msf4/msf-ws-cert.pem -t 72ce00fd9ab1a96970137e5a12faa12f38dcc4a9e42158bdd3ce7043c65f5ca37b862f3faf3630d2 https://localhost:8080` - Connect to the server running at localhost on port 8080 that has SSL and authentication enabled.
  * `db_connect -l` - List the data services that have been saved using the `db_save` command.
  * `db_connect -n LA_server` - Connect to the data service named "LA_server" that has been previously saved using `db_save`.
* URL Formats
 * HTTP - `http://<host>:<port>`
 * HTTPS - `https://<host>:<port>`
 * Postgres - `<user>:<password>@<host>:<port>/<database name>`


### Saving the Connection
The currently connected data service can be saved for later use using the `db_save` command. The `default` connection is the data service that msfconsole will connect to on startup.

**Usage:**
* `db_save <options> <name>`
* Options:
  * `-d`,`--default` - Set this data service as the default connection.
  * `-c`,`--clear-default` - Clear the currently set default data service.
  * `--delete` - Delete the specified data service.
* Examples:
  * `db_save new_york_server` - Save the current connection as "new_york_server".
  * `db_save -d LA_server` - Save the current connection as "LA_server" and set it as the default.
  * `db-save --delete new_york_server` - Delete the "new_york_server" entry.

### Notes ###
There are a few pieces of information to keep in mind when using data services with Metasploit Framework.
* A Postgres database connection is required before connecting to a remote data service.
* The configuration from the `database.yml` will still be honored for the foreseeable future, but a saved default data service will take priority when it is present.

