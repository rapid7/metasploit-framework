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
The `db_connect` command can be used to connect to the remote data service, or a Postgres database, to enable data storage.

### Connecting
To connect, enter `db_connect <url>` in msfconsole. The URL can be either an http(s) string pointing to a remote data store, such as `http://127.0.0.1:8080` or `https://127.0.0.1:8080`, or a custom Postgres string such as `user:password@127.0.0.1:8080/database_name`.


### Saving the Connection
Data services can be saved for later use using the `db_save` command.

**Usage:**
* `db_save <options> <name>`
* Options:
  * `-d`,`--default` - Set this data service as the default connection.
  * `-c`,`--clear-default` - Clear the currently set default data service.
  * `--delete` - Delete the specified data service.
* Examples:
  * `db_save new_york_server` - Save the current connection as "new_york_server".
  * `db_save -d la_server` - Save the current connection as "la_server" and set it as the default.
  * `db-save --delete new_york_server` - Delete the "new_york_server" entry.
