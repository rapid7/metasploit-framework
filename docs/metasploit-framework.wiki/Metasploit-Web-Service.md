The Metasploit web service allows interaction with Metasploit's various data models through a REST API.

## Managing the Web Service

### Requirements
To use the web service you will need a PostgreSQL database to serve as the backend data store. The `msfdb` tool allows you to manage both the Metasploit Framework database and web service. If you are going to configure the database manually you can find more information on the [Managing the Database](https://metasploit.help.rapid7.com/docs/managing-the-database) page.

### Getting Started

#### Initialize the Database and Web Service
Execute `msfdb init` and respond to prompts during the interactive initialization. The script first creates and configures the database, then it configures the web service, and finally configures the local `msfconsole` with the new data service connection.

#### msfdb

The `msfdb` tool allows you to manage both the Metasploit Framework database and web service components together or independently. If the `--component` option is not provided then the specified command will be executed for the database followed by the web service. This default mode of operation is useful when first setting up the database and web service. The component may be specified if you wish to make changes to a given component independent of the other.

**Usage:** `msfdb [options] <command>`
* Options:
  * Execute `msfdb --help` for the complete usage information
* Commands:
  * init - initialize the component
  * reinit - delete and reinitialize the component
  * delete - delete and stop the component
  * status - check component status
  * start - start the component
  * stop - stop the component
  * restart - restart the component

##### Examples
* `msfdb start` - Start the database and web service
* `msfdb --component webservice stop` - Stop the web service
* `msfdb --component webservice --address 0.0.0.0 start` - Start the web service, listening on any host address

#### Notes
* SSL is enabled by default and `msfdb` will generate a fake "snakeoil" SSL certificate during initialization using `Rex::Socket::Ssl.ssl_generate_certificate` if one is not provided. The generated SSL certificate uses a random common name (CN) which will not match your hostname, therefore, you will need to make appropriate accommodations when operating the web service with such a certificate. **Please** generate your own SSL certificate and key instead and supply those to `msfdb` using the `--ssl-cert-file` and `--ssl-key-file` options, and enable SSL verification by passing the option `--no-ssl-disable-verify`.

* A simple verification that web service is up and running can be performed using cURL: `curl --insecure -H "Accept: application/json" -H "Authorization: Bearer <token>" https://localhost:5443/api/v1/msf/version`

### Accessing the API
The API account can be accessed with your preferred web browser by visiting `https://<address>:<port>/api/v1/auth/account`. If you want to change the API token for your account you can log in to the API account page and generate a new API token. You can find more
information on the data models and various API endpoints by visiting the API Documentation at: `https://<address>:<port>/api/v1/api-docs`

## Utilizing the Data Service in msfconsole

### Connecting
You can use the `db_connect` command to connect to the desired data service. When you successfully connect to a data service that connection will be saved in the Metasploit config file. You can provide a name with the `-n` option, otherwise one will be randomly generated. You can then use that name to reconnect to the data service at a later time.

Please note that you can only be connected to one data service at a time. The `db_disconnect` command will need to be used before switching to a new data service. You can use `db_status` to see information about the currently connected data service.

**Usage:** `db_connect <options> <url>`
* Options:
  * `-l`,`--list-services` - List the available data services that have been previously saved.
  * `-y`,`--yaml` - Connect to the data service specified in the provided database.yml file.
  * `-n`,`--name` - Name used to store the connection. Providing an existing name will overwrite the settings for that connection.
  * `-c`,`--cert` - Certificate file matching the remote data server's certificate. Needed when using self-signed SSL cert.
  * `-t`,`--token` - The API token used to authenticate to the remote data service.
  * `--skip-verify` - Skip validating authenticity of server's certificate (NOT RECOMMENDED).
* Examples:
  * `db_connect http://localhost:5443` - Connect to the Metasploit REST API instance at localhost running on port 5443
  * `db_connect -c ~/.msf4/msf-ws-cert.pem -t 72ce00fd9ab1a96970137e5a12faa12f38dcc4a9e42158bdd3ce7043c65f5ca37b862f3faf3630d2 https://localhost:5443` - Connect to the server running at localhost on port 5443 that has SSL and authentication enabled.
  * `db_connect -l` - List the data services that have been saved.
  * `db_connect -n LA_server http://localhost:5443` - Connect to the data service running on localhost port 5443 and assign the name "LA_server" to the saved entry.
* URL Formats
  * HTTP - `http://<host>:<port>`
  * HTTPS - `https://<host>:<port>`
  * Postgres - `<user>:<password>@<host>:<port>/<database name>`

### Setting a Default Data Service
The `db_save` command can be used to save the currently connected data service as the default. Every time msfconsole starts up it will attempt to connect to that data service. You can always switch between data services if you have a default set, this will just determine which data service you are connected to when msfconsole is started.

**Usage:** `db_save`
* Examples:
  * `db_connect http://localhost:5443` then `db_save` - Connect to the data service running on localhost port 5443 then set it as the default connection.

### Removing Saved Data Services
Saved data services can be removed using the `db_remove` command. This can be useful if the data service no longer exists at that location, or if you no longer want to keep a record of it around for fast connection.

**Usage:** `db_remove <name>`
 * Examples:
   * `db_remove LA_server` - Remove the saved data service entry called "LA_server"

### Notes
There are a few pieces of information to keep in mind when using data services with Metasploit Framework.
* Specifying the name of an existing saved data service connection will overwrite those settings.
* A data service must already have an existing entry in the list of saved data services to be set as the default. Data services that were connected to using a database.yml file cannot be saved as default using this method.
* A Postgres database connection is required before connecting to a remote data service.
* The configuration from the `database.yml` will still be honored for the foreseeable future, but a saved default data service will take priority when it is present.
* The saved data services are stored in the Metasploit config file, which is located at `~/.msf4/config` by default.

