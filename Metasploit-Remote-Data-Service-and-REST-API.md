The Metasploit Remote Data service is a tool that allows you to host a web service to interact
with Metasploit's various data models through a REST API.

### Requirements.
You can find more information on setting that up on the 
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