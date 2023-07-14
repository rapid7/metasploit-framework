The RPC API enables you to programmatically drive the Metasploit Framework and commercial products using HTTP-based remote procedure call (RPC) services. An RPC service is a collection of message types and remote methods that provide a structured way for external applications to interact with web applications. You can use the RPC interface to locally or remotely execute Metasploit commands to perform basic tasks like running modules, communicating with the database, interacting with sessions, exporting data, and generating reports.

The Metasploit products are written primarily in Ruby, which is the easiest way to use the remote API. However, in addition to Ruby, any language with support for HTTPS and MessagePack, such as Python, Java, and C, can be used to take advantage of the RPC API.

There are currently two implementations of Metasploit's RPC:

- HTTP and messagepack - covered by a separate guide
- HTTP and JSON - covered by this guide

Note that both the messagepack and JSON RPC services provide very similar operations, and it is worth reviewing both documents.

## Starting the JSON API Server

The pre-requisite to running the JSON API Server is to run your Metasploit database. This can be initialized with `msfdb`.
Note that `msfdb` will ask if you wish to run the JSON RPC web service - but it is not required for this guide which
shows how to run the JSON service directly with [thin](https://github.com/macournoyer/thin) or [Puma](https://github.com/puma/puma): 

First run the Metasploit database:

```
msfdb init
```

After configuring the database the JSON RPC service can be initialized with the [thin](https://github.com/macournoyer/thin) Ruby web server:

```
bundle exec thin --rackup msf-json-rpc.ru --address 0.0.0.0 --port 8081 --environment production --tag msf-json-rpc start
```

Or with [Puma](https://github.com/puma/puma):

```
bundle exec puma msf-json-rpc.ru --port 8081 --environment production --tag msf-json-rpc start
```

### Development

If you are wanting to develop or debug the Ruby implementation of the JSON RPC service - it can be useful to run the Metasploit API synchronously in the foreground.
This allows for console logs to appear directly in the terminal, as well as being able to interact with breakpoints via `require 'pry-byebug'; binding.pry`:

It is possible to debug Msfconsole's webservice component too:

```
bundle exec ruby ./msfdb reinit
bundle exec ruby ./msfdb --component webservice stop
bundle exec ruby ./msfdb --component webservice --no-daemon start
```

### RPC Logging

You can configure the RPC service logging with the `MSF_WS_DATA_SERVICE_LOGGER` environment variable. 

The list of supported loggers is viewable with `msfconsole --help`. The list at the time of writing is:

- Stdout / Stderr / StdoutWithoutTimestamps - Write logs to stdout/stderr
- Flatfile / TimestampColorlessFlatfile  - Write logs to `~/.msf4/logs`

Example usage:

```
$ MSF_WS_DATA_SERVICE_LOGGER=Stdout bundle exec thin --rackup msf-json-rpc.ru --address localhost --port 8081 --environment production --tag msf-json-rpc start
[11/25/2020 17:34:53] [e(0)] core: Dependency for windows/encrypted_shell_reverse_tcp is not supported
[11/25/2020 17:34:53] [e(0)] core: Dependency for windows/x64/encrypted_shell_reverse_tcp is not supported
[11/25/2020 17:34:53] [e(0)] core: Dependency for windows/encrypted_reverse_tcp is not supported
[11/25/2020 17:34:53] [e(0)] core: Dependency for windows/x64/encrypted_reverse_tcp is not supported
[11/25/2020 17:34:54] [e(0)] core: Unable to load module /Users/adfoster/Documents/code/metasploit-framework/modules/auxiliary/gather/office365userenum.py - LoadError  Try running file manually to check for errors or dependency issues.
Thin web server (v1.7.2 codename Bachmanity)
Maximum connections set to 1024
Listening on localhost:8081, CTRL+C to stop
[11/25/2020 17:35:17] [d(0)] core: Already established connection to postgresql, so reusing active connection.
[11/25/2020 17:35:17] [e(0)] core: DB.connect threw an exception - ActiveRecord::AdapterNotSpecified database configuration does not specify adapter
[11/25/2020 17:35:17] [e(0)] core: Failed to connect to the database: database configuration does not specify adapter```
```

## Concepts

The Metasploit RPC aims to follow the [jsonrpc specification](https://www.jsonrpc.org/specification). Therefore:

- Each JSON RPC request should provide a unique message ID which the client and server can use to correlate requests and responses
- Metasploit may return the following [error codes](https://github.com/rapid7/metasploit-framework/blob/87b1f3b602753e39226a475a5d737fb50200957d/lib/msf/core/rpc/json/error.rb#L3-L13).

## Examples 

First ensure you are running the Metasploit database, and are running the JSON service before running these examples

### Querying

#### Query DB status

Request:

```sh
curl --request POST \
  --url http://localhost:8081/api/v1/json-rpc \
  --header 'Content-Type: application/json' \
  --data '{
        "jsonrpc": "2.0",
        "method": "db.status",
        "id": 1,
        "params": []
}'
```

Response:

```json
{
  "jsonrpc": "2.0",
  "result": {
    "driver": "postgresql",
    "db": "msf"
  },
  "id": 1
}
```

#### Query workspaces

Request:

```sh
curl --request POST \
  --url http://localhost:8081/api/v1/json-rpc \
  --header 'Content-Type: application/json' \
  --data '{
        "jsonrpc": "2.0",
        "method": "db.workspaces",
        "id": 1,
        "params": []
}'
```

Response:

```json
{
  "jsonrpc": "2.0",
  "result": {
    "workspaces": [
      {
        "id": 1,
        "name": "default",
        "created_at": 1673368954,
        "updated_at": 1673368954
      }
    ]
  },
  "id": 1
}
```

### Modules workflow

#### Search for modules

Request:

```sh
curl --request POST \
  --url http://localhost:8081/api/v1/json-rpc \
  --header 'content-type: application/json' \
  --data '{ "jsonrpc": "2.0", "method": "module.search", "id": 1, "params": ["psexec author:egypt arch:x64"] }'
```

Response:

```json
{
    "jsonrpc": "2.0",
    "result": [
        {
            "type": "exploit",
            "name": "PsExec via Current User Token",
            "fullname": "exploit/windows/local/current_user_psexec",
            "rank": "excellent",
            "disclosuredate": "1999-01-01"
        }
    ],
    "id": 1
}
```

#### Run module check methods

Metasploit modules support running `check` methods which can be used to identify the success of an exploit module, or to run an
auxiliary module against a target. For instance, with an Auxiliary module check request:

```sh
curl --request POST \
  --url http://localhost:8081/api/v1/json-rpc \
  --header 'Content-Type: application/json' \
  --data '{
    "jsonrpc": "2.0",
    "method": "module.check",
    "id": 1,
    "params": [
        "auxiliary",
        "auxiliary/scanner/ssl/openssl_heartbleed",
        {
            "RHOST": "192.168.123.13"
        }
    ]
}'
```

Or an Exploit module check request:

```sh
curl --request POST \
  --url http://localhost:8081/api/v1/json-rpc \
  --header 'content-type: application/json' \
  --data '{
    "jsonrpc": "2.0",
    "method": "module.check",
    "id": 1,
    "params": [
        "exploit",
        "exploit/windows/smb/ms17_010_eternalblue",
        {
          "RHOST": "192.168.123.13"
        }
    ]
}'
```

The response will contain an identifier which can be used to query for updates:

```json
{
  "jsonrpc": "2.0",
  "result": {
    "job_id": 0,
    "uuid": "1MIqJ5lViZHSOuaWf1Zz1lpR"
  },
  "id": 1
}
```

#### query all running stats

Request:

```sh
curl --request POST \
  --url http://localhost:8081/api/v1/json-rpc \
  --header 'Content-Type: application/json' \
  --data '{
    "jsonrpc": "2.0",
    "method": "module.running_stats",
    "id": 1,
    "params": []
}'
```

The response will include the following keys:
- waiting - modules that are queued up, but have not started to run yet
- running - currently running modules
- results - the module has completed or failed, and the results can be retrieved and acknowledged 

Response:

```json
{
  "jsonrpc": "2.0",
  "result": {
    "waiting": [
      "NkJvf4kp4JxcuFCz7rjSuHL1",
      "wRnMQuJ8gzMTp5CaHu18bHdV"      
    ],
    "running": [
      "b7hIX6G4ZtwvRVRDOXk5ylSx",
      "gx9xTEi6KlH5LJHauyhrHTBn",
    ],
    "results": [
      "1MIqJ5lViZHSOuaWf1Zz1lpR",
      "IN5PwYXrjqKfuekQt8cyCENK",
      "Spd1xfgsCZXQABNh7UA3uB58",
      "nRQw0bEvhFcXF0AxtVYOpQku"
    ]
  },
  "id": 1
}
```

#### retrieve module results

It is possible to poll for module results using the id returned when running a module.

Request:

```sh
curl --request POST \
  --url http://localhost:8081/api/v1/json-rpc \
  --header 'Content-Type: application/json' \
  --data '{
    "jsonrpc": "2.0",
    "method": "module.results",
    "id": 1,
    "params": ["0L37lfcIQqyRK9aBTIVJB4H3"]
}'
```

Example response when the module is has not yet complete:

```json
{
  "jsonrpc": "2.0",
  "result": {
    "status": "running"  
  },
  "id": 1
}
```

Example error response:

```json
{
  "jsonrpc": "2.0",
  "result": {
    "status": "errored",
    "error": "The connection with (192.168.123.13:443) timed out."
  },
  "id": 1
}
```

Example success response:

```json
{
    "jsonrpc": "2.0",
    "result": {
        "status": "completed",
        "result": {
            "code": "vulnerable",
            "message": "The target is vulnerable.",
            "reason": null,
            "details": {
                "os": "Windows 7 Enterprise 7601 Service Pack 1",
                "arch": "x64"
            }
        }
    },
    "id": 1
}
```

#### acknowledge module results

This command will also allow Metasploit to remove the result resources from memory. Not acknowledging module results will lead to a memory leak,
but the memory is limited to 35mb as the memory datastore used is implemented by [`ActiveSupport::Cache::MemoryStore`](https://github.com/rapid7/metasploit-framework/pull/13036/files#diff-6e31832215e40b17a184a7f7b82d2aabfbaa8d98fabb3c43033dd8579ad3caaeR102) 

Request:

```sh
curl --request POST \
  --url http://localhost:8081/api/v1/json-rpc \
  --header 'Content-Type: application/json' \
  --data '{
    "jsonrpc": "2.0",
    "method": "module.ack",
    "id": 1,
    "params": ["nRQw0bEvhFcXF0AxtVYOpQku"]
}'
```

Response:

```json
{
  "jsonrpc": "2.0",
  "result": {
    "success": true
  },
  "id": 1
}
```

### Analyzing hosts workflow

Metasploit supports an `analyze` command which suggests modules to run based on what a user has already learned and stored about a host.
First report a host:

```bash
curl --request POST \
  --url http://localhost:8081/api/v1/json-rpc \
  --header 'Authorization: Bearer ' \
  --header 'Content-Type: application/json' \
  --data '{
    "jsonrpc": "2.0",
    "method": "db.report_host",
    "id": 1,
    "params": [
        {
            "workspace": "default",
            "host": "10.0.0.1",
            "state": "alive",
            "os_name": "Windows",
            "os_flavor": "Enterprize",
            "os_sp": "SP2",
            "os_lang": "English",
            "arch": "ARCH_X86",
            "mac": "97-42-51-F2-A7-A7",
            "scope": "eth2",
            "virtual_host": "VMWare"
        }    
    ]
}'

# response: {"jsonrpc":"2.0","result":{"result":"success"},"id":1}
```

Report the host vulnerabilities:

```bash
curl --request POST \
  --url http://localhost:8081/api/v1/json-rpc \
  --header 'Authorization: Bearer ' \
  --header 'Content-Type: application/json' \
  --data '{
    "jsonrpc": "2.0",
    "method": "db.report_vuln",
    "id": 1,
    "params": [
        {
            "workspace": "default",
            "host": "10.0.0.1",
            "name": "Exploit Name",
            "info": "Human readable description of the vuln",
            "refs": [
                "CVE-2017-0143",
                "CVE-2017-0144",
                "CVE-2017-0145",
                "CVE-2017-0146",
                "CVE-2017-0147",
                "CVE-2017-0148"
            ]
        }
    ]
}'

# response: {"jsonrpc":"2.0","result":{"result":"success"},"id":1}
```

Run the analyze command:

```sh
curl --request POST \
  --url http://localhost:8081/api/v1/json-rpc \
  --header 'Authorization: Bearer ' \
  --header 'Content-Type: application/json' \
  --data '{
    "jsonrpc": "2.0",
    "method": "db.analyze_host",
    "id": 1,
    "params": [
        {
            "workspace": "default",
            "host": "10.0.0.1"
        }
    ]
}'
```

Response:

```json
{
  "jsonrpc": "2.0",
  "result": {
    "host": {
      "address": "10.0.0.1",
      "modules": [
        {
          "mtype": "exploit",
          "mname": "exploit/windows/smb/ms17_010_eternalblue",
          "state": "READY_FOR_TEST",
          "description": "ready for testing",
          "options": {
            "invalid": [],
            "missing": []
          }
        }
      ]
    }
  },
  "id": 1
}
```

When analyzing a host, it is also possible to specify payload requirements for additional granularity:

```sh
curl --request POST \
  --url http://localhost:8081/api/v1/json-rpc \
  --header 'Authorization: Bearer ' \
  --header 'Content-Type: application/json' \
  --data '{
    "jsonrpc": "2.0",
    "method": "db.analyze_host",
    "id": 1,
    "params": [
        {
            "workspace": "default",
            "host": "10.0.0.1",
            "payload": "payload/cmd/unix/reverse_bash"
        }
    ]
}'
```
