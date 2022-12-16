# JSON-RPC API

## Integrating with msfdb
Firstly make sure your database is correctly configured using the steps below:
### Verify reinit

Start the database in its entirety

```
bundle exec ruby ./msfdb reinit
```

Verify that the msfdb details are output to the console, and that you can open msfconsole and see `db_status` as being connected to the remote service:
```
[*] Connected to remote_data_service: (https://localhost:5443). Connection type: http.
```

### Verify non-daemon mode

For development purposes it's useful to run the Metasploit API synchronously in the foreground to ensure that your breakpoints trigger. Ensure that the webservice can now be run synchronously:

```
bundle exec ruby ./msfdb reinit
bundle exec ruby ./msfdb --component webservice stop
bundle exec ruby ./msfdb --component webservice --no-daemon start
```

###  Making requests
Have the above `msfdb` instance running, and run the json rpc service with:
```
bundle exec thin --rackup msf-json-rpc.ru --address localhost --port 8081 --environment production --tag msf-json-rpc start
```

Verify that the RPC service can interact with the http data service
```
curl --request POST \
  --url http://localhost:8081/api/v1/json-rpc \
  --header 'Content-Type: application/json' \
  --data '{
        "jsonrpc": "2.0",
        "method": "db.status",
        "id": 1,
        "params": []
}'

{"jsonrpc":"2.0","result":{"driver":"http","db":"msf"},"id":1}
```

Verify that information can be retrieved:
```
curl --request POST \
  --url http://localhost:8081/api/v1/json-rpc \
  --header 'Content-Type: application/json' \
  --data '{
        "jsonrpc": "2.0",
        "method": "db.workspaces",
        "id": 1,
        "params": []
}'

{"jsonrpc":"2.0","result":{"workspaces":[{"id":1,"name":"default","created_at":1617283083,"updated_at":1617283083}]},"id":1}
```

Verify that this works with a framework instance that is talking to the local database rather than via the http service: This can be achieved by removing the logic from `~/.msf4/config`

Verify that the json rpc service can connect to a remote data service via its config
```
MSF_WS_DATA_SERVICE_URL=https://localhost:5443 MSF_WS_DATA_SERVICE_API_TOKEN=5e396b5175292daf7d5051cdabf953e16e0d789d2a6199a8021f439cc8712b043fa43eb21a14e7cc MSF_WS_DATA_SERVICE_CERT=/Users/user/.msf4/msf-ws-cert.pem MSF_WS_DATA_SERVICE_SKIP_VERIFY=true bundle exec thin --rackup msf-json-rpc.ru --address localhost --port 8081 --environment production --tag msf-json-rpc start
```

## Commands
Lets look at some example commands:

### Report a host
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
```

### Report the host's vulnerabilities
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
```

### Run the analyze command
```
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

### Specify payload requirements, note this currently does not change the resulting payload response
```
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
