The Metasploit MCP Server (`msfmcpd`) provides AI applications with secure, structured access to Metasploit Framework data and execution capabilities through the [Model Context Protocol](https://modelcontextprotocol.io/) (MCP). It acts as a middleware layer between AI clients (such as Claude, Cursor, or custom agents) and Metasploit, exposing 16 standardized tools for searching modules, querying reconnaissance data, executing modules, and interacting with sessions.

Tools are split into two classes:

- **Read-only tools** (always enabled): query modules, hosts, services, vulnerabilities, notes, credentials, loot, jobs, and sessions.
- **Dangerous tools** (gated, disabled by default): run module execution and check methods, stop sessions, and write to interactive sessions. These tools must be explicitly enabled by the operator via the `--enable-dangerous-actions` CLI flag, the `MSF_MCP_DANGEROUS_ACTIONS` environment variable, or the `mcp.dangerous_actions` configuration key. See [Dangerous Actions Mode](#dangerous-actions-mode) below.

## Architecture

```mermaid
flowchart TD
    ai_app["AI Application<br>(Claude, Cursor, etc.)"]

    subgraph msfmcp_server["MsfMcp Server"]
        mcp_layer["MCP Layer (16 Tools)<br>Input Validation / Rate Limiting / Response Transformation<br>Dangerous Actions Gate"]
        rpc_manager["RPC Manager<br>Auto-detect / Auto-start / Lifecycle Management"]
        api_client["Metasploit API Client<br>MessagePack RPC (port 55553) / JSON-RPC (port 8081)<br>Session Management"]

        mcp_layer --> rpc_manager
        rpc_manager --> api_client
    end

    msf["Metasploit Framework<br>(msfrpcd)"]

    ai_app -- "MCP Protocol (stdio or HTTP)<br>JSON-RPC 2.0" --> mcp_layer
    api_client -- "HTTP/HTTPS" --> msf
```

## Quick Start

The simplest way to start the MCP server is with no arguments:

```
./msfmcpd
```

The server automatically detects whether a Metasploit RPC server is already running on the configured port. If not, it starts one automatically with randomly generated credentials.

To use specific credentials:

```
./msfmcpd --user your_username --password your_password
```

## Configuration

### Configuration File

Copy the example configuration and edit it:

```
cp config/mcp_config.yaml.example config/mcp_config.yaml
```

A MessagePack RPC configuration looks like this:

```yaml
msf_api:
  type: messagepack
  host: localhost
  port: 55553
  ssl: true
  endpoint: /api/
  user: msfuser
  password: CHANGEME
  auto_start_rpc: true

mcp:
  transport: stdio

rate_limit:
  enabled: true
  requests_per_minute: 60
  burst_size: 10

logging:
  enabled: false
  level: INFO
  log_file: msfmcp.log
```

For JSON-RPC with bearer token authentication, use the JSON-RPC example instead:

```
cp config/mcp_config_jsonrpc.yaml.example config/mcp_config.yaml
```

### Command-Line Options

```
./msfmcpd --help

Options:
  --config PATH                Path to configuration file
  --enable-logging             Enable file logging with sanitization
  --log-file PATH              Log file path (overrides config file)
  --user USER                  MSF API username (for MessagePack auth)
  --password PASS              MSF API password (for MessagePack auth)
  --no-auto-start-rpc          Disable automatic RPC server startup
  --mcp-transport TRANSPORT    MCP server transport type ('stdio' or 'http')
  --enable-dangerous-actions   Enable dangerous tools (module execute/check,
                               session stop/write). Disabled by default.
  -h, --help                   Show this help message
  -v, --version                Show version information
```

### Environment Variable Overrides

All configuration settings can be overridden by environment variables:

| Variable | Description |
|---|---|
| `MSF_API_TYPE` | Connection type (`messagepack` or `json-rpc`) |
| `MSF_API_HOST` | Metasploit RPC API host |
| `MSF_API_PORT` | Metasploit RPC API port |
| `MSF_API_SSL` | Use SSL for Metasploit RPC API (`true` or `false`) |
| `MSF_API_ENDPOINT` | Metasploit RPC API endpoint |
| `MSF_API_USER` | RPC API username (for MessagePack auth) |
| `MSF_API_PASSWORD` | RPC API password (for MessagePack auth) |
| `MSF_API_TOKEN` | RPC API token (for JSON-RPC auth) |
| `MSF_AUTO_START_RPC` | Auto-start RPC server (`true` or `false`) |
| `MSF_MCP_TRANSPORT` | MCP transport type (`stdio` or `http`) |
| `MSF_MCP_HOST` | MCP server host (for HTTP transport) |
| `MSF_MCP_PORT` | MCP server port (for HTTP transport) |
| `MSF_MCP_AUTH_TOKEN` | MCP server Bearer token for authentication (for HTTP transport) |
| `MSF_MCP_DANGEROUS_ACTIONS` | Enable dangerous tools (`true`/`1`/`yes`/`on` to enable, anything else to disable) |

Example using environment variables:

```
MSF_API_HOST=192.168.33.44 ./msfmcpd --config ./config/mcp_config.yaml
```

## Automatic RPC Server Management

When using MessagePack RPC on localhost, the MCP server can automatically manage the Metasploit RPC server lifecycle. This is enabled by default.

### How It Works

1. **Detection**: On startup, the MCP server probes the configured RPC port to check if a server is already running.
2. **Auto-start**: If no server is detected, it spawns the `msfrpcd` executable as a child process.
3. **Credentials**: If no username and password are provided, random credentials are generated automatically and used for both the RPC server and client authentication.
4. **Wait**: After starting, it polls the port until the RPC server becomes available (timeout: 30 seconds).
5. **Shutdown**: When the MCP server shuts down (via Ctrl+C or SIGTERM), it cleans up the managed RPC process.

**Note**: If an RPC server is already running, credentials must be provided via `--user`/`--password`, config file, or environment variables to authenticate with it.

### Database Support

The auto-started RPC server creates a framework instance with database support enabled by default. If the database is not running when the RPC server starts, a warning is displayed:

```
[WARNING] Database is not available. Some MCP tools that rely on the database will not work.
[WARNING] Start the database and restart the MCP server to enable full functionality.
```

Tools that query the database (`msf_host_info`, `msf_service_info`, `msf_vulnerability_info`, `msf_note_info`, `msf_credential_info`, `msf_loot_info`) require a running database. To initialize and start the database:

```
msfdb init
msfdb start
```

Then restart the MCP server.

### Disabling Auto-Start

Auto-start can be disabled in three ways:

- CLI flag: `--no-auto-start-rpc`
- Config file: `auto_start_rpc: false` in the `msf_api` section
- Environment variable: `MSF_AUTO_START_RPC=false`

Auto-start is also not available when:

- The API type is `json-rpc` (requires SSL certificates and a web server)
- The host is a remote address (cannot start a server on a remote machine)

When auto-start is disabled and no RPC server is running, you must start `msfrpcd` manually:

```
msfrpcd -U your_username -P your_password -p 55553
```

## Authentication

The HTTP transport supports authentication through a Bearer token as set in the Authorization header (e.g.
`Authorization: Bearer ...`). By default, if the token is not set, a random token will be generated automatically and
printed when the MCP server starts.

For example:

```
Initializing MCP server...
Starting MCP server on HTTP transport...
Server listening on http://localhost:3000/
Authentication: Bearer token (auto-generated)
  Configure your MCP client with: Authorization: Bearer 2fc41c38eccfe505b44cde1bc96dc4bf72e4abe163a689a3e25bd05e8c081cbd
Press Ctrl+C to shutdown
```

Using the automatically generated token means the MCP client's configuration will need to be updated each time the
server is restarted. A persistent token can be defined in two ways:

1. In the configuration file, by defining `auth_token` to a non-empty string under the `mcp` key, e.g.:

```yaml
mcp:
  transport: http
  # ... other config keys
  auth_token: MY-SUPER-SECURE-TOKEN
```

2. By setting the `MSF_MCP_AUTH_TOKEN` environment variable. As with other configuration options, the environment
  variable takes precedence over the configuration.

### Disabling Authentication

While not advisable, authentication can be disabled by setting the configuration to null or an empty string. In this
case the server will respond to HTTP requests from any client that can connect to it. Use caution when disabling 
authentication.

```yaml
mcp:
  transport: http
  # ... other config keys
  auth_token: null # DISABLE HTTP AUTHENTICATION
```

The same can be achieved through the environment variable, e.g. `MSF_MCP_AUTH_TOKEN="" ./msfmcpd --mcp-transport http`.

## MCP Tools

The server exposes 16 tools to AI applications via the MCP protocol. Tools marked **dangerous** are gated by [Dangerous Actions Mode](#dangerous-actions-mode) and return a tool error unless the operator has explicitly enabled it.

### Read-only Tools

#### msf_search_modules

Search for Metasploit modules by keywords, CVE IDs, or module names.

- `query` (string, required): Search terms (e.g., `windows smb`, `CVE-2017-0144`)
- `limit` (integer, optional): Max results (1-1000, default: 100)
- `offset` (integer, optional): Pagination offset (default: 0)

#### msf_module_info

Get detailed information about a specific Metasploit module.

- `type` (string, required): Module type (`exploit`, `auxiliary`, `post`, `payload`, `encoder`, `nop`)
- `name` (string, required): Module path (e.g., `windows/smb/ms17_010_eternalblue`)

Returns complete module details including options, targets, references, and authors.

#### msf_host_info

Query discovered hosts from the Metasploit database.

- `workspace` (string, optional): Workspace name (default: `default`)
- `addresses` (string, optional): Filter by IP/CIDR (e.g., `192.168.1.0/24`)
- `only_up` (boolean, optional): Only return alive hosts (default: false)
- `limit` (integer, optional): Max results (1-1000, default: 100)
- `offset` (integer, optional): Pagination offset (default: 0)

#### msf_service_info

Query discovered services on hosts.

- `workspace` (string, optional): Workspace name
- `names` (string, optional): Filter by service names, comma-separated (e.g., `http`, `ldap,ssh`)
- `host` (string, optional): Filter by host IP
- `ports` (string, optional): Filter by port or range (e.g., `80,443` or `1-1024`)
- `protocol` (string, optional): Protocol filter (`tcp` or `udp`)
- `only_up` (boolean, optional): Only return running services (default: false)
- `limit` (integer, optional): Max results (1-1000, default: 100)
- `offset` (integer, optional): Pagination offset (default: 0)

#### msf_vulnerability_info

Query discovered vulnerabilities.

- `workspace` (string, optional): Workspace name
- `names` (array of strings, optional): Filter by vulnerability names (exact, case-sensitive module names)
- `host` (string, optional): Filter by host IP
- `ports` (string, optional): Filter by port or range
- `protocol` (string, optional): Protocol filter (`tcp` or `udp`)
- `limit` (integer, optional): Max results (1-1000, default: 100)
- `offset` (integer, optional): Pagination offset (default: 0)

#### msf_note_info

Query notes stored in the database.

- `workspace` (string, optional): Workspace name
- `type` (string, optional): Filter by note type (e.g., `ssl.certificate`, `smb.fingerprint`)
- `host` (string, optional): Filter by host IP
- `ports` (string, optional): Filter by port or range
- `protocol` (string, optional): Protocol filter (`tcp` or `udp`)
- `limit` (integer, optional): Max results (1-1000, default: 100)
- `offset` (integer, optional): Pagination offset (default: 0)

#### msf_credential_info

Query discovered credentials.

- `workspace` (string, optional): Workspace name
- `limit` (integer, optional): Max results (1-1000, default: 100)
- `offset` (integer, optional): Pagination offset (default: 0)

#### msf_loot_info

Query collected loot (files, data dumps).

- `workspace` (string, optional): Workspace name
- `limit` (integer, optional): Max results (1-1000, default: 100)
- `offset` (integer, optional): Pagination offset (default: 0)

#### msf_module_results

Retrieve the result of a previously executed module run by its UUID.

- `uuid` (string, required): 24-character alphanumeric run UUID returned by `msf_module_execute` or `msf_module_check`

Returns one of:

- `{ "status": "ready" }` — job is queued but has not started yet
- `{ "status": "running" }` — job is still executing
- `{ "status": "completed", "result": ... }` — job finished; payload depends on module type (a check returns a `CheckCode` payload, a scanner returns per-host results, etc.)
- `{ "status": "errored", "error": "..." }` — job finished with an error

#### msf_running_stats

Return a snapshot of running and waiting module runs known to the framework.

Takes no parameters. Returns an object with:

- `waiting`: list of run UUIDs queued but not yet started
- `running`: list of run UUIDs currently executing
- `results`: list of run UUIDs whose results are available via `msf_module_results`

#### msf_session_list

List active Metasploit sessions.

Takes no parameters. Returns a hash keyed by integer session id, where each value describes the session type (e.g. `meterpreter`, `shell`), tunnel endpoints, the target host, and the originating module.

#### msf_session_read

Non-destructively read pending output from an interactive session (shell or meterpreter).

- `session_id` (integer, required): Session id from `msf_session_list`

Returns `{ "data": "...", "seq": N }`. The MCP server does not buffer; clients are responsible for reassembling reads. Returns an error if the session id is not active.

### Dangerous Tools

These four tools can change the state of the framework, remote targets, or running sessions. They are gated by [Dangerous Actions Mode](#dangerous-actions-mode) and return a tool error unless the operator has explicitly enabled it.

#### msf_module_execute

Run a Metasploit module as a background job.

- `type` (string, required): Module type (`exploit`, `auxiliary`, `post`, `evasion`)
- `name` (string, required): Module path (e.g., `multi/handler`)
- `options` (object, required): Datastore options as a flat JSON object. Keys are Metasploit option names; namespaced (`HTTP::compression`) and hyphenated (`BEARER-TOKEN`) names are supported. Values must be scalars (string, integer, number, boolean, or null). No nested objects or arrays.

Returns `{ "metadata": { "uuid": "<24 chars>", "job_id": N }, "next_steps": { ... } }`. Poll `msf_module_results` with the returned UUID to retrieve the outcome.

This tool does not implement check-before-exploit. If a module supports `Msf::Exploit::Remote::AutoCheck`, the framework runs the check automatically; otherwise, run `msf_module_check` first.

#### msf_module_check

Run the `check` method of an exploit or auxiliary module to determine whether a target is vulnerable, without exploiting it.

- `type` (string, required): Module type (`exploit` or `auxiliary`)
- `name` (string, required): Module path
- `options` (object, required): Datastore options (same shape as `msf_module_execute`)

Returns `{ "metadata": { "uuid": "<24 chars>", "job_id": N } }`. Poll `msf_module_results` for the `CheckCode` (e.g. `Vulnerable`, `Safe`, `Detected`, `Appears`, `Unknown`).

Modules that do not implement a `check` method surface as a tool error rather than a success payload.

#### msf_session_stop

Terminate an active session.

- `session_id` (integer, required): Session id from `msf_session_list`

Returns `{ "result": "success" }`. Returns a tool error if the session id is not active.

#### msf_session_write

Send data to an interactive session (shell or meterpreter).

- `session_id` (integer, required): Session id from `msf_session_list`
- `data` (string, required): Bytes to write to the session, capped at 64 KB per call

Returns `{ "write_count": N }`. Use `msf_session_read` afterwards to retrieve any output produced by the command.

## Dangerous Actions Mode

The four tools listed under [Dangerous Tools](#dangerous-tools) are disabled by default and must be explicitly enabled. When the gate is closed, calls to any of those tools return an MCP tool error and the underlying RPC call is never issued.

### Enabling

Dangerous mode can be enabled through any of three mechanisms, in order of precedence (highest first):

1. **CLI flag**: pass `--enable-dangerous-actions` to `msfmcpd`.
2. **Environment variable**: set `MSF_MCP_DANGEROUS_ACTIONS=true` (also accepts `1`, `yes`, `on`).
3. **Configuration file**: set `mcp.dangerous_actions: true` in `mcp_config.yaml`.

When the gate is open, `msfmcpd` prints a warning banner on startup:

```
WARNING: dangerous actions mode is ENABLED. Destructive tools (module
execute/check, session stop/write) are now callable from connected MCP
clients.
```

## Integration with AI Applications

Add the MCP server to your AI application configuration. The exact format depends on the client.

### Claude Desktop / Cursor

```json
{
  "mcpServers": {
    "metasploit": {
      "command": "/path/to/metasploit-framework/msfmcpd",
      "args": [
        "--config",
        "/path/to/config/mcp_config.yaml"
      ],
      "env": {}
    }
  }
}
```

### Using RVM

If you use RVM to manage Ruby versions, specify the full path to RVM so the correct Ruby and gemset are used:

```json
{
  "mcpServers": {
    "metasploit": {
      "command": "/your/home_dir/.rvm/bin/rvm",
      "args": [
        "in",
        "/path/to/metasploit-framework",
        "do",
        "./msfmcpd",
        "--config",
        "config/mcp_config.yaml"
      ]
    }
  }
}
```

## Security Considerations

### Dangerous Actions Gate

Tools that execute modules or interact with sessions are disabled by default. They must be explicitly enabled per session via CLI flag, environment variable, or configuration key — see [Dangerous Actions Mode](#dangerous-actions-mode). When the gate is closed, the RPC client is never invoked for a gated call.

### Input Validation

All tool parameters are validated against strict JSON schemas. IP addresses are validated using Ruby's `IPAddr` class with CIDR support, workspace names are restricted to alphanumeric characters plus underscore/hyphen, port ranges are validated (1-65535), and search queries are limited to 500 characters. Module datastore option keys must match Metasploit's option-name shape (identifier segments joined by `::` or `-`, up to 128 characters); option payloads are capped at 100 keys, 8 KB per string value, and 64 KB aggregate. Session data writes are capped at 64 KB per call.

### Credential Management

Configuration files should use `chmod 600` permissions. Credentials are transmitted securely to the Metasploit Framework API and are never cached or logged by the MCP server.

### Rate Limiting

The server applies rate limiting to all MCP tools using a token bucket algorithm. Default: 60 requests per minute with a burst of 10 requests. This is configurable in the `rate_limit` section of the configuration file.

### Logging

Logging is disabled by default. When enabled (via `--enable-logging` or config), sensitive data (passwords, tokens, API keys) is automatically redacted. Log files should be protected with `chmod 600`.

### Error Handling

Stack traces are never exposed to clients. Error messages are sanitized to avoid leaking credentials. Metasploit API errors are wrapped in the MCP error format.

## Testing with MCP Inspector

The [MCP Inspector](https://github.com/modelcontextprotocol/inspector) is an interactive developer tool for testing and debugging MCP servers. It runs directly through `npx`:

```
npx @modelcontextprotocol/inspector

# stdio transport type usage:
npx @modelcontextprotocol/inspector -- bundle exec ./msfmcpd
```

## Troubleshooting

### Connection Refused or Timeout

1. Verify the RPC daemon is running: `ps aux | grep msfrpcd`
2. Check the port is listening: `netstat -an | grep 55553`
3. Test connectivity: `curl -k -v https://localhost:55553/api/`

### Authentication Failures

For MessagePack RPC, verify the username and password in your configuration file or CLI arguments. For JSON-RPC, verify the bearer token is valid and has not expired.

### Database Not Available

If database-dependent tools return errors, ensure the database is running:

```
msfdb init
msfdb start
```

Then restart the MCP server.

### Rate Limit Exceeded

Increase the rate limit in your configuration file:

```yaml
rate_limit:
  requests_per_minute: 120
  burst_size: 20
```
