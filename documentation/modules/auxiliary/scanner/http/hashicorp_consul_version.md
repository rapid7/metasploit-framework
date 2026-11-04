## Vulnerable Application

This module scans for HashiCorp Consul agents and fingerprints the
running version. It reads the /v1/agent/self API endpoint and
extracts the Config.Version field. On agents without ACL enforcement
(the default) this is unauthenticated; when the agent replies 403
the module retries with the configured ACL token in the
X-Consul-Token header. If the agent info API stays unreadable the
module tries the permission-free /v1/agent/version endpoint and then
the Consul UI at /ui/, whose static HTML leaks the exact version in
a CONSUL_VERSION comment even when the ACL default policy denies
everything else.

Tested against every major GA release since October 2024 (1.20,
1.21, 1.22, 2.0).

### Docker Targets

Every command below binds host port 8500, so run one target at a
time and stop and remove the previous container before starting the
next release:

```
docker run -d --name consul -p 8500:8500 hashicorp/consul:1.20.6 agent -dev -client=0.0.0.0
# before starting the next release:
docker rm -f consul

docker run -d --name consul -p 8500:8500 hashicorp/consul:1.21.5 agent -dev -client=0.0.0.0
docker rm -f consul

docker run -d --name consul -p 8500:8500 hashicorp/consul:1.22.7 agent -dev -client=0.0.0.0
docker rm -f consul

docker run -d --name consul -p 8500:8500 hashicorp/consul:2.0.4 agent -dev -client=0.0.0.0
```

## Verification Steps

1. Run Consul in Docker
1. Start msfconsole
1. Do: `use auxiliary/scanner/http/hashicorp_consul_version`
1. Do: `set rhost [ip]`
1. Do: `run`
1. You should find the Consul version.

## Options

### Token

Consul ACL token for agents that enforce ACLs. Set SSL true when the
agent speaks TLS so the token is not sent in cleartext.

## Scenarios

### Docker with version 1.20.6

```
msf > use auxiliary/scanner/http/hashicorp_consul_version
msf auxiliary(scanner/http/hashicorp_consul_version) > set rhosts 127.0.0.1
rhosts => 127.0.0.1
msf auxiliary(scanner/http/hashicorp_consul_version) > run
[+] HashiCorp Consul 1.20.6 found
[*] No authentication required to read the agent info API
[*] ACL default policy is allow (no ACL enforcement)
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```

### Docker with version 1.22.7, ACL default policy deny

With ACLs enforcing a deny default the agent info API answers 403,
so the version comes from the permission-free version endpoint:

```
msf > use auxiliary/scanner/http/hashicorp_consul_version
msf auxiliary(scanner/http/hashicorp_consul_version) > set rhosts 127.0.0.1
rhosts => 127.0.0.1
msf auxiliary(scanner/http/hashicorp_consul_version) > run
[+] HashiCorp Consul 1.22.7 identified from the version endpoint, though the agent info API returned HTTP 403
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```
