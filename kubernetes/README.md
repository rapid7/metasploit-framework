
# Running Metasploit Framework Inside Kubernetes

Running metasploit framework inside Kubernetes enables pentesters to security test cluster components such as the API Server, as well as internal application components or micro-services.

The installation chart also offers to install & run metasploit framework with different priviliges and permissions with respect to Kubernetes node hosting metasploit, as well as Kubernetes API server itself - see 'priviliges' section under values.yaml

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

3. Install the helm chart by running:

    ```sh
    helm dep update ./metasploit
    helm upgrade --create-namespace -i -n metasploit metasploit ./metasploit
    ```

4. Run metasploit console by running:

    ```sh
    export MSF_POD_NAME=$(kubectl get pods --namespace metasploit -l "app.kubernetes.io/name=metasploit,app.kubernetes.io/instance=metasploit" -o jsonpath="{.items[0].metadata.name}")

    kubectl --namespace metasploit exec -it $MSF_POD_NAME -- msfconsole.sh
    ```  
