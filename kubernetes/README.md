# Running Metasploit Inside Kubernetes

1. Make sure helm (version 3 or above) is [installed](https://helm.sh/docs/intro/install/)
2. Make sure you have an available Kubernetes cluster to deploy metasploit. You can install a local Kubernetes cluster using [KIND](https://kind.sigs.k8s.io/docs/user/quick-start/#installation)
    > You can create local KIND cluster by running  `make create-kind-cluster`

3. Install the helm chart by running:

    ```sh
    helm upgrade --create-namespace -i -n metasploit metasploit ./metasploit
    ```

4. Run metasploit console by running:

    ```sh
    export MSF_POD_NAME=$(kubectl get pods --namespace {{ .Release.Namespace }} -l "app.kubernetes.io/name={{ include "metasploit.name" . }},app.kubernetes.io/instance={{ .Release.Name }}" -o jsonpath="{.items[0].metadata.name}")

    kubectl --namespace {{ .Release.Namespace }} exec -it $MSF_POD_NAME -- msfconsole.sh
    ```  
