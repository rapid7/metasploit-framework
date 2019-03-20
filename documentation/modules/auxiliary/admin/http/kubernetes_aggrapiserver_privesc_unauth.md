## Kubernetes Aggregate API Server Privilege Escalation Unauthenticated

## minikube
- Start
You can start minikube using below command
```
minikube start
```
Start minikube with specific vulnerable kubernetes version
```
minikube start --kubernetes-version 1.10.0
```
Check the status of minikube k8s cluster status
```
$ minikube status
host: Running
kubelet: Running
apiserver: Running
kubectl: Correctly Configured: pointing to minikube-vm at 192.168.99.100
```

Once the cluster is up and running we can get API Server details
```
$ kubectl cluster-info
Kubernetes master is running at https://192.168.99.100:8443
KubeDNS is running at https://192.168.99.100:8443/api/v1/namespaces/kube-system/services/kube-dns:dns/proxy
```

### Metrics Aggregation API
- Enable Metrics Aggregation API
```
minikube addons list
minikube addons enable metrics-server
```

### Service Catalogue Aggregation API
registry-creds is kind of dependency to enable service catalog in minikube
```
minikube addons enable registry-creds
```

Create clusterrolebinding to be used by Tiller
$ kubectl create clusterrolebinding tiller-cluster-admin \
     --clusterrole=cluster-admin \
     --serviceaccount=kube-system:default
clusterrolebinding.rbac.authorization.k8s.io/tiller-cluster-admin created

- Helm
helm is a package manager for kubernetes. helm init is used to deploy/install/configure Tiller Server/Client to a specific namespace, kube-system is default namespace.
Below commands will initialize helm, create Tiller server in kube-system namespace and install service catalog chart. 
```
$ helm init

# if u have helm errors with minikube
$ helm init --upgrade --debug
$ kubectl create -f tiller-minikube.yaml -n kube-system
$ helm install svc-cat/catalog --name catalog --namespace catalog
```

Tiller deployment configuration
```
$ cat tiller-minikube.yaml
apiVersion: extensions/v1beta1
kind: Deployment
metadata:
  creationTimestamp: null
  labels:
    app: helm
    name: tiller
  name: tiller-deploy
  namespace: kube-system
spec:
  strategy: {}
  template:
    metadata:
      creationTimestamp: null
      labels:
        app: helm
        name: tiller
    spec:
      containers:
      - env:
        - name: TILLER_NAMESPACE
          value: kube-system
        - name: TILLER_HISTORY_MAX
          value: "0"
        image: gcr.io/kubernetes-helm/tiller:v2.8.2
        imagePullPolicy: IfNotPresent
        livenessProbe:
          httpGet:
            path: /liveness
            port: 44135
          initialDelaySeconds: 1
          timeoutSeconds: 1
        name: tiller
        ports:
        - containerPort: 44134
          name: tiller
        - containerPort: 44135
          name: http
        readinessProbe:
          httpGet:
            path: /readiness
            port: 44135
          initialDelaySeconds: 1
          timeoutSeconds: 1
        resources: {}
status: {}
---
apiVersion: v1
kind: Service
metadata:
  creationTimestamp: null
  labels:
    app: helm
    name: tiller
  name: tiller-deploy
  namespace: kube-system
spec:
  ports:
  - name: tiller
    port: 44134
    targetPort: tiller
  selector:
    app: helm
    name: tiller
  type: ClusterIP
status:
  loadBalancer: {}
```

### Debug
- Check installed api extensions
```
$ kubectl get apiservices -o 'jsonpath={range .items[?(@.spec.service.name!="")]}{.metadata.name}{"\n"}{end}'
v1beta1.metrics.k8s.io
v1beta1.servicecatalog.k8s.io
```

- Check available API and their versions
```
kubectl get --raw /apis/ | jq . |grep -i groupVersion
```

### References
https://github.com/kubernetes-incubator/service-catalog/blob/master/docs/install.md
https://www.twistlock.com/labs-blog/demystifying-kubernetes-cve-2018-1002105-dead-simple-exploit/
https://github.com/kubernetes/kubernetes/issues/71411
