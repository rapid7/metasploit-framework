## Vulnerable Application

### Description

Enumerates a Kubernetes cluster.

## Verification Steps

### Create or acquire the credentials

1. Start msfconsole
2. Do: `use auxiliary/cloud/kubernetes/enum_kubernetes`
3. Set the required options
4. Do: `run`
5: You should see the enumerated resources from the Kubernetes API.

## Options

### SESSION
An optional session to use for configuration. When specified, the values of `NAMESPACE`, `TOKEN`, `RHOSTS` and `RPORT`
will be gathered from the session host. This requires that the session be on an existing Kubernetes pod. The necessary
values may not always be present.

Setting this option will also automatically route connections through the specified session.

### TOKEN
The JWT token. The token with the necessary privileges to access the exec endpoint within a running pod and optionally
create a new pod.

### POD
The pod name to execute in. When not specified, a new pod will be created with an entrypoint that allows it to run
forever. After creation, the pod will be used to execute the payload. **The created pod is not automatically cleaned
up.** A note containing the created pod's information will be added to the database when it is connected.

### NAMESPACE
The Kubernetes namespace that the `TOKEN` has permissions for and that `POD` either exists in or should be created in.

### NAMESPACE_LIST

The default namespace list to iterate when the current token does not have the permission to retrieve the available namespaces

### HIGHLIGHT_NAME_PATTERN
A PCRE regex of resource names to highlight.

### OUTPUT
Output format, allowed values are: table, json

## Scenarios

### Run all enumeration

Explicitly setting RHOST and TOKEN to enumerate all available namespaces, and associated resources:

```
msf6 > use cloud/kubernetes/enum_kubernetes
msf6 auxiliary(cloud/kubernetes/enum_kubernetes) > set RHOST https://kubernetes.docker.internal:6443
RHOST => https://kubernetes.docker.internal:6443
msf6 auxiliary(cloud/kubernetes/enum_kubernetes) > set TOKEN eyJhbGciO...
TOKEN => eyJhbGciO...
msf6 auxiliary(cloud/kubernetes/enum_kubernetes) > run
[*] Running module against 127.0.0.1

[+] Kubernetes service version: {"major":"1","minor":"21","gitVersion":"v1.21.2","gitCommit":"092fbfbf53427de67cac1e9fa54aaa09a28371d7","gitTreeState":"clean","buildDate":"2021-06-16T12:53:14Z","goVersion":"go1.16.5","compiler":"gc","platform":"linux/amd64"}
[+] Enumerating namespaces
Namespaces
==========

  #  name
  -  ----
  0  default
  1  kube-node-lease
  2  kube-public
  3  kube-system
  4  kubernetes-dashboard

[+] Namespace 0: default
Auth (namespace: default)
=========================

  Resources                                      Non-Resource URLs                    Resource Names  Verbs
  ---------                                      -----------------                    --------------  -----
  *.*                                            []                                   []              [*]
  selfsubjectaccessreviews.authorization.k8s.io  []                                   []              [create]
  selfsubjectrulesreviews.authorization.k8s.io   []                                   []              [create]
                                                 [*]                                  []              [*]
                                                 [/.well-known/openid-configuration]  []              [get]
                                                 [/api/*]                             []              [get]
                                                 [/api]                               []              [get]
                                                 [/apis/*]                            []              [get]
                                                 [/apis]                              []              [get]
                                                 [/healthz]                           []              [get]
                                                 [/healthz]                           []              [get]
                                                 [/livez]                             []              [get]
                                                 [/livez]                             []              [get]
                                                 [/openapi/*]                         []              [get]
                                                 [/openapi]                           []              [get]
                                                 [/openid/v1/jwks]                    []              [get]
                                                 [/readyz]                            []              [get]
                                                 [/readyz]                            []              [get]
                                                 [/version/]                          []              [get]
                                                 [/version/]                          []              [get]
                                                 [/version]                           []              [get]
                                                 [/version]                           []              [get]

Pods (namespace: default)
=========================

  #   namespace  name                       status   containers                                       ip
  -   ---------  ----                       ------   ----------                                       --
  0   default    a4bg7r                     Running  iyxz0ujfck9t (image: vulhub/thinkphp:5.0.23)     10.1.1.51
  1   default    appjokbpiiml               Running  iggapn (image: vulhub/thinkphp:5.0.23)           10.1.1.57
  2   default    cvyf4m9le                  Running  t0e93vcuyi (image: vulhub/thinkphp:5.0.23)       10.1.1.53
  3   default    fh4bfdtf                   Running  dygvv (image: vulhub/thinkphp:5.0.23)            10.1.1.52
  4   default    gavp                       Running  jfwdaei (image: vulhub/thinkphp:5.0.23)          10.1.1.58
  5   default    mkfkuwd6hkd1               Running  aoavh (image: vulhub/thinkphp:5.0.23)            10.1.1.62
  6   default    nid7jd                     Running  geb (image: vulhub/thinkphp:5.0.23)              10.1.1.45
  7   default    redis-7fd956df5-sbchb      Running  redis (image: redis:5.0.4 TCP:6379)              10.1.1.56
  8   default    thinkphp-67f7c88cc9-djg6q  Running  thinkphp (image: vulhub/thinkphp:5.0.23 TCP:80)  10.1.1.55
  9   default    thinkphp-67f7c88cc9-l56mg  Running  thinkphp (image: vulhub/thinkphp:5.0.23 TCP:80)  10.1.1.44
  10  default    usuuucs                    Running  xfcw (image: vulhub/thinkphp:5.0.23)             10.1.1.50
  11  default    v2xxl7z                    Running  nu3s (image: vulhub/thinkphp:5.0.23)             10.1.1.61
  12  default    yulfpaohsepk               Running  jjmxkkzgkmy (image: vulhub/thinkphp:5.0.23)      10.1.1.47

Secrets (namespace: default)
============================

  #  namespace  name                                  type                                 data                    age
  -  ---------  ----                                  ----                                 ----                    ---
  0  default    default-token-btlkb                   kubernetes.io/service-account-token  ca.crt,namespace,token  8d
  1  default    local-registry                        kubernetes.io/dockerconfigjson       .dockerconfigjson       7d15h
  2  default    secret-basic-auth                     kubernetes.io/basic-auth             password,username       8d
  3  default    secret-empty                          Opaque                                                       8d
  4  default    secret-id-ed25519-with-passphrase     kubernetes.io/ssh-auth               ssh-privatekey          7d15h
  5  default    secret-id-ed25519-without-passphrase  kubernetes.io/ssh-auth               ssh-privatekey          7d15h
  6  default    secret-id-rsa-with-passphrase         kubernetes.io/ssh-auth               ssh-privatekey          8d
  7  default    secret-id-rsa-without-passphrase      kubernetes.io/ssh-auth               ssh-privatekey          8d
  8  default    secret-tls                            kubernetes.io/tls                    tls.crt,tls.key         8d

[+] service token default-token-btlkb: /Users/user/.msf4/loot/20211006105714_default_127.0.0.1_kubernetes.token_257374.bin
[+] dockerconfig json local-registry: /Users/user/.msf4/loot/20211006105714_default_unknown_docker.json_543280.bin
[+] basic_auth secret-basic-auth: admin:password213
[+] ssh_key secret-id-ed25519-with-passphrase: /Users/user/.msf4/loot/20211006105714_default_unknown_id_rsa_861231.txt
[+] ssh_key secret-id-ed25519-without-passphrase: /Users/user/.msf4/loot/20211006105714_default_unknown_id_rsa_095417.txt
[+] ssh_key secret-id-rsa-with-passphrase: /Users/user/.msf4/loot/20211006105714_default_unknown_id_rsa_246326.txt
[+] ssh_key secret-id-rsa-without-passphrase: /Users/user/.msf4/loot/20211006105714_default_unknown_id_rsa_429821.txt
[+] tls_key secret-tls: /Users/user/.msf4/loot/20211006105714_default_unknown_tls.key_651137.txt
[+] tls_cert secret-tls: /Users/user/.msf4/loot/20211006105714_default_unknown_tls.cert_025932.txt (/CN=example.com)

[+] Namespace 1: kube-node-lease
Auth (namespace: kube-node-lease)
=================================

  Resources                                      Non-Resource URLs                    Resource Names  Verbs
  ---------                                      -----------------                    --------------  -----
  *.*                                            []                                   []              [*]
  selfsubjectaccessreviews.authorization.k8s.io  []                                   []              [create]
  selfsubjectrulesreviews.authorization.k8s.io   []                                   []              [create]
                                                 [*]                                  []              [*]
                                                 [/.well-known/openid-configuration]  []              [get]
                                                 [/api/*]                             []              [get]
                                                 [/api]                               []              [get]
                                                 [/apis/*]                            []              [get]
                                                 [/apis]                              []              [get]
                                                 [/healthz]                           []              [get]
                                                 [/healthz]                           []              [get]
                                                 [/livez]                             []              [get]
                                                 [/livez]                             []              [get]
                                                 [/openapi/*]                         []              [get]
                                                 [/openapi]                           []              [get]
                                                 [/openid/v1/jwks]                    []              [get]
                                                 [/readyz]                            []              [get]
                                                 [/readyz]                            []              [get]
                                                 [/version/]                          []              [get]
                                                 [/version/]                          []              [get]
                                                 [/version]                           []              [get]
                                                 [/version]                           []              [get]

Pods (namespace: kube-node-lease)
=================================

  #  namespace  name  status  containers  ip
  -  ---------  ----  ------  ----------  --
  No rows

Secrets (namespace: kube-node-lease)
====================================

  #  namespace        name                 type                                 data                    age
  -  ---------        ----                 ----                                 ----                    ---
  0  kube-node-lease  default-token-54967  kubernetes.io/service-account-token  ca.crt,namespace,token  19d

[+] service token default-token-54967: /Users/user/.msf4/loot/20211006105714_default_127.0.0.1_kubernetes.token_727718.bin

[+] Namespace 2: kube-public
Auth (namespace: kube-public)
=============================

  Resources                                      Non-Resource URLs                    Resource Names  Verbs
  ---------                                      -----------------                    --------------  -----
  *.*                                            []                                   []              [*]
  selfsubjectaccessreviews.authorization.k8s.io  []                                   []              [create]
  selfsubjectrulesreviews.authorization.k8s.io   []                                   []              [create]
                                                 [*]                                  []              [*]
                                                 [/.well-known/openid-configuration]  []              [get]
                                                 [/api/*]                             []              [get]
                                                 [/api]                               []              [get]
                                                 [/apis/*]                            []              [get]
                                                 [/apis]                              []              [get]
                                                 [/healthz]                           []              [get]
                                                 [/healthz]                           []              [get]
                                                 [/livez]                             []              [get]
                                                 [/livez]                             []              [get]
                                                 [/openapi/*]                         []              [get]
                                                 [/openapi]                           []              [get]
                                                 [/openid/v1/jwks]                    []              [get]
                                                 [/readyz]                            []              [get]
                                                 [/readyz]                            []              [get]
                                                 [/version/]                          []              [get]
                                                 [/version/]                          []              [get]
                                                 [/version]                           []              [get]
                                                 [/version]                           []              [get]

Pods (namespace: kube-public)
=============================

  #  namespace  name  status  containers  ip
  -  ---------  ----  ------  ----------  --
  No rows

Secrets (namespace: kube-public)
================================

  #  namespace    name                 type                                 data                    age
  -  ---------    ----                 ----                                 ----                    ---
  0  kube-public  default-token-2r2s4  kubernetes.io/service-account-token  ca.crt,namespace,token  19d

[+] service token default-token-2r2s4: /Users/user/.msf4/loot/20211006105714_default_127.0.0.1_kubernetes.token_198155.bin

[+] Namespace 3: kube-system
Auth (namespace: kube-system)
=============================

  Resources                                      Non-Resource URLs                    Resource Names  Verbs
  ---------                                      -----------------                    --------------  -----
  *.*                                            []                                   []              [*]
  selfsubjectaccessreviews.authorization.k8s.io  []                                   []              [create]
  selfsubjectrulesreviews.authorization.k8s.io   []                                   []              [create]
                                                 [*]                                  []              [*]
                                                 [/.well-known/openid-configuration]  []              [get]
                                                 [/api/*]                             []              [get]
                                                 [/api]                               []              [get]
                                                 [/apis/*]                            []              [get]
                                                 [/apis]                              []              [get]
                                                 [/healthz]                           []              [get]
                                                 [/healthz]                           []              [get]
                                                 [/livez]                             []              [get]
                                                 [/livez]                             []              [get]
                                                 [/openapi/*]                         []              [get]
                                                 [/openapi]                           []              [get]
                                                 [/openid/v1/jwks]                    []              [get]
                                                 [/readyz]                            []              [get]
                                                 [/readyz]                            []              [get]
                                                 [/version/]                          []              [get]
                                                 [/version/]                          []              [get]
                                                 [/version]                           []              [get]
                                                 [/version]                           []              [get]

Pods (namespace: kube-system)
=============================

  #  namespace    name                                    status   containers                                                                   ip
  -  ---------    ----                                    ------   ----------                                                                   --
  0  kube-system  coredns-558bd4d5db-2fspm                Running  coredns (image: k8s.gcr.io/coredns/coredns:v1.8.0 UDP:53,TCP:53,TCP:9153)    10.1.1.48
  1  kube-system  coredns-558bd4d5db-zx7k5                Running  coredns (image: k8s.gcr.io/coredns/coredns:v1.8.0 UDP:53,TCP:53,TCP:9153)    10.1.1.59
  2  kube-system  etcd-docker-desktop                     Running  etcd (image: k8s.gcr.io/etcd:3.4.13-0)                                       192.168.65.4
  3  kube-system  kube-apiserver-docker-desktop           Running  kube-apiserver (image: k8s.gcr.io/kube-apiserver:v1.21.2)                    192.168.65.4
  4  kube-system  kube-controller-manager-docker-desktop  Running  kube-controller-manager (image: k8s.gcr.io/kube-controller-manager:v1.21.2)  192.168.65.4
  5  kube-system  kube-proxy-tvgm2                        Running  kube-proxy (image: k8s.gcr.io/kube-proxy:v1.21.2)                            192.168.65.4
  6  kube-system  kube-scheduler-docker-desktop           Running  kube-scheduler (image: k8s.gcr.io/kube-scheduler:v1.21.2)                    192.168.65.4
  7  kube-system  storage-provisioner                     Running  storage-provisioner (image: docker/desktop-storage-provisioner:v2.0)         10.1.1.49
  8  kube-system  vpnkit-controller                       Running  vpnkit-controller (image: docker/desktop-vpnkit-controller:v2.0)             10.1.1.54

Secrets (namespace: kube-system)
================================

  #   namespace    name                                            type                                 data                    age
  -   ---------    ----                                            ----                                 ----                    ---
  0   kube-system  attachdetach-controller-token-4tnpl             kubernetes.io/service-account-token  ca.crt,namespace,token  19d
  1   kube-system  bootstrap-signer-token-kqgwd                    kubernetes.io/service-account-token  ca.crt,namespace,token  19d
  2   kube-system  certificate-controller-token-g2lcs              kubernetes.io/service-account-token  ca.crt,namespace,token  19d
  3   kube-system  clusterrole-aggregation-controller-token-9kh9j  kubernetes.io/service-account-token  ca.crt,namespace,token  19d
  4   kube-system  coredns-token-xjv86                             kubernetes.io/service-account-token  ca.crt,namespace,token  19d
  5   kube-system  cronjob-controller-token-wddp5                  kubernetes.io/service-account-token  ca.crt,namespace,token  19d
  6   kube-system  daemon-set-controller-token-7w2wt               kubernetes.io/service-account-token  ca.crt,namespace,token  19d
  7   kube-system  default-token-hq24x                             kubernetes.io/service-account-token  ca.crt,namespace,token  19d
  8   kube-system  deployment-controller-token-bf8ks               kubernetes.io/service-account-token  ca.crt,namespace,token  19d
  9   kube-system  disruption-controller-token-j4mlp               kubernetes.io/service-account-token  ca.crt,namespace,token  19d
  10  kube-system  endpoint-controller-token-sqdg2                 kubernetes.io/service-account-token  ca.crt,namespace,token  19d
  11  kube-system  endpointslice-controller-token-wr2v9            kubernetes.io/service-account-token  ca.crt,namespace,token  19d
  12  kube-system  endpointslicemirroring-controller-token-4lqdn   kubernetes.io/service-account-token  ca.crt,namespace,token  19d
  13  kube-system  ephemeral-volume-controller-token-67k95         kubernetes.io/service-account-token  ca.crt,namespace,token  19d
  14  kube-system  expand-controller-token-cmfwt                   kubernetes.io/service-account-token  ca.crt,namespace,token  19d
  15  kube-system  generic-garbage-collector-token-sxdc8           kubernetes.io/service-account-token  ca.crt,namespace,token  19d
  16  kube-system  horizontal-pod-autoscaler-token-267qc           kubernetes.io/service-account-token  ca.crt,namespace,token  19d
  17  kube-system  job-controller-token-hzv9p                      kubernetes.io/service-account-token  ca.crt,namespace,token  19d
  18  kube-system  kube-proxy-token-cqw2h                          kubernetes.io/service-account-token  ca.crt,namespace,token  19d
  19  kube-system  namespace-controller-token-cldm6                kubernetes.io/service-account-token  ca.crt,namespace,token  19d
  20  kube-system  node-controller-token-tjtk5                     kubernetes.io/service-account-token  ca.crt,namespace,token  19d
  21  kube-system  persistent-volume-binder-token-2n7jx            kubernetes.io/service-account-token  ca.crt,namespace,token  19d
  22  kube-system  pod-garbage-collector-token-vgzrz               kubernetes.io/service-account-token  ca.crt,namespace,token  19d
  23  kube-system  pv-protection-controller-token-5jvqn            kubernetes.io/service-account-token  ca.crt,namespace,token  19d
  24  kube-system  pvc-protection-controller-token-jg5sn           kubernetes.io/service-account-token  ca.crt,namespace,token  19d
  25  kube-system  replicaset-controller-token-zvblz               kubernetes.io/service-account-token  ca.crt,namespace,token  19d
  26  kube-system  replication-controller-token-tcj4p              kubernetes.io/service-account-token  ca.crt,namespace,token  19d
  27  kube-system  resourcequota-controller-token-q5nsg            kubernetes.io/service-account-token  ca.crt,namespace,token  19d
  28  kube-system  root-ca-cert-publisher-token-ghh92              kubernetes.io/service-account-token  ca.crt,namespace,token  19d
  29  kube-system  service-account-controller-token-ljxn7          kubernetes.io/service-account-token  ca.crt,namespace,token  19d
  30  kube-system  service-controller-token-dg8ks                  kubernetes.io/service-account-token  ca.crt,namespace,token  19d
  31  kube-system  statefulset-controller-token-dcx8k              kubernetes.io/service-account-token  ca.crt,namespace,token  19d
  32  kube-system  storage-provisioner-token-52m2w                 kubernetes.io/service-account-token  ca.crt,namespace,token  19d
  33  kube-system  token-cleaner-token-lc8jh                       kubernetes.io/service-account-token  ca.crt,namespace,token  19d
  34  kube-system  ttl-after-finished-controller-token-qkv66       kubernetes.io/service-account-token  ca.crt,namespace,token  19d
  35  kube-system  ttl-controller-token-rw6zq                      kubernetes.io/service-account-token  ca.crt,namespace,token  19d
  36  kube-system  vpnkit-controller-token-l9ljz                   kubernetes.io/service-account-token  ca.crt,namespace,token  19d

[+] service token attachdetach-controller-token-4tnpl: /Users/user/.msf4/loot/20211006105714_default_127.0.0.1_kubernetes.token_443806.bin
[+] service token bootstrap-signer-token-kqgwd: /Users/user/.msf4/loot/20211006105714_default_127.0.0.1_kubernetes.token_334381.bin
[+] service token certificate-controller-token-g2lcs: /Users/user/.msf4/loot/20211006105714_default_127.0.0.1_kubernetes.token_780446.bin
[+] service token clusterrole-aggregation-controller-token-9kh9j: /Users/user/.msf4/loot/20211006105714_default_127.0.0.1_kubernetes.token_695659.bin
[+] service token coredns-token-xjv86: /Users/user/.msf4/loot/20211006105714_default_127.0.0.1_kubernetes.token_035400.bin
[+] service token cronjob-controller-token-wddp5: /Users/user/.msf4/loot/20211006105714_default_127.0.0.1_kubernetes.token_256456.bin
[+] service token daemon-set-controller-token-7w2wt: /Users/user/.msf4/loot/20211006105714_default_127.0.0.1_kubernetes.token_370856.bin
[+] service token default-token-hq24x: /Users/user/.msf4/loot/20211006105714_default_127.0.0.1_kubernetes.token_167584.bin
[+] service token deployment-controller-token-bf8ks: /Users/user/.msf4/loot/20211006105714_default_127.0.0.1_kubernetes.token_668044.bin
[+] service token disruption-controller-token-j4mlp: /Users/user/.msf4/loot/20211006105714_default_127.0.0.1_kubernetes.token_025629.bin
[+] service token endpoint-controller-token-sqdg2: /Users/user/.msf4/loot/20211006105714_default_127.0.0.1_kubernetes.token_952597.bin
[+] service token endpointslice-controller-token-wr2v9: /Users/user/.msf4/loot/20211006105714_default_127.0.0.1_kubernetes.token_454535.bin
[+] service token endpointslicemirroring-controller-token-4lqdn: /Users/user/.msf4/loot/20211006105714_default_127.0.0.1_kubernetes.token_573333.bin
[+] service token ephemeral-volume-controller-token-67k95: /Users/user/.msf4/loot/20211006105714_default_127.0.0.1_kubernetes.token_791145.bin
[+] service token expand-controller-token-cmfwt: /Users/user/.msf4/loot/20211006105714_default_127.0.0.1_kubernetes.token_350984.bin
[+] service token generic-garbage-collector-token-sxdc8: /Users/user/.msf4/loot/20211006105714_default_127.0.0.1_kubernetes.token_095555.bin
[+] service token horizontal-pod-autoscaler-token-267qc: /Users/user/.msf4/loot/20211006105714_default_127.0.0.1_kubernetes.token_696872.bin
[+] service token job-controller-token-hzv9p: /Users/user/.msf4/loot/20211006105714_default_127.0.0.1_kubernetes.token_709657.bin
[+] service token kube-proxy-token-cqw2h: /Users/user/.msf4/loot/20211006105714_default_127.0.0.1_kubernetes.token_148992.bin
[+] service token namespace-controller-token-cldm6: /Users/user/.msf4/loot/20211006105714_default_127.0.0.1_kubernetes.token_138901.bin
[+] service token node-controller-token-tjtk5: /Users/user/.msf4/loot/20211006105714_default_127.0.0.1_kubernetes.token_113414.bin
[+] service token persistent-volume-binder-token-2n7jx: /Users/user/.msf4/loot/20211006105714_default_127.0.0.1_kubernetes.token_154991.bin
[+] service token pod-garbage-collector-token-vgzrz: /Users/user/.msf4/loot/20211006105714_default_127.0.0.1_kubernetes.token_413568.bin
[+] service token pv-protection-controller-token-5jvqn: /Users/user/.msf4/loot/20211006105714_default_127.0.0.1_kubernetes.token_233791.bin
[+] service token pvc-protection-controller-token-jg5sn: /Users/user/.msf4/loot/20211006105714_default_127.0.0.1_kubernetes.token_468067.bin
[+] service token replicaset-controller-token-zvblz: /Users/user/.msf4/loot/20211006105714_default_127.0.0.1_kubernetes.token_821269.bin
[+] service token replication-controller-token-tcj4p: /Users/user/.msf4/loot/20211006105714_default_127.0.0.1_kubernetes.token_210131.bin
[+] service token resourcequota-controller-token-q5nsg: /Users/user/.msf4/loot/20211006105714_default_127.0.0.1_kubernetes.token_510682.bin
[+] service token root-ca-cert-publisher-token-ghh92: /Users/user/.msf4/loot/20211006105714_default_127.0.0.1_kubernetes.token_341707.bin
[+] service token service-account-controller-token-ljxn7: /Users/user/.msf4/loot/20211006105714_default_127.0.0.1_kubernetes.token_242421.bin
[+] service token service-controller-token-dg8ks: /Users/user/.msf4/loot/20211006105714_default_127.0.0.1_kubernetes.token_231000.bin
[+] service token statefulset-controller-token-dcx8k: /Users/user/.msf4/loot/20211006105714_default_127.0.0.1_kubernetes.token_346820.bin
[+] service token storage-provisioner-token-52m2w: /Users/user/.msf4/loot/20211006105714_default_127.0.0.1_kubernetes.token_889808.bin
[+] service token token-cleaner-token-lc8jh: /Users/user/.msf4/loot/20211006105714_default_127.0.0.1_kubernetes.token_071179.bin
[+] service token ttl-after-finished-controller-token-qkv66: /Users/user/.msf4/loot/20211006105714_default_127.0.0.1_kubernetes.token_155663.bin
[+] service token ttl-controller-token-rw6zq: /Users/user/.msf4/loot/20211006105714_default_127.0.0.1_kubernetes.token_730592.bin
[+] service token vpnkit-controller-token-l9ljz: /Users/user/.msf4/loot/20211006105714_default_127.0.0.1_kubernetes.token_693223.bin

[+] Namespace 4: kubernetes-dashboard
Auth (namespace: kubernetes-dashboard)
======================================

  Resources                                      Non-Resource URLs                    Resource Names  Verbs
  ---------                                      -----------------                    --------------  -----
  *.*                                            []                                   []              [*]
  selfsubjectaccessreviews.authorization.k8s.io  []                                   []              [create]
  selfsubjectrulesreviews.authorization.k8s.io   []                                   []              [create]
                                                 [*]                                  []              [*]
                                                 [/.well-known/openid-configuration]  []              [get]
                                                 [/api/*]                             []              [get]
                                                 [/api]                               []              [get]
                                                 [/apis/*]                            []              [get]
                                                 [/apis]                              []              [get]
                                                 [/healthz]                           []              [get]
                                                 [/healthz]                           []              [get]
                                                 [/livez]                             []              [get]
                                                 [/livez]                             []              [get]
                                                 [/openapi/*]                         []              [get]
                                                 [/openapi]                           []              [get]
                                                 [/openid/v1/jwks]                    []              [get]
                                                 [/readyz]                            []              [get]
                                                 [/readyz]                            []              [get]
                                                 [/version/]                          []              [get]
                                                 [/version/]                          []              [get]
                                                 [/version]                           []              [get]
                                                 [/version]                           []              [get]

Pods (namespace: kubernetes-dashboard)
======================================

  #  namespace             name                                        status   containers                                                                       ip
  -  ---------             ----                                        ------   ----------                                                                       --
  0  kubernetes-dashboard  dashboard-metrics-scraper-856586f554-c2pz5  Running  dashboard-metrics-scraper (image: kubernetesui/metrics-scraper:v1.0.6 TCP:8000)  10.1.1.60
  1  kubernetes-dashboard  kubernetes-dashboard-67484c44f6-4hh4j       Running  kubernetes-dashboard (image: kubernetesui/dashboard:v2.3.1 TCP:8443)             10.1.1.46

Secrets (namespace: kubernetes-dashboard)
=========================================

  #  namespace             name                              type                                 data                    age
  -  ---------             ----                              ----                                 ----                    ---
  0  kubernetes-dashboard  default-token-6gwtz               kubernetes.io/service-account-token  ca.crt,namespace,token  19d
  1  kubernetes-dashboard  kubernetes-dashboard-certs        Opaque                                                       19d
  2  kubernetes-dashboard  kubernetes-dashboard-csrf         Opaque                               csrf                    19d
  3  kubernetes-dashboard  kubernetes-dashboard-key-holder   Opaque                               priv,pub                19d
  4  kubernetes-dashboard  kubernetes-dashboard-token-gfhhr  kubernetes.io/service-account-token  ca.crt,namespace,token  19d

[+] service token default-token-6gwtz: /Users/user/.msf4/loot/20211006105714_default_127.0.0.1_kubernetes.token_854995.bin
[+] service token kubernetes-dashboard-token-gfhhr: /Users/user/.msf4/loot/20211006105714_default_127.0.0.1_kubernetes.token_729795.bin

[*] Auxiliary module execution completed
msf6 auxiliary(cloud/kubernetes/enum_kubernetes) >
```

### Using actions

See available actions:

```
msf6 auxiliary(cloud/kubernetes/enum_kubernetes) > show actions

Auxiliary actions:

   Name        Description
   ----        -----------
   all         enumerate all resources
   auth        enumerate auth
   namespace   enumerate namespace
   namespaces  enumerate namespaces
   pod         enumerate pod
   pods        enumerate pods
   secret      enumerate secret
   secrets     enumerate secrets
   version     enumerate version

```

Enumerate pods:
```
msf6 auxiliary(cloud/kubernetes/enum_kubernetes) > pods
[*] Running module against 127.0.0.1
Pods (namespace: default)
=========================

  #   namespace  name                       status   containers                                       ip
  -   ---------  ----                       ------   ----------                                       --
  0   default    a4bg7r                     Running  iyxz0ujfck9t (image: vulhub/thinkphp:5.0.23)     10.1.1.51
  1   default    appjokbpiiml               Running  iggapn (image: vulhub/thinkphp:5.0.23)           10.1.1.57
  2   default    cvyf4m9le                  Running  t0e93vcuyi (image: vulhub/thinkphp:5.0.23)       10.1.1.53
  3   default    fh4bfdtf                   Running  dygvv (image: vulhub/thinkphp:5.0.23)            10.1.1.52
  4   default    gavp                       Running  jfwdaei (image: vulhub/thinkphp:5.0.23)          10.1.1.58
  5   default    mkfkuwd6hkd1               Running  aoavh (image: vulhub/thinkphp:5.0.23)            10.1.1.62
  6   default    nid7jd                     Running  geb (image: vulhub/thinkphp:5.0.23)              10.1.1.45
  7   default    redis-7fd956df5-sbchb      Running  redis (image: redis:5.0.4 TCP:6379)              10.1.1.56
  8   default    thinkphp-67f7c88cc9-djg6q  Running  thinkphp (image: vulhub/thinkphp:5.0.23 TCP:80)  10.1.1.55
  9   default    thinkphp-67f7c88cc9-l56mg  Running  thinkphp (image: vulhub/thinkphp:5.0.23 TCP:80)  10.1.1.44
  10  default    usuuucs                    Running  xfcw (image: vulhub/thinkphp:5.0.23)             10.1.1.50
  11  default    v2xxl7z                    Running  nu3s (image: vulhub/thinkphp:5.0.23)             10.1.1.61
  12  default    yulfpaohsepk               Running  jjmxkkzgkmy (image: vulhub/thinkphp:5.0.23)      10.1.1.47


[*] Auxiliary module execution completed
```

Enumerate a pod with a specified namespace, name:

```
msf6 auxiliary(cloud/kubernetes/enum_kubernetes) > pod namespace=default name=redis-7fd956df5-sbchb
[*] Running module against 127.0.0.1
Pods (namespace: default)
=========================

  #  namespace  name                   status   containers                           ip
  -  ---------  ----                   ------   ----------                           --
  0  default    redis-7fd956df5-sbchb  Running  redis (image: redis:5.0.4 TCP:6379)  10.1.1.56


[*] Auxiliary module execution completed
```

Enumerate a pod with a specified namespace, name, and outputting the result as JSON:

```
msf6 auxiliary(cloud/kubernetes/enum_kubernetes) > pod namespace=default name=redis-7fd956df5-sbchb output=json 
[*] Running module against 127.0.0.1

[
  {
    "kind": "Pod",
    "apiVersion": "v1",
    "metadata": {
      "name": "redis-7fd956df5-sbchb",
      "generateName": "redis-7fd956df5-",
      "namespace": "default",
      "uid": "0f00c08c-bdb1-4206-94ce-5c447cd2d446",
      "resourceVersion": "629723",
      "creationTimestamp": "2021-09-16T22:33:33Z",
      "labels": {
        "app": "redis",
        "pod-template-hash": "7fd956df5",
        "role": "leader",
        "tier": "backend"
      },
    },
    ... etc ...
  }
]
[*] Auxiliary module execution completed
```
