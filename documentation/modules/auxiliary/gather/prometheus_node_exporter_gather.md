## Vulnerable Application

Instructions to get the vulnerable application. If applicable, include links to the vulnerable install
files, as well as instructions on installing/configuring the environment if it is different than a
standard install. Much of this will come from the PR, and can be copy/pasted.

### Install

docker run -d   --net="host"   --pid="host"   -v "/:/host:ro,rslave"   quay.io/prometheus/node-exporter:latest   --path.rootfs=/host

./node_exporter --collector.buddyinfo --collector.cgroups --collector.drm --collector.drbd --collector.ethtool --collecto
r.interrupts --collector.ksmd --collector.lnstat --collector.logind --collector.meminfo_numa --collector.mountstats --collector.network_route --collector.perf --collector.proce
sses --collector.qdisc --collector.slabinfo --collector.softirqs --collector.sysctl --collector.systemd --collector.tcpstat --collector.wifi --collector.zoneinfo

windows --collectors.enabled ad,adcs,adfs,cache,cpu,cpu_info,cs,container,dfsr,dhcp,dns,exchange,fsrmquota,hyperv,iis,logical_disk,logon,memory,mscluster_cluster,mscluster_network,mscluster_node,mscluster_resource,mscluster_resourcegroup,msmq,mssql,netframework_clrexceptions,netframework_clrinterop,netframework_clrjit,netframework_clrloading,netframework_clrlocksandthreads,netframework_clrmemory,netframework_clrremoting,netframework_clrsecurity,net,os,process,remote_fx,scheduled_task,service,smtp,system,tcp,teradici_pcoip,time,thermalzone,terminal_services,textfile,vmware_blast,vmware

## Verification Steps
Example steps in this format (is also in the PR):

1. Install the application
1. Start msfconsole
1. Do: `use [module path]`
1. Do: `run`
1. You should get a shell.

## Options
List each option and how to use it.

### Option Name

Talk about what it does, and how to use it appropriately. If the default value is likely to change, include the default value here.

## Scenarios
Specific demo of using the module that might be useful in a real world scenario.

### Version and OS

```
code or console output
```

For example:

To do this specific thing, here's how you do it:

```
msf > use module_name
msf auxiliary(module_name) > set POWERLEVEL >9000
msf auxiliary(module_name) > exploit
```
