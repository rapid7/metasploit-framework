## Vulnerable Application

This modules connects to a Prometheus Node Exporter or Windows Exporter service
and gathers information about the host.

Tested against Docker image 1.6.1, Linux 1.6.1, and Windows 0.23.1

### Install

#### Docker

`docker run -d --net="host" --pid="host" -v "/:/host:ro,rslave" quay.io/prometheus/node-exporter:latest --path.rootfs=/host`

#### Linux

[Instructions](https://prometheus.io/docs/guides/node-exporter/#installing-and-running-the-node-exporter)

```
wget https://github.com/prometheus/node_exporter/releases/download/v1.6.1/node_exporter-1.6.1.linux-amd64.tar.gz
tar xvfz node_exporter-1.6.1.linux-amd64.tar.gz
cd node_exporter-*.*-amd64
./node_exporter --collector.buddyinfo --collector.cgroups --collector.drm --collector.drbd --collector.ethtool --collector.interrupts --collector.ksmd --collector.lnstat --collector.logind --collector.meminfo_numa --collector.mountstats --collector.network_route --collector.perf --collector.processes --collector.qdisc --collector.slabinfo --collector.softirqs --collector.sysctl --collector.systemd --collector.tcpstat --collector.wifi --collector.zoneinfo
```

#### Windows

Download the latest release from [github](https://github.com/prometheus-community/windows_exporter/releases)

Run it with the following command:
```
.\windows_exporter-0.23.1-amd64.exe --collectors.enabled ad,adcs,adfs,cache,cpu,cpu_info,cs,container,dfsr,dhcp,dns,exchange,fsrmquota,hyperv,iis,logical_disk,logon,memory,mscluster_cluster,mscluster_network,mscluster_node,mscluster_resource,mscluster_resourcegroup,msmq,mssql,netframework_clrexceptions,netframework_clrinterop,netframework_clrjit,netframework_clrloading,netframework_clrlocksandthreads,netframework_clrmemory,netframework_clrremoting,netframework_clrsecurity,net,os,process,remote_fx,scheduled_task,service,smtp,system,tcp,teradici_pcoip,time,thermalzone,terminal_services,textfile,vmware_blast,vmware
```

## Verification Steps

1. Install the application
1. Start msfconsole
1. Do: `use auxiliary/gather/prometheus_node_exporter_gather`
1. Do: `set rhosts [ip]`
1. Do: `run`
1. You should get information back about the host.

## Options

## Scenarios

### Docker 1.6.1

```
msf6 > use auxiliary/gather/prometheus_node_exporter_gather 
msf6 auxiliary(gather/prometheus_node_exporter_gather) > set rhosts 127.0.0.1
rhosts => 127.0.0.1
msf6 auxiliary(gather/prometheus_node_exporter_gather) > set verbose true
verbose => true
msf6 auxiliary(gather/prometheus_node_exporter_gather) > run
[*] Running module against 127.0.0.1

[*] 127.0.0.1:9100 - Checking 
[+] 127.0.0.1:9100 - Prometheus Node Exporter version: 1.6.1
[+] Go Version: go1.20.6
[+] SELinux enabled: 0
[+] Timezone: UTC
[+] BIOS Information
================

  Field              Value
  -----              -----
  Asset Tag
  Board Name         000000
  Board Vendor       Sanitized
  Board Version      111
  Chassis Asset Tag
  Chassis Vendor     Sanitized
  Date               04/17/2023
  Product Family     Sanitized
  Product Name       Sanitized
  System Vendor      Sanitized
  Vendor             Sanitized
  Version            1.0.0

[+] OS Information
==============

  Field             Value
  -----             -----
  Family            kali
  Name              Kali GNU/Linux
  Pretty Name       Kali GNU/Linux Rolling
  Version           2023.3
  Version Codename  kali-rolling
  Version ID        2023.3

[+] Network Interfaces
==================

  Device           MAC                Broadcast          State
  ------           ---                ---------          -----
  br-4b55fa64cd13  de:ad:be:ef:de:ad  de:ad:be:ef:de:ad  down
  br-65f1f7a9ff61  de:ad:be:ef:de:ad  de:ad:be:ef:de:ad  down
  docker0          de:ad:be:ef:de:ad  de:ad:be:ef:de:ad  up
  eth0             de:ad:be:ef:de:ad  de:ad:be:ef:de:ad  down
  lo               de:ad:be:ef:de:ad  de:ad:be:ef:de:ad  unknown
  vethe418d5c      de:ad:be:ef:de:ad  de:ad:be:ef:de:ad  up
  wlan0            de:ad:be:ef:de:ad  de:ad:be:ef:de:ad  up

[+] File Systems
============

  Device                              Mount Point     FS Type
  ------                              -----------     -------
  /dev/mapper/map--new--vg-root       /               ext4
  /dev/nvme0n1p1                      /boot/efi       vfat
  /dev/nvme1n1p2                      /boot           ext2
  tmpfs                               /run            tmpfs
  tmpfs                               /run/lock       tmpfs
  tmpfs                               /run/user/1000  tmpfs
  tmpfs                               /run/user/125   tmpfs

[+] uname Information
=================

  Field        Value
  -----        -----
  Arch         x86_64
  Domain Name  (none)
  Node Name    ragekali-new
  OS Type      Linux
  Release      6.3.0-kali1-amd64
  Version      #1 SMP PREEMPT_DYNAMIC Debian 6.3.7-1kali1 (2023-06-29)

[*] Auxiliary module execution completed
```
