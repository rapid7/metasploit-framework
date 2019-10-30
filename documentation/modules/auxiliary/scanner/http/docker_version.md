## Introduction

This module scans for Docker servers listening on a TCP port (default 2375).

## Options

**VERBOSE**

Enable this to dump all info to the screen.

## Usage

```
msf5 > use auxiliary/scanner/http/docker_version
msf5 auxiliary(scanner/http/docker_version) > set rhosts 127.0.0.1
rhosts => 127.0.0.1
msf5 auxiliary(scanner/http/docker_version) > set verbose true
verbose => true
msf5 auxiliary(scanner/http/docker_version) > run

[*] Identifying Docker Server Version on 127.0.0.1:2375
[+] [Docker Server] Version: 18.03.1-ce
[*] All info: {"Platform"=>{"Name"=>""}, "Components"=>[{"Name"=>"Engine", "Version"=>"18.03.1-ce", "Details"=>{"ApiVersion"=>"1.37", "Arch"=>"amd64", "BuildTime"=>"2018-04-26T07:15:24.000000000+00:00", "Experimental"=>"false", "GitCommit"=>"9ee9f40", "GoVersion"=>"go1.9.5", "KernelVersion"=>"[redacted]", "MinAPIVersion"=>"1.12", "Os"=>"linux"}}], "Version"=>"18.03.1-ce", "ApiVersion"=>"1.37", "MinAPIVersion"=>"1.12", "GitCommit"=>"9ee9f40", "GoVersion"=>"go1.9.5", "Os"=>"linux", "Arch"=>"amd64", "KernelVersion"=>"[redacted]", "BuildTime"=>"2018-04-26T07:15:24.000000000+00:00"}
[*] Saving host information.
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
msf5 auxiliary(scanner/http/docker_version) >
```
