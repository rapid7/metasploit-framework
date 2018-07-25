## Local MITM

Change the proxy settings of the victim computer to the one provided by the user.

## Vulnerable Application

The following platforms are supported:


* Windows (require administration privileges)
* Linux


## Verification Steps

1. Get a session.
2. `use post/multi/local_mitm`.
3. Set the `SESSION` option.
4. `set PRXHOST <proxy host>`.
5. `set PRXPORT <proxy port>`.
6. `run`.


### Cleaning up

1. `set action CLEANUP`.
2. `run`.


## Actions

**INSTALL** (default)

Update the proxy settings.


**CLEANUP**

Remove proxy settings.


## Parameters

**PRXHOST**

Host of the proxy server, such as `123.45.67.89`.


**PRXPORT**

Port of the proxy server, such as `8080`.
