Symantec Messaging Gateway is an all-in-one appliance to secure email with real-time antispam,
antimalware, targeted attacks, content filtering, data loss, and email encryption.

The management console of SMG can be used to recover the AD password by any user with at least
read access to the appliance, which could potentially permit leveraging unauthorized, elevated
access to other resources of the network.

Authentication is required to use symantec_brightmail_ldapcreds. However, it is possible to see
SMG with using the default username **admin** and **symantec**.


## Vulnerable Application

Symantec Messaging Gateway 10.6.0 and earlier are known to be vulnerable.

symantec_brightmail_ldapcreds was specifically tested against 10.6.0 during development.

## Verification Steps

These verification steps assume you already have access to the vulnerable version of
[Symantec Messaging Gateway](https://www.symantec.com/products/threat-protection/messaging-gateway).
During the development of symantec_brightmail_ldapcreds, Symantec was still providing 10.6.0 as a trial.

**Installation**

The 10.6.0 installation guide can be found [here](https://symwisedownload.symantec.com//resources/sites/SYMWISE/content/live/DOCUMENTATION/9000/DOC9108/en_US/smg_10.6_installation_guide.pdf?__gda__=1465490103_20360f5503fd3ef6ce426bd541fd2109)

Make sure you remember your username and password for Symantec Messaging Gateway before using
the module.

**Using the Module**

Once you have the vulnerable setup ready, go ahead and do this:

1. Start msfconsole
2. Do: ```use auxiliary/scanner/http/symantec_brightmail_ldapcreds```
3. Do: ```set RHOSTS [IP]```
4. Do: ```set USERNAME [USERNAME FOR SMG]```
5. Do: ```set PASSWORD [PASSWORD FOR SMG]```
6. Do: ```run```