The post/gather/hashdump module functions similarly to Meterpreter's built-in hashdump command.

Having this feature as a post module allows it to be used in different penetration testing scenarios.


## Vulnerable Application


To be able to use post/gather/hash_dump, you must meet these requirements:

* You are on a Meterpreter type session.
* The target is a Windows platform.
* It must be executed under the context of a high privilege account, such as SYSTEM.

## Verification Steps

Please see Overview for usage.

## Scenarios


**Upgrading to Meterpreter**

To be able to use this module, a Meterpreter session is needed. To upgrade to a Meterpreter session, the easiest way is to use the post/multi/manage/shell_to_meterpreter module. Or, you can try:

1. Use the exploit/multi/script/web_delivery module.
2. Manually generate a Meterpreter executable, upload it, and execute it.

**High Privilege Account**

Before using post/gather/hashdump, there is a possibility you need to escalate your privileges.

There are a few common options to consider:

* Using a local exploit module. Or use Local Exploit Suggester, which automatically informs you
  which exploits might be suitable for the remote target.
* The getsystem command in Meterpreter.
* Stolen passwords.

**Hashdump From Multiple Sessions**

One major advantage of having hashdump as a post module is you can run against it multiple hosts easily. To learn how, refer to Overview for usage.
