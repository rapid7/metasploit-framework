# What does my Rex::Proto::SMB Error mean?
All SMB error codes are explained in the following MSDN documentation:

[http://msdn.microsoft.com/en-us/library/ee441884.aspx](http://msdn.microsoft.com/en-us/library/ee441884.aspx)

The following is a list of commonly seen errors when using an Metasploit module that involves SMB:

* **STATUS_ACCESS_DENIED**

If you are testing against newer Windows systems such as Windows 7, by default you will see STATUS_ACCESS_DENIED because these systems no longer allow remote access to the share. To change this, that target machine will need to manually change the LocalAccountTokenFilterPolicy setting to 1 in the registry:

```
Windows Registry Editor Version 5.00

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System]
"LocalAccountTokenFilterPolicy"=dword:00000001
```

* **STATUS_LOGON_FAILURE**

Invalid SMBUSER or SMBPASS datastore option.

Or, in Local Security Settings, you should probably set **Network access:Sharing and security model for local accounts** to "**Local users authenticate as themselves**".

* **STATUS_BAD_NETWORK_NAME**

Invalid SMB share datastore option.

* **STATUS_LOGON_TYPE_NOT_GRANTED**

On Windows, in Local Security Settings, Network access:Sharing and security model for local accounts to "Local users authenticate as themselves".