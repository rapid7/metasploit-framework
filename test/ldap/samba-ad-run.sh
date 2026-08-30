#!/bin/bash

set -e

[ -f /var/lib/samba/.setup ] || {
    >&2 echo "[ERROR] Samba is not setup yet, which should happen automatically. Look for errors!"
    exit 127
}

cat << EOF > /var/lib/samba/private/smb.conf
# Global parameters
[global]
	dns forwarder = 192.168.65.7
	#server services = s3fs, rpc, nbt, wrepl, ldap, cldap, kdc, drepl, winbindd, ntp_signd, kcc, dnsupdate
	server services = ldap

	netbios name = LDAP
	realm = LDAP.EXAMPLE.COM
	server role = active directory domain controller
	workgroup = DEV-AD
	idmap_ldb:use rfc2307 = yes
	ldap server require strong auth = no
	allow dns updates = disabled
[sysvol]
	path = /var/lib/samba/sysvol
	read only = No

[netlogon]
	path = /var/lib/samba/sysvol/ldap.example.com/scripts
	read only = No
EOF

samba -i -s /var/lib/samba/private/smb.conf
