#!/bin/bash

set -e

info () {
    echo "[INFO] $@"
}

info "Running setup"

# Check if samba is setup
[ -f /var/lib/samba/.setup ] && info "Already setup..." && exit 0

info "Provisioning domain controller..."

info "Given admin password: ${SMB_ADMIN_PASSWORD}"

rm /etc/samba/smb.conf

samba-tool domain provision\
 --server-role=dc\
 --use-rfc2307\
 --dns-backend=SAMBA_INTERNAL\
 --realm=`hostname`\
 --domain=DEV-AD\
 --adminpass=${SMB_ADMIN_PASSWORD}\
 --option='server services = ldap'

mv /etc/samba/smb.conf /var/lib/samba/private/smb.conf

info "Applying LAPS schema changes..."
ldbadd    -H /var/lib/samba/private/sam.ldb laps-schema-add.ldif    --option="dsdb:schema update allowed"=true
ldbmodify -H /var/lib/samba/private/sam.ldb laps-schema-modify.ldif --option="dsdb:schema update allowed"=true
info "Adding LAPS test accounts..."
ldbadd    -H /var/lib/samba/private/sam.ldb laps-accounts.ldif

touch /var/lib/samba/.setup
