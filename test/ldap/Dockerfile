FROM ubuntu:20.04

RUN DEBIAN_FRONTEND=noninteractive apt-get update && DEBIAN_FRONTEND=noninteractive apt-get -y install samba krb5-config winbind smbclient
RUN DEBIAN_FRONTEND=noninteractive apt-get update && DEBIAN_FRONTEND=noninteractive apt-get -y install iproute2
RUN DEBIAN_FRONTEND=noninteractive apt-get update && DEBIAN_FRONTEND=noninteractive apt-get -y install openssl
RUN DEBIAN_FRONTEND=noninteractive apt-get update && DEBIAN_FRONTEND=noninteractive apt-get -y install vim
RUN DEBIAN_FRONTEND=noninteractive apt-get update && DEBIAN_FRONTEND=noninteractive apt-get -y install ldap-utils
RUN DEBIAN_FRONTEND=noninteractive apt-get update && DEBIAN_FRONTEND=noninteractive apt-get -y install ldb-tools

RUN rm /etc/krb5.conf
RUN mkdir -p /opt/ad-scripts

WORKDIR /opt/ad-scripts

CMD chmod +x *.sh && ./samba-ad-setup.sh && ./samba-ad-run.sh
