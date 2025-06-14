# syntax=docker/dockerfile:1
FROM ubuntu:22.04 AS build
MAINTAINER metasploit-framework <https://github.com/rapid7/metasploit-framework>
WORKDIR /opt

EXPOSE 445 139

# Switch shells to support ANSI-C quoting:
#   https://stackoverflow.com/questions/33439230/how-to-write-commands-with-multiple-lines-in-dockerfile-while-preserving-the-new
SHELL ["/bin/bash", "-c"]

# Install Samba
RUN apt update && apt install -y samba smbclient

# To add a credential to Samba, the user needs to be created on the system
RUN useradd -m acceptance_tests_user

# Configure a few shares
COPY shares shares

RUN chmod -R 777 shares

COPY config/smb.conf /etc/samba/smb.conf

# Change the passwords for our user
RUN smbpasswd -a acceptance_tests_user <<EOF
acceptance_tests_password
acceptance_tests_password
EOF

# Enable the users
RUN smbpasswd -e acceptance_tests_user

RUN service smbd restart

FROM build AS runner

ENTRYPOINT ["smbd", "--foreground", "--no-process-group"]
