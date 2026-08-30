# syntax=docker/dockerfile:1
FROM ubuntu:22.04
MAINTAINER metasploit-framework <https://github.com/rapid7/metasploit-framework>

EXPOSE 22

# Switch shells to support ANSI-C quoting:
#   https://stackoverflow.com/questions/33439230/how-to-write-commands-with-multiple-lines-in-dockerfile-while-preserving-the-new
SHELL ["/bin/bash", "-c"]

RUN apt-get update && apt-get install -y --no-install-recommends \
    openssh-client \
    openssh-server

# Create the privilege separation directory required by sshd
RUN mkdir -p /run/sshd

# Create the test user and set a known password
RUN useradd -m -s /bin/bash acceptance_tests_user
RUN echo 'acceptance_tests_user:acceptance_tests_password' | chpasswd

# Allow password authentication and permit root login for test purposes
RUN sed -i \
    -e 's/^#\?PasswordAuthentication.*/PasswordAuthentication yes/' \
    -e 's/^#\?PermitRootLogin.*/PermitRootLogin yes/' \
    /etc/ssh/sshd_config

# Generate host keys
RUN ssh-keygen -A

ENTRYPOINT ["/usr/sbin/sshd", "-D", "-e"]
