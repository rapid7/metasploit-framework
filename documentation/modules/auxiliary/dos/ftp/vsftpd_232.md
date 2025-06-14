## Vulnerable Application

This is an auxiliary for DOSing a VSFTPD server from version 2.3.2 and below. The
vulnerability has been directly tested on versions 2.3.0, 2.3.1, and 2.3.2 and have
shown success.

VSFTPD is a popular ftp server written in C. The vulnerability causes a DOS on
the service by leveraging a long recursive glob statement on the server. When
we fill the 4096 character buffer with this recursive glob search, it makes the
current thread spend all of that time unwinding that glob statement which can
use up all the resources on that core. Sending this glob on all threads leave no
availability for anyone else to access the server while taking up all of the CPU
resources of the machine.

## Options

### FTPUSER
The username used to log into the FTP server

### FTPPASS
The password used to log into the FTP server

### Install on Arch Linux

The software has been tested on multiple versions using arch linux. To create an
installable package for the vulnerable software to test, follow these instructions.

1. Clone the source repository using `git clone https://gitlab.archlinux.org/archlinux/packaging/packages/vsftpd.git`
2. Replace the contents of the PKGBUILD with this

```pkgbuild
pkgname=vsftpd
pkgver=2.3.2
pkgrel=1
pkgdesc='Very Secure FTP daemon'
url='https://security.appspot.com/vsftpd.html'
arch=('x86_64')
license=('GPL2')
depends=('glibc' 'openssl' 'libcap' 'pam' 'libnsl')
optdepends=('logrotate')
backup=('etc/vsftpd.conf'
        'etc/xinetd.d/vsftpd'
        "etc/logrotate.d/vsftpd")
source=(https://security.appspot.com/downloads/${pkgname}-${pkgver}.tar.gz
        vsftpd-ssl.socket
        vsftpd.socket
        vsftpd.service
        vsftpd@.service
        vsftpd-ssl.service
        vsftpd-ssl@.service)
sha256sums=('SKIP'
            'd5185e48fffc6253499a55e0fe0f90a3424fc639640af11a9d38df33fb145afe'
            '9fdbfd2ec0207170371ca3cf2b0ddca2dc2fe3d062e5792e0d3e51474c3198c9'
            '0597e571718ba0f4dc4b32a4ddd148103758c48c7d65dcb8bbedafc9e810e83d'
            'd7b8e4827d4f6bafcbf52f9d2d7380958c7b08bb3f757806aa89d4bc06c9671c'
            'b88a50fc68b3bf746d13c9a777df77791cd3eac6eb7c2df655418071c2adf422'
            '4a55c2468b08d858f71bacf1f4885847bec8e548b0e92088068d9bdd3884af84')

prepare() {
  cd ${pkgname}-${pkgver}
  # build-time config
  sed -e 's|^#undef VSF_BUILD_SSL$|#define VSF_BUILD_SSL|' -i builddefs.h
  sed -e 's|/usr/share/empty|/var/empty|g' -i tunables.c vsftpd.conf.5 INSTALL
  sed -e 's|/usr/local/sbin/vsftpd|/usr/bin/vsftpd|' -i EXAMPLE/INTERNET_SITE/${pkgname}.xinetd

  # fix linking to openssl 1.1
  sed -e 's|SSL_library_init|SSL_CTX_new|' -i vsf_findlibs.sh
}

build() {
  cd ${pkgname}-${pkgver}
  make LINK='' CFLAGS="${CFLAGS} ${CPPFLAGS}" LDFLAGS="${LDFLAGS}"
}

package() {
  cd ${pkgname}-${pkgver}

  install -Dm 755 ${pkgname} -t "${pkgdir}/usr/bin"
  install -dm 755 "${pkgdir}/var/empty"
  install -Dm 644 "${srcdir}"/{*.service,*.socket} -t "${pkgdir}/usr/lib/systemd/system"

  install -Dm 644 ${pkgname}.conf -t "${pkgdir}/etc"
  install -Dm 644 EXAMPLE/INTERNET_SITE/${pkgname}.xinetd "${pkgdir}/etc/xinetd.d/${pkgname}"
  install -Dm 644 RedHat/vsftpd.log "${pkgdir}/etc/logrotate.d/${pkgname}"
  install -Dm 644 RedHat/vsftpd.pam "${pkgdir}/etc/pam.d/${pkgname}"

  install -Dm 644 ${pkgname}.8 -t "${pkgdir}/usr/share/man/man8"
  install -Dm 644 ${pkgname}.conf.5 -t "${pkgdir}/usr/share/man/man5"
  install -Dm 644 BENCHMARKS BUGS Changelog FAQ INSTALL README README.ssl REFS \
    REWARD SPEED TODO TUNING -t "${pkgdir}/usr/share/doc/${pkgname}"
}
```

3. If you want to test a different version, Change the version variable to your
desired version.
4. Run `makepkg -i` to build the package and automatically install it.
5. Start the systemd service with `sudo systemctl start vsftpd`

### Docker install on Arch Linux

A simple container was created to easily test this vulnerability. To easily run a
vulnerable instance of this application, build this image from this Dockerfile.

1. Create a `Dockerfile` and place the content below into it

```dockerfile
FROM archlinux:latest
ARG VERSION=2.3.2
RUN pacman -Sy --noconfirm gcc make libnsl
RUN curl -O https://security.appspot.com/downloads/vsftpd-$VERSION.tar.gz
RUN tar zxf vsftpd-$VERSION.tar.gz
WORKDIR /vsftpd-$VERSION
RUN make
RUN mkdir -p /usr/share/empty/
RUN chmod +x /vsftpd-$VERSION/vsftpd
RUN mv /vsftpd-$VERSION/vsftpd /bin/vsftpd
RUN mv /vsftpd-$VERSION/vsftpd.conf /etc/vsftpd.conf
RUN chown root:root /etc/vsftpd.conf
EXPOSE 21
CMD [ "/bin/vsftpd" ]
```

2. Run `sudo docker build . -t vsftpd:2.3.2 --build-arg=2.3.2`
3. Run `sudo docker run --name vsftpd -p 21:21 vsftpd:2.3.2`

Run the module against this container and the container will either slow down or crash entirely.

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

You can verify that it works by either attempting to ftp into the machine after or checking
htop on the machine. If the CPU is at max capacity, that would be due to the DOS.
