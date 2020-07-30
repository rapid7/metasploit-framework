## Vulnerable Application

### General Notes

This module imports a Mikrotik configuration file into the database.
This is similar to `post/networking/gather/enum_mikrotik` only access isn't required,
and assumes you already have the file.

RouterOS images can be downloaded for VMs from the MikroTik website.

* https://mikrotik.com/download
* https://mikrotik.com/download/archive

SwOS (Switch OS) can only be used on hardware devices.  These files are downloaded from the web interface.

Example files for import from a RouterOS:

### /export

  ```
  # jul/18/2020 16:07:05 by RouterOS 6.45.9
  # software id =
  #
  #
  #
  /interface ovpn-client
  add connect-to=10.99.99.98 mac-address=FE:45:B0:31:4A:34 name=ovpn-out1 password=password user=user
  add connect-to=10.99.99.98 mac-address=FE:45:B0:31:4A:34 name=ovpn-out2 password=password user=user
  add connect-to=10.99.99.98 disabled=yes mac-address=FE:45:B0:31:4A:34 name=ovpn-out3 password=password user=user
  add connect-to=10.99.99.98 mac-address=FE:45:B0:31:4A:34 name=ovpn-out4 password=password user=user
  /interface bridge
  add name=bridge_local
  /interface ethernet
  set [ find default-name=ether1 ] disable-running-check=no
  set [ find default-name=ether2 ] disable-running-check=no
  /interface pppoe-client
  # Client is on slave interface
  add disabled=no interface=ether2 name=pppoe-user password=password service-name=internet user=user
  /interface l2tp-client
  add connect-to=10.99.99.99 name=l2tp-hm password=123 user=l2tp-hm
  /interface pptp-client
  add connect-to=10.99.99.99 disabled=no name=pptp-hm password=123 user=pptp-hm
  /interface lte apn
  add apn=accesspointname
  /interface wireless security-profiles
  set [ find default=yes ] supplicant-identity=MikroTik
  add name=openwifi supplicant-identity=MikroTik
  add authentication-types=wpa-psk mode=dynamic-keys name=wpawifi supplicant-identity=MikroTik wpa-pre-shared-key=presharedkey
  add authentication-types=wpa2-psk mode=dynamic-keys name=wpa2wifi supplicant-identity=MikroTik wpa2-pre-shared-key=presharedkey
  add authentication-types=wpa2-eap mode=dynamic-keys mschapv2-password=password mschapv2-username=username name=wpaeapwifi \
      supplicant-identity=MikroTik
  add mode=static-keys-required name=wepwifi static-key-0=0123456789 static-key-1=0987654321 static-key-2=1234509876 static-key-3=\
      0192837645 supplicant-identity=MikroTik
  add mode=static-keys-required name=wep1wifi static-key-0=1111111111 supplicant-identity=MikroTik
  /ppp profile
  add bridge=bridge_local name=ppp_bridge use-encryption=yes
  /snmp community
  add addresses=::/0 authentication-password=write name=write write-access=yes
  add addresses=::/0 authentication-password=0123456789 authentication-protocol=SHA1 encryption-password=9876543210 \
      encryption-protocol=AES name=v3
  /interface bridge port
  add bridge=bridge_local interface=ether2
  /ip dhcp-client
  add dhcp-options=hostname,clientid disabled=no interface=ether1
  /ip smb users
  add name=mtuser password=mtpasswd read-only=no
  add disabled=yes name=disableduser password=disabledpasswd
  /ppp secret
  add name=ppp1 password=password profile=ppp_bridge
  /snmp
  set contact="fake <fake@fake.com>" location=nowhere
  /system identity
  set name=mikrotik_hostname
  /tool e-mail
  set address=1.1.1.1 from=router@router.com password=smtppassword user=smtpuser
  ```

### /export terse

  ```
  # jul/18/2020 16:08:41 by RouterOS 6.45.9
  # software id =
  #
  #
  #
  /interface ovpn-client add connect-to=10.99.99.98 mac-address=FE:45:B0:31:4A:34 name=ovpn-out1 password=password user=user
  /interface ovpn-client add connect-to=10.99.99.98 mac-address=FE:45:B0:31:4A:34 name=ovpn-out2 password=password user=user
  /interface ovpn-client add connect-to=10.99.99.98 disabled=yes mac-address=FE:45:B0:31:4A:34 name=ovpn-out3 password=password user=user
  /interface ovpn-client add connect-to=10.99.99.98 mac-address=FE:45:B0:31:4A:34 name=ovpn-out4 password=password user=user
  /interface bridge add name=bridge_local
  /interface ethernet set [ find default-name=ether1 ] disable-running-check=no
  /interface ethernet set [ find default-name=ether2 ] disable-running-check=no
  /interface pppoe-client
  # Client is on slave interface
  add disabled=no interface=ether2 name=pppoe-user password=password service-name=internet user=user
  /interface l2tp-client add connect-to=10.99.99.99 name=l2tp-hm password=123 user=l2tp-hm
  /interface pptp-client add connect-to=10.99.99.99 disabled=no name=pptp-hm password=123 user=pptp-hm
  /interface lte apn add apn=accesspointname
  /interface wireless security-profiles set [ find default=yes ] supplicant-identity=MikroTik
  /interface wireless security-profiles add name=openwifi supplicant-identity=MikroTik
  /interface wireless security-profiles add authentication-types=wpa-psk mode=dynamic-keys name=wpawifi supplicant-identity=MikroTik wpa-pre-shared-key=presharedkey
  /interface wireless security-profiles add authentication-types=wpa2-psk mode=dynamic-keys name=wpa2wifi supplicant-identity=MikroTik wpa2-pre-shared-key=presharedkey
  /interface wireless security-profiles add authentication-types=wpa2-eap mode=dynamic-keys mschapv2-password=password mschapv2-username=username name=wpaeapwifi supplicant-identity=MikroTik
  /interface wireless security-profiles add mode=static-keys-required name=wepwifi static-key-0=0123456789 static-key-1=0987654321 static-key-2=1234509876 static-key-3=0192837645 supplicant-identity=MikroTik
  /interface wireless security-profiles add mode=static-keys-required name=wep1wifi static-key-0=1111111111 supplicant-identity=MikroTik
  /ppp profile add bridge=bridge_local name=ppp_bridge use-encryption=yes
  /snmp community add addresses=::/0 authentication-password=write name=write write-access=yes
  /snmp community add addresses=::/0 authentication-password=0123456789 authentication-protocol=SHA1 encryption-password=9876543210 encryption-protocol=AES name=v3
  /interface bridge port add bridge=bridge_local interface=ether2
  /ip dhcp-client add dhcp-options=hostname,clientid disabled=no interface=ether1
  /ip smb users add name=mtuser password=mtpasswd read-only=no
  /ip smb users add disabled=yes name=disableduser password=disabledpasswd
  /ppp secret add name=ppp1 password=password profile=ppp_bridge
  /snmp set contact="fake <fake@fake.com>" location=nowhere
  /system identity set name=mikrotik_hostname
  /tool e-mail set address=1.1.1.1 from=router@router.com password=smtppassword user=smtpuser
  ```

### /export verbose

  ```
  # jul/18/2020 16:09:36 by RouterOS 6.45.9
  # software id =
  #
  #
  #
  /interface bridge
  add ageing-time=5m arp=enabled arp-timeout=auto auto-mac=yes dhcp-snooping=no disabled=no fast-forward=yes forward-delay=15s \
      igmp-snooping=no max-message-age=20s mtu=auto name=bridge_local priority=0x8000 protocol-mode=rstp transmit-hold-count=6 \
      vlan-filtering=no
  /interface ethernet
  set [ find default-name=ether1 ] advertise=1000M-full,10000M-full arp=enabled arp-timeout=auto auto-negotiation=yes cable-settings=\
      default disable-running-check=no disabled=no full-duplex=yes loop-protect=default loop-protect-disable-time=5m \
      loop-protect-send-interval=5s mac-address=00:0C:29:9A:0B:43 mtu=1500 name=ether1 orig-mac-address=00:0C:29:9A:0B:43 speed=10Gbps
  set [ find default-name=ether2 ] advertise=1000M-full,10000M-full arp=enabled arp-timeout=auto auto-negotiation=yes cable-settings=\
      default disable-running-check=no disabled=no full-duplex=yes loop-protect=default loop-protect-disable-time=5m \
      loop-protect-send-interval=5s mac-address=00:0C:29:9A:0B:4D mtu=1500 name=ether2 orig-mac-address=00:0C:29:9A:0B:4D speed=10Gbps
  /queue interface
  set bridge_local queue=no-queue
  /interface list
  set [ find name=all ] comment="contains all interfaces" exclude="" include="" name=all
  set [ find name=none ] comment="contains no interfaces" exclude="" include="" name=none
  set [ find name=dynamic ] comment="contains dynamic interfaces" exclude="" include="" name=dynamic
  /interface lte apn
  set [ find default=yes ] add-default-route=yes apn=internet default-route-distance=2 name=default use-peer-dns=yes
  add add-default-route=yes apn=accesspointname default-route-distance=2 use-peer-dns=yes
  /interface wireless security-profiles
  set [ find default=yes ] authentication-types="" disable-pmkid=no eap-methods=passthrough group-ciphers=aes-ccm group-key-update=5m \
      interim-update=0s management-protection=disabled management-protection-key="" mode=none mschapv2-password="" mschapv2-username=\
      "" name=default radius-called-format=mac:ssid radius-eap-accounting=no radius-mac-accounting=no radius-mac-authentication=no \
      radius-mac-caching=disabled radius-mac-format=XX:XX:XX:XX:XX:XX radius-mac-mode=as-username static-algo-0=none static-algo-1=\
      none static-algo-2=none static-algo-3=none static-key-0="" static-key-1="" static-key-2="" static-key-3="" \
      static-sta-private-algo=none static-sta-private-key="" static-transmit-key=key-0 supplicant-identity=MikroTik tls-certificate=\
      none tls-mode=no-certificates unicast-ciphers=aes-ccm wpa-pre-shared-key="" wpa2-pre-shared-key=""
  add authentication-types="" disable-pmkid=no eap-methods=passthrough group-ciphers=aes-ccm group-key-update=5m interim-update=0s \
      management-protection=disabled management-protection-key="" mode=none mschapv2-password="" mschapv2-username="" name=openwifi \
      radius-called-format=mac:ssid radius-eap-accounting=no radius-mac-accounting=no radius-mac-authentication=no radius-mac-caching=\
      disabled radius-mac-format=XX:XX:XX:XX:XX:XX radius-mac-mode=as-username static-algo-0=none static-algo-1=none static-algo-2=\
      none static-algo-3=none static-key-0="" static-key-1="" static-key-2="" static-key-3="" static-sta-private-algo=none \
      static-sta-private-key="" static-transmit-key=key-0 supplicant-identity=MikroTik tls-certificate=none tls-mode=no-certificates \
      unicast-ciphers=aes-ccm wpa-pre-shared-key="" wpa2-pre-shared-key=""
  add authentication-types=wpa-psk disable-pmkid=no eap-methods=passthrough group-ciphers=aes-ccm group-key-update=5m interim-update=\
      0s management-protection=disabled management-protection-key="" mode=dynamic-keys mschapv2-password="" mschapv2-username="" name=\
      wpawifi radius-called-format=mac:ssid radius-eap-accounting=no radius-mac-accounting=no radius-mac-authentication=no \
      radius-mac-caching=disabled radius-mac-format=XX:XX:XX:XX:XX:XX radius-mac-mode=as-username static-algo-0=none static-algo-1=\
      none static-algo-2=none static-algo-3=none static-key-0="" static-key-1="" static-key-2="" static-key-3="" \
      static-sta-private-algo=none static-sta-private-key="" static-transmit-key=key-0 supplicant-identity=MikroTik tls-certificate=\
      none tls-mode=no-certificates unicast-ciphers=aes-ccm wpa-pre-shared-key=presharedkey wpa2-pre-shared-key=""
  add authentication-types=wpa2-psk disable-pmkid=no eap-methods=passthrough group-ciphers=aes-ccm group-key-update=5m interim-update=\
      0s management-protection=disabled management-protection-key="" mode=dynamic-keys mschapv2-password="" mschapv2-username="" name=\
      wpa2wifi radius-called-format=mac:ssid radius-eap-accounting=no radius-mac-accounting=no radius-mac-authentication=no \
      radius-mac-caching=disabled radius-mac-format=XX:XX:XX:XX:XX:XX radius-mac-mode=as-username static-algo-0=none static-algo-1=\
      none static-algo-2=none static-algo-3=none static-key-0="" static-key-1="" static-key-2="" static-key-3="" \
      static-sta-private-algo=none static-sta-private-key="" static-transmit-key=key-0 supplicant-identity=MikroTik tls-certificate=\
      none tls-mode=no-certificates unicast-ciphers=aes-ccm wpa-pre-shared-key="" wpa2-pre-shared-key=presharedkey
  add authentication-types=wpa2-eap disable-pmkid=no eap-methods=passthrough group-ciphers=aes-ccm group-key-update=5m interim-update=\
      0s management-protection=disabled management-protection-key="" mode=dynamic-keys mschapv2-password=password mschapv2-username=\
      username name=wpaeapwifi radius-called-format=mac:ssid radius-eap-accounting=no radius-mac-accounting=no \
      radius-mac-authentication=no radius-mac-caching=disabled radius-mac-format=XX:XX:XX:XX:XX:XX radius-mac-mode=as-username \
      static-algo-0=none static-algo-1=none static-algo-2=none static-algo-3=none static-key-0="" static-key-1="" static-key-2="" \
      static-key-3="" static-sta-private-algo=none static-sta-private-key="" static-transmit-key=key-0 supplicant-identity=MikroTik \
      tls-certificate=none tls-mode=no-certificates unicast-ciphers=aes-ccm wpa-pre-shared-key="" wpa2-pre-shared-key=""
  add authentication-types="" disable-pmkid=no eap-methods=passthrough group-ciphers=aes-ccm group-key-update=5m interim-update=0s \
      management-protection=disabled management-protection-key="" mode=static-keys-required mschapv2-password="" mschapv2-username="" \
      name=wepwifi radius-called-format=mac:ssid radius-eap-accounting=no radius-mac-accounting=no radius-mac-authentication=no \
      radius-mac-caching=disabled radius-mac-format=XX:XX:XX:XX:XX:XX radius-mac-mode=as-username static-algo-0=none static-algo-1=\
      none static-algo-2=none static-algo-3=none static-key-0=0123456789 static-key-1=0987654321 static-key-2=1234509876 static-key-3=\
      0192837645 static-sta-private-algo=none static-sta-private-key="" static-transmit-key=key-0 supplicant-identity=MikroTik \
      tls-certificate=none tls-mode=no-certificates unicast-ciphers=aes-ccm wpa-pre-shared-key="" wpa2-pre-shared-key=""
  add authentication-types="" disable-pmkid=no eap-methods=passthrough group-ciphers=aes-ccm group-key-update=5m interim-update=0s \
      management-protection=disabled management-protection-key="" mode=static-keys-required mschapv2-password="" mschapv2-username="" \
      name=wep1wifi radius-called-format=mac:ssid radius-eap-accounting=no radius-mac-accounting=no radius-mac-authentication=no \
      radius-mac-caching=disabled radius-mac-format=XX:XX:XX:XX:XX:XX radius-mac-mode=as-username static-algo-0=none static-algo-1=\
      none static-algo-2=none static-algo-3=none static-key-0=1111111111 static-key-1="" static-key-2="" static-key-3="" \
      static-sta-private-algo=none static-sta-private-key="" static-transmit-key=key-0 supplicant-identity=MikroTik tls-certificate=\
      none tls-mode=no-certificates unicast-ciphers=aes-ccm wpa-pre-shared-key="" wpa2-pre-shared-key=""
  /ip dhcp-client option
  set clientid_duid code=61 name=clientid_duid value="0xff\$(CLIENT_DUID)"
  set clientid code=61 name=clientid value="0x01\$(CLIENT_MAC)"
  set hostname code=12 name=hostname value="\$(HOSTNAME)"
  /ip hotspot profile
  set [ find default=yes ] dns-name="" hotspot-address=0.0.0.0 html-directory=hotspot html-directory-override="" http-cookie-lifetime=\
      3d http-proxy=0.0.0.0:0 login-by=cookie,http-chap name=default rate-limit="" smtp-server=0.0.0.0 split-user-domain=no \
      use-radius=no
  /ip hotspot user profile
  set [ find default=yes ] add-mac-cookie=yes address-list="" idle-timeout=none !insert-queue-before keepalive-timeout=2m \
      mac-cookie-timeout=3d name=default !parent-queue !queue-type shared-users=1 status-autorefresh=1m transparent-proxy=no
  /ip ipsec mode-config
  set [ find default=yes ] name=request-only responder=no
  /ip ipsec policy group
  set [ find default=yes ] name=default
  /ip ipsec profile
  set [ find default=yes ] dh-group=modp2048,modp1024 dpd-interval=2m dpd-maximum-failures=5 enc-algorithm=aes-128,3des \
      hash-algorithm=sha1 lifetime=1d name=default nat-traversal=yes proposal-check=obey
  /ip ipsec proposal
  set [ find default=yes ] auth-algorithms=sha1 disabled=no enc-algorithms=aes-256-cbc,aes-192-cbc,aes-128-cbc lifetime=30m name=\
      default pfs-group=modp1024
  /port
  set 0 baud-rate=9600 data-bits=8 flow-control=none name=serial0 parity=none stop-bits=1
  set 1 baud-rate=9600 data-bits=8 flow-control=none name=serial1 parity=none stop-bits=1
  /ppp profile
  set *0 address-list="" !bridge !bridge-horizon !bridge-path-cost !bridge-port-priority change-tcp-mss=yes !dns-server !idle-timeout \
      !incoming-filter !insert-queue-before !interface-list !local-address name=default on-down="" on-up="" only-one=default \
      !outgoing-filter !parent-queue !queue-type !rate-limit !remote-address !session-timeout use-compression=default use-encryption=\
      default use-mpls=default use-upnp=default !wins-server
  add address-list="" bridge=bridge_local !bridge-horizon !bridge-path-cost !bridge-port-priority change-tcp-mss=default !dns-server \
      !idle-timeout !incoming-filter !insert-queue-before !interface-list !local-address name=ppp_bridge on-down="" on-up="" only-one=\
      default !outgoing-filter !parent-queue !queue-type !rate-limit !remote-address !session-timeout use-compression=default \
      use-encryption=yes use-mpls=default use-upnp=default !wins-server
  set *FFFFFFFE address-list="" !bridge !bridge-horizon !bridge-path-cost !bridge-port-priority change-tcp-mss=yes !dns-server \
      !idle-timeout !incoming-filter !insert-queue-before !interface-list !local-address name=default-encryption on-down="" on-up="" \
      only-one=default !outgoing-filter !parent-queue !queue-type !rate-limit !remote-address !session-timeout use-compression=default \
      use-encryption=yes use-mpls=default use-upnp=default !wins-server
  /interface ovpn-client
  add add-default-route=no auth=sha1 certificate=none cipher=blowfish128 connect-to=10.99.99.98 disabled=no mac-address=\
      FE:45:B0:31:4A:34 max-mtu=1500 mode=ip name=ovpn-out1 password=password port=1194 profile=default user=user \
      verify-server-certificate=no
  add add-default-route=no auth=sha1 certificate=none cipher=blowfish128 connect-to=10.99.99.98 disabled=no mac-address=\
      FE:45:B0:31:4A:34 max-mtu=1500 mode=ip name=ovpn-out2 password=password port=1194 profile=default user=user \
      verify-server-certificate=no
  add add-default-route=no auth=sha1 certificate=none cipher=blowfish128 connect-to=10.99.99.98 disabled=yes mac-address=\
      FE:45:B0:31:4A:34 max-mtu=1500 mode=ip name=ovpn-out3 password=password port=1194 profile=default user=user \
      verify-server-certificate=no
  add add-default-route=no auth=sha1 certificate=none cipher=blowfish128 connect-to=10.99.99.98 disabled=no mac-address=\
      FE:45:B0:31:4A:34 max-mtu=1500 mode=ip name=ovpn-out4 password=password port=1194 profile=default user=user \
      verify-server-certificate=no
  /interface pppoe-client
  # Client is on slave interface
  add ac-name="" add-default-route=no allow=pap,chap,mschap1,mschap2 dial-on-demand=no disabled=no interface=ether2 keepalive-timeout=\
      10 max-mru=auto max-mtu=auto mrru=disabled name=pppoe-user password=password profile=default service-name=internet use-peer-dns=\
      no user=user
  /interface l2tp-client
  add add-default-route=no allow=pap,chap,mschap1,mschap2 allow-fast-path=no connect-to=10.99.99.99 dial-on-demand=no disabled=yes \
      ipsec-secret="" keepalive-timeout=60 max-mru=1450 max-mtu=1450 mrru=disabled name=l2tp-hm password=123 profile=\
      default-encryption use-ipsec=no user=l2tp-hm
  /interface pptp-client
  add add-default-route=no allow=pap,chap,mschap1,mschap2 connect-to=10.99.99.99 dial-on-demand=no disabled=no keepalive-timeout=60 \
      max-mru=1450 max-mtu=1450 mrru=disabled name=pptp-hm password=123 profile=default-encryption user=pptp-hm
  /queue interface
  set l2tp-hm queue=no-queue
  # Client is on slave interface
  set pppoe-user queue=no-queue
  set pptp-hm queue=no-queue
  /queue type
  set 0 kind=pfifo name=default pfifo-limit=50
  set 1 kind=pfifo name=ethernet-default pfifo-limit=50
  set 2 kind=sfq name=wireless-default sfq-allot=1514 sfq-perturb=5
  set 3 kind=red name=synchronous-default red-avg-packet=1000 red-burst=20 red-limit=60 red-max-threshold=50 red-min-threshold=10
  set 4 kind=sfq name=hotspot-default sfq-allot=1514 sfq-perturb=5
  set 5 kind=pcq name=pcq-upload-default pcq-burst-rate=0 pcq-burst-threshold=0 pcq-burst-time=10s pcq-classifier=src-address \
      pcq-dst-address-mask=32 pcq-dst-address6-mask=128 pcq-limit=50KiB pcq-rate=0 pcq-src-address-mask=32 pcq-src-address6-mask=128 \
      pcq-total-limit=2000KiB
  set 6 kind=pcq name=pcq-download-default pcq-burst-rate=0 pcq-burst-threshold=0 pcq-burst-time=10s pcq-classifier=dst-address \
      pcq-dst-address-mask=32 pcq-dst-address6-mask=128 pcq-limit=50KiB pcq-rate=0 pcq-src-address-mask=32 pcq-src-address6-mask=128 \
      pcq-total-limit=2000KiB
  set 7 kind=none name=only-hardware-queue
  set 8 kind=mq-pfifo mq-pfifo-limit=50 name=multi-queue-ethernet-default
  set 9 kind=pfifo name=default-small pfifo-limit=10
  /queue interface
  set ether1 queue=only-hardware-queue
  set ether2 queue=only-hardware-queue
  set ovpn-out1 queue=only-hardware-queue
  set ovpn-out2 queue=only-hardware-queue
  set ovpn-out3 queue=only-hardware-queue
  set ovpn-out4 queue=only-hardware-queue
  /routing bgp instance
  set default as=65530 client-to-client-reflection=yes !cluster-id !confederation disabled=no ignore-as-path-len=no name=default \
      out-filter="" redistribute-connected=no redistribute-ospf=no redistribute-other-bgp=no redistribute-rip=no redistribute-static=\
      no router-id=0.0.0.0 routing-table=""
  /routing ospf instance
  set [ find default=yes ] disabled=no distribute-default=never !domain-id !domain-tag in-filter=ospf-in metric-bgp=auto \
      metric-connected=20 metric-default=1 metric-other-ospf=auto metric-rip=20 metric-static=20 !mpls-te-area !mpls-te-router-id \
      name=default out-filter=ospf-out redistribute-bgp=no redistribute-connected=no redistribute-other-ospf=no redistribute-rip=no \
      redistribute-static=no router-id=0.0.0.0 !routing-table !use-dn
  /routing ospf area
  set [ find default=yes ] area-id=0.0.0.0 disabled=no instance=default name=backbone type=default
  /snmp community
  set [ find default=yes ] addresses=::/0 authentication-password="" authentication-protocol=MD5 encryption-password="" \
      encryption-protocol=DES name=public read-access=yes security=none write-access=no
  add addresses=::/0 authentication-password=write authentication-protocol=MD5 encryption-password="" encryption-protocol=DES name=\
      write read-access=yes security=none write-access=yes
  add addresses=::/0 authentication-password=0123456789 authentication-protocol=SHA1 encryption-password=9876543210 \
      encryption-protocol=AES name=v3 read-access=yes security=none write-access=no
  /system logging action
  set 0 memory-lines=1000 memory-stop-on-full=no name=memory target=memory
  set 1 disk-file-count=2 disk-file-name=log disk-lines-per-file=1000 disk-stop-on-full=no name=disk target=disk
  set 2 name=echo remember=yes target=echo
  set 3 bsd-syslog=no name=remote remote=0.0.0.0 remote-port=514 src-address=0.0.0.0 syslog-facility=daemon syslog-severity=auto \
      syslog-time-format=bsd-syslog target=remote
  /user group
  set read name=read policy=\
      local,telnet,ssh,reboot,read,test,winbox,password,web,sniff,sensitive,api,romon,tikapp,!ftp,!write,!policy,!dude skin=default
  set write name=write policy=\
      local,telnet,ssh,reboot,read,write,test,winbox,password,web,sniff,sensitive,api,romon,tikapp,!ftp,!policy,!dude skin=default
  set full name=full policy=\
      local,telnet,ssh,ftp,reboot,read,write,policy,test,winbox,password,web,sniff,sensitive,api,romon,dude,tikapp skin=default
  /caps-man aaa
  set called-format=mac:ssid interim-update=disabled mac-caching=disabled mac-format=XX:XX:XX:XX:XX:XX mac-mode=as-username
  /caps-man manager
  set ca-certificate=none certificate=none enabled=no package-path="" require-peer-certificate=no upgrade-policy=none
  /caps-man manager interface
  set [ find default=yes ] disabled=no forbid=no interface=all
  /certificate settings
  set crl-download=yes crl-store=ram crl-use=yes
  /dude
  set data-directory=dude enabled=no
  /interface bridge port
  add auto-isolate=no bpdu-guard=no bridge=bridge_local broadcast-flood=yes disabled=no edge=auto fast-leave=no frame-types=admit-all \
      horizon=none hw=yes ingress-filtering=no interface=ether2 internal-path-cost=10 learn=auto multicast-router=temporary-query \
      path-cost=10 point-to-point=auto priority=0x80 pvid=1 restricted-role=no restricted-tcn=no tag-stacking=no trusted=no \
      unknown-multicast-flood=yes unknown-unicast-flood=yes
  /interface bridge settings
  set allow-fast-path=yes use-ip-firewall=no use-ip-firewall-for-pppoe=no use-ip-firewall-for-vlan=no
  /ip firewall connection tracking
  set enabled=auto generic-timeout=10m icmp-timeout=10s loose-tcp-tracking=yes tcp-close-timeout=10s tcp-close-wait-timeout=10s \
      tcp-established-timeout=1d tcp-fin-wait-timeout=10s tcp-last-ack-timeout=10s tcp-max-retrans-timeout=5m \
      tcp-syn-received-timeout=5s tcp-syn-sent-timeout=5s tcp-time-wait-timeout=10s tcp-unacked-timeout=5m udp-stream-timeout=3m \
      udp-timeout=10s
  /ip neighbor discovery-settings
  set discover-interface-list=!dynamic
  /ip settings
  set accept-redirects=no accept-source-route=no allow-fast-path=yes arp-timeout=30s icmp-rate-limit=10 icmp-rate-mask=0x1818 \
      ip-forward=yes max-neighbor-entries=8192 route-cache=yes rp-filter=no secure-redirects=yes send-redirects=yes tcp-syncookies=no
  /interface detect-internet
  set detect-interface-list=none internet-interface-list=none lan-interface-list=none wan-interface-list=none
  /interface l2tp-server server
  set allow-fast-path=no authentication=pap,chap,mschap1,mschap2 caller-id-type=ip-address default-profile=default-encryption enabled=\
      no ipsec-secret="" keepalive-timeout=30 max-mru=1450 max-mtu=1450 max-sessions=unlimited mrru=disabled one-session-per-host=no \
      use-ipsec=no
  /interface ovpn-server server
  set auth=sha1,md5 cipher=blowfish128,aes128 default-profile=default enabled=no keepalive-timeout=60 mac-address=FE:73:1F:69:35:EC \
      max-mtu=1500 mode=ip netmask=24 port=1194 require-client-certificate=no
  /interface pptp-server server
  set authentication=mschap1,mschap2 default-profile=default-encryption enabled=no keepalive-timeout=30 max-mru=1450 max-mtu=1450 \
      mrru=disabled
  /interface sstp-server server
  set authentication=pap,chap,mschap1,mschap2 certificate=none default-profile=default enabled=no force-aes=no keepalive-timeout=60 \
      max-mru=1500 max-mtu=1500 mrru=disabled pfs=no port=443 tls-version=any verify-client-certificate=no
  /interface wireless align
  set active-mode=yes audio-max=-20 audio-min=-100 audio-monitor=00:00:00:00:00:00 filter-mac=00:00:00:00:00:00 frame-size=300 \
      frames-per-second=25 receive-all=no ssid-all=no
  /interface wireless cap
  set bridge=none caps-man-addresses="" caps-man-certificate-common-names="" caps-man-names="" certificate=none discovery-interfaces=\
      "" enabled=no interfaces="" lock-to-caps-man=no static-virtual=no
  /interface wireless sniffer
  set channel-time=200ms file-limit=10 file-name="" memory-limit=10 multiple-channels=no only-headers=no receive-errors=no \
      streaming-enabled=no streaming-max-rate=0 streaming-server=0.0.0.0
  /interface wireless snooper
  set channel-time=200ms multiple-channels=yes receive-errors=no
  /ip accounting
  set account-local-traffic=no enabled=no threshold=256
  /ip accounting web-access
  set accessible-via-web=no address=0.0.0.0/0
  /ip cloud
  set ddns-enabled=no ddns-update-interval=none update-time=no
  /ip cloud advanced
  set use-local-address=no
  /ip dhcp-client
  add add-default-route=yes default-route-distance=1 dhcp-options=hostname,clientid disabled=no interface=ether1 use-peer-dns=yes \
      use-peer-ntp=yes
  /ip dhcp-server config
  set accounting=yes interim-update=0s store-leases-disk=5m
  /ip dns
  set allow-remote-requests=no cache-max-ttl=1w cache-size=2048KiB max-concurrent-queries=100 max-concurrent-tcp-sessions=20 \
      max-udp-packet-size=4096 query-server-timeout=2s query-total-timeout=10s servers=""
  /ip firewall service-port
  set ftp disabled=no ports=21
  set tftp disabled=no ports=69
  set irc disabled=no ports=6667
  set h323 disabled=no
  set sip disabled=no ports=5060,5061 sip-direct-media=yes sip-timeout=1h
  set pptp disabled=no
  set udplite disabled=no
  set dccp disabled=no
  set sctp disabled=no
  /ip hotspot service-port
  set ftp disabled=no ports=21
  /ip hotspot user
  set [ find default=yes ] comment="counters and limits for trial users" disabled=no name=default-trial
  /ip ipsec policy
  set 0 disabled=no dst-address=::/0 group=default proposal=default protocol=all src-address=::/0 template=yes
  /ip ipsec settings
  set accounting=yes interim-update=0s xauth-use-radius=no
  /ip proxy
  set always-from-cache=no anonymous=no cache-administrator=webmaster cache-hit-dscp=4 cache-on-disk=no cache-path=web-proxy enabled=\
      no max-cache-object-size=2048KiB max-cache-size=unlimited max-client-connections=600 max-fresh-time=3d max-server-connections=\
      600 parent-proxy=:: parent-proxy-port=0 port=8080 serialize-connections=no src-address=::
  /ip service
  set telnet address="" disabled=no port=23
  set ftp address="" disabled=no port=21
  set www address="" disabled=no port=80
  set ssh address="" disabled=no port=22
  set www-ssl address="" certificate=none disabled=yes port=443
  set api address="" disabled=no port=8728
  set winbox address="" disabled=no port=8291
  set api-ssl address="" certificate=none disabled=no port=8729
  /ip smb
  set allow-guests=yes comment=MikrotikSMB domain=MSHOME enabled=no interfaces=all
  /ip smb shares
  set [ find default=yes ] comment="default share" directory=/pub disabled=no max-sessions=10 name=pub
  /ip smb users
  set [ find default=yes ] disabled=no name=guest password="" read-only=yes
  add disabled=no name=mtuser password=mtpasswd read-only=no
  add disabled=yes name=disableduser password=disabledpasswd read-only=yes
  /ip socks
  set connection-idle-timeout=2m enabled=no max-connections=200 port=1080
  /ip ssh
  set allow-none-crypto=no always-allow-password-login=no forwarding-enabled=no host-key-size=2048 strong-crypto=no
  /ip tftp settings
  set max-block-size=4096
  /ip traffic-flow
  set active-flow-timeout=30m cache-entries=16k enabled=no inactive-flow-timeout=15s interfaces=all
  /ip traffic-flow ipfix
  set bytes=yes dst-address=yes dst-address-mask=yes dst-mac-address=yes dst-port=yes first-forwarded=yes gateway=yes icmp-code=yes \
      icmp-type=yes igmp-type=yes in-interface=yes ip-header-length=yes ip-total-length=yes ipv6-flow-label=yes is-multicast=yes \
      last-forwarded=yes nat-dst-address=yes nat-dst-port=yes nat-src-address=yes nat-src-port=yes out-interface=yes packets=yes \
      protocol=yes src-address=yes src-address-mask=yes src-mac-address=yes src-port=yes tcp-ack-num=yes tcp-flags=yes tcp-seq-num=yes \
      tcp-window-size=yes tos=yes ttl=yes udp-length=yes
  /ip upnp
  set allow-disable-external-interface=no enabled=no show-dummy-rule=yes
  /mpls
  set dynamic-label-range=16-1048575 propagate-ttl=yes
  /mpls interface
  set [ find default=yes ] disabled=no interface=all mpls-mtu=1508
  /mpls ldp
  set distribute-for-default-route=no enabled=no hop-limit=255 loop-detect=no lsr-id=0.0.0.0 path-vector-limit=255 transport-address=\
      0.0.0.0 use-explicit-null=no
  /port firmware
  set directory=firmware ignore-directip-modem=no
  /ppp aaa
  set accounting=yes interim-update=0s use-circuit-id-in-nas-port-id=no use-radius=no
  /ppp secret
  add caller-id="" disabled=no limit-bytes-in=0 limit-bytes-out=0 !local-address name=ppp1 password=password profile=ppp_bridge \
      !remote-address routes="" service=any
  /radius incoming
  set accept=no port=3799
  /routing bfd interface
  set [ find default=yes ] disabled=no interface=all interval=0.2s min-rx=0.2s multiplier=5
  /routing mme
  set bidirectional-timeout=2 gateway-class=none gateway-keepalive=1m gateway-selection=no-gateway origination-interval=5s \
      preferred-gateway=0.0.0.0 timeout=1m ttl=50
  /routing rip
  set distribute-default=never garbage-timer=2m metric-bgp=1 metric-connected=1 metric-default=1 metric-ospf=1 metric-static=1 \
      redistribute-bgp=no redistribute-connected=no redistribute-ospf=no redistribute-static=no routing-table=main timeout-timer=3m \
      update-timer=30s
  /snmp
  set contact="fake <fake@fake.com>" enabled=no engine-id="" location=nowhere trap-community=public trap-generators=temp-exception \
      trap-target="" trap-version=1
  /system clock
  set time-zone-autodetect=yes time-zone-name=manual
  /system clock manual
  set dst-delta=+00:00 dst-end="jan/01/1970 00:00:00" dst-start="jan/01/1970 00:00:00" time-zone=+00:00
  /system console
  set [ find port=serial0 ] channel=0 disabled=no port=serial0 term=vt102
  set [ find vcno=1 ] channel=0 disabled=no term=linux
  set [ find vcno=2 ] channel=0 disabled=no term=linux
  set [ find vcno=3 ] channel=0 disabled=no term=linux
  set [ find vcno=4 ] channel=0 disabled=no term=linux
  set [ find vcno=5 ] channel=0 disabled=no term=linux
  set [ find vcno=6 ] channel=0 disabled=no term=linux
  set [ find vcno=7 ] channel=0 disabled=no term=linux
  set [ find vcno=8 ] channel=0 disabled=no term=linux
  /system console screen
  set blank-interval=10min line-count=25
  /system hardware
  set multi-cpu=yes
  /system health
  set state-after-reboot=enabled
  /system identity
  set name=mikrotik_hostname
  /system leds settings
  set all-leds-off=never
  /system logging
  set 0 action=memory disabled=no prefix="" topics=info
  set 1 action=memory disabled=no prefix="" topics=error
  set 2 action=memory disabled=no prefix="" topics=warning
  set 3 action=echo disabled=no prefix="" topics=critical
  /system note
  set note="" show-at-login=yes
  /system ntp client
  set enabled=no primary-ntp=0.0.0.0 secondary-ntp=0.0.0.0 server-dns-names=""
  /system resource irq
  set 0 cpu=auto
  set 1 cpu=auto
  set 2 cpu=auto
  set 3 cpu=auto
  set 4 cpu=auto
  set 5 cpu=auto
  set 6 cpu=auto
  set 7 cpu=auto
  set 8 cpu=auto
  set 9 cpu=auto
  set 10 cpu=auto
  /system upgrade mirror
  set check-interval=1d enabled=no primary-server=0.0.0.0 secondary-server=0.0.0.0 user=""
  /system watchdog
  set auto-send-supout=no automatic-supout=yes ping-start-after-boot=5m ping-timeout=1m watch-address=none watchdog-timer=yes
  /tool bandwidth-server
  set allocate-udp-ports-from=2000 authenticate=yes enabled=yes max-sessions=100
  /tool e-mail
  set address=1.1.1.1 from=router@router.com password=smtppassword port=25 start-tls=no user=smtpuser
  /tool graphing
  set page-refresh=300 store-every=5min
  /tool mac-server
  set allowed-interface-list=all
  /tool mac-server mac-winbox
  set allowed-interface-list=all
  /tool mac-server ping
  set enabled=yes
  /tool romon
  set enabled=no id=00:00:00:00:00:00 secrets=""
  /tool romon port
  set [ find default=yes ] cost=100 disabled=no forbid=no interface=all secrets=""
  /tool sms
  set allowed-number="" auto-erase=no channel=0 port=none receive-enabled=no secret="" sim-pin=""
  /tool sniffer
  set file-limit=1000KiB file-name="" filter-cpu="" filter-direction=any filter-interface="" filter-ip-address="" filter-ip-protocol=\
      "" filter-ipv6-address="" filter-mac-address="" filter-mac-protocol="" filter-operator-between-entries=or filter-port="" \
      filter-stream=no memory-limit=100KiB memory-scroll=yes only-headers=no streaming-enabled=no streaming-server=0.0.0.0
  /tool traffic-generator
  set latency-distribution-max=100us measure-out-of-order=yes stats-samples-to-keep=100 test-id=0
  /user aaa
  set accounting=yes default-group=read exclude-groups="" interim-update=0s use-radius=no
  ```

### SwOS

  ```
  vlan.b:[],lacp.b:{mode:[0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00],sgrp:[0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00]},host.b:[],acl.b:[],snmp.b:{en:0x01,com:'7075626c6963',ci:'636f6e74616374696e666f',loc:'6c6f636174696f6e'},rstp.b:{ena:0x03ffffff},fwd.b:{fp1:0x03fffffe,fp2:0x03fffffd,fp3:0x03fffffb,fp4:0x03fffff7,fp5:0x03ffffef,fp6:0x03ffffdf,fp7:0x03ffffbf,fp8:0x03ffff7f,fp9:0x03fffeff,fp10:0x03fffdff,fp11:0x03fffbff,fp12:0x03fff7ff,fp13:0x03ffefff,fp14:0x03ffdfff,fp15:0x03ffbfff,fp16:0x03ff7fff,fp17:0x03feffff,fp18:0x03fdffff,fp19:0x03fbffff,fp20:0x03f7ffff,fp21:0x03efffff,fp22:0x03dfffff,fp23:0x03bfffff,fp24:0x037fffff,fp25:0x02ffffff,fp26:0x01ffffff,lck:0x00,lckf:0x00,imr:0x00,omr:0x00,mrto:0x01,vlan:[0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01],vlni:[0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00],dvid:[0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01],fvid:0x00,srt:[0x64,0x64,0x64,0x64,0x64,0x64,0x64,0x64,0x64,0x64,0x64,0x64,0x64,0x64,0x64,0x64,0x64,0x64,0x64,0x64,0x64,0x64,0x64,0x64,0x64,0x64],suni:0x00,fmc:0x03ffffff,ir:[0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00]},link.b:{en:0x03ffffff,blkp:0x00,an:0x03ffffff,dpxc:0x03ffffff,fctc:0x03ffffff,fctr:0x00,spdc:[0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00],cm:[0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00],qtyp:[0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00],nm:['506f727431','506f727432','506f727433','506f727434','506f727435','506f727436','506f727437','506f727438','506f727439','506f72743130','506f72743131','506f72743132','506f72743133','506f72743134','506f72743135','506f72743136','506f72743137','506f72743138','506f72743139','506f72743230','506f72743231','506f72743232','506f72743233','75706c696e6b','53465031','53465032']},sys.b:{id:'4d696b726f54696b2d637373333236',wdt:0x01,dsc:0x01,ivl:0x00,alla:0x00,allm:0x00,allp:0x03ffffff,avln:0x00,prio:0x8000,cost:0x00,igmp:0x00,ip:0x0158a8c0,iptp:0x02,dtrp:0x03ffffff,ainf:0x01,poe:0x00},.pwd.b:{pwd:'61646d696e'}
  ```


## Verification Steps

1. Have a Mikrotik configuration file
2. Start `msfconsole`
3. `use auxiliary/admin/networking/mikrotik_config`
4. `set RHOST x.x.x.x`
5. `set CONFIG /tmp/file.config`
6. `run`

## Options

### RHOST

Needed for setting services and items to.  This is relatively arbitrary.

### CONFIG

File path to the configuration file.

### ACTION

`ROUTEROS` for RouterOS config file, and `SWOS` for SwitchOS config file (usually SWB file extension). Default is `ROUTEROS`


## Scenarios

### RouterOS 6.45.9 /export verbose

```
resource (mikrotik_config.rb)> use auxiliary/admin/networking/mikrotik_config
resource (mikrotik_config.rb)> set rhost 1.1.1.1
rhost => 1.1.1.1
resource (mikrotik_config.rb)> set config /tmp/mikrotik.config
config => /tmp/mikrotik.config
resource (mikrotik_config.rb)> set verbose true
verbose => true
resource (mikrotik_config.rb)> run
[*] Running module against 1.1.1.1
[*] Importing config
[+] 1.1.1.1:22 OS: RouterOS 6.45.9
[+] 1.1.1.1:22 Wireless AP wpawifi with WPA password presharedkey
[+] 1.1.1.1:22 Wireless AP wpa2wifi with WPA2 password presharedkey
[+] 1.1.1.1:22 Wireless AP wpaeapwifi with WPA2-EAP username username password password
[+] 1.1.1.1:22 Wireless AP wepwifi with WEP password 0123456789 with WEP password 0987654321 with WEP password 1234509876 with WEP password 0192837645
[+] 1.1.1.1:22 Wireless AP wep1wifi with WEP password 1111111111
[+] 1.1.1.1:22 disabled Open VPN Client to 10.99.99.98 on mac FE:45:B0:31:4A:34 named ovpn-out1 with username user and password password
[+] 1.1.1.1:22 disabled Open VPN Client to 10.99.99.98 on mac FE:45:B0:31:4A:34 named ovpn-out2 with username user and password password
[+] 1.1.1.1:22 disabled Open VPN Client to 10.99.99.98 on mac FE:45:B0:31:4A:34 named ovpn-out3 with username user and password password
[+] 1.1.1.1:22 disabled Open VPN Client to 10.99.99.98 on mac FE:45:B0:31:4A:34 named ovpn-out4 with username user and password password
[+] 1.1.1.1:22  PPPoE Client on ether2 named pppoe-user and service name internet with username user and password password
[+] 1.1.1.1:22  L2TP Client to 10.99.99.99 named l2tp-hm with username l2tp-hm and password 123
[+] 1.1.1.1:22  PPTP Client to 10.99.99.99 named pptp-hm with username pptp-hm and password 123
[+] 1.1.1.1:22 SNMP community write with password write and write access
[+] 1.1.1.1:22 SNMP community v3 with password 0123456789(SHA1), encryption password 9876543210(AES) and write access
[+] 1.1.1.1:22  SMB Username mtuser and password mtpasswd
[+] 1.1.1.1:22 disabled SMB Username disableduser and password disabledpasswd with RO only access
[+] 1.1.1.1:22 disabled PPP tunnel bridging named ppp1 with profile name ppp_bridge and password password
[+] 1.1.1.1:22 SMTP Username smtpuser and password smtppassword for 1.1.1.1:25
[+] Config import successful
[*] Auxiliary module execution completed
```

### SwOS 2.12 from Mikrotik CSS326-24G-2S+RM

```
resource (mikrotik_config_sw.rb)> use auxiliary/admin/networking/mikrotik_config
resource (mikrotik_config_sw.rb)> set rhost 1.1.1.1
rhost => 1.1.1.1
resource (mikrotik_config_sw.rb)> set config /home/h00die/Downloads/backup(1).swb
config => /home/h00die/Downloads/backup(1).swb
resource (mikrotik_config_sw.rb)> set verbose true
verbose => true
resource (mikrotik_config_sw.rb)> set action SWOS
action => SWOS
resource (mikrotik_config_sw.rb)> run
[*] Running module against 1.1.1.1
[*] Importing config
[*] 1.1.1.1:22 IP Address: 192.168.88.1
[+] 1.1.1.1:22 Hostname: MikroTik-css326
[+] 1.1.1.1:22 Admin login password: admin
[+] 1.1.1.1:22 SNMP Community: public, contact: , location: 
[*] 1.1.1.1:22 Port 24 Named: uplink
[+] Config import successful
[*] Auxiliary module execution completed
```
