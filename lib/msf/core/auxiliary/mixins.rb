# -*- coding: binary -*-

#
# Auxiliary mixins
#
require 'msf/core/auxiliary/auth_brute'
require 'msf/core/auxiliary/crand'
require 'msf/core/auxiliary/dos'
require 'msf/core/auxiliary/drdos'
require 'msf/core/auxiliary/fuzzer'
require 'msf/core/auxiliary/report'
require 'msf/core/auxiliary/scanner'
require 'msf/core/auxiliary/udp_scanner'
require 'msf/core/auxiliary/timed'
require 'msf/core/auxiliary/wmapmodule'
require 'msf/core/auxiliary/web'
require 'msf/core/auxiliary/crawler'

require 'msf/core/auxiliary/commandshell'
require 'msf/core/auxiliary/login'
require 'msf/core/auxiliary/rservices'
require 'msf/core/auxiliary/cisco'
require 'msf/core/auxiliary/juniper'
require 'msf/core/auxiliary/brocade'
require 'msf/core/auxiliary/kademlia'
require 'msf/core/auxiliary/llmnr'
require 'msf/core/auxiliary/mdns'
require 'msf/core/auxiliary/mqtt'
require 'msf/core/auxiliary/nmap'
require 'msf/core/auxiliary/natpmp'
require 'msf/core/auxiliary/iax2'
require 'msf/core/auxiliary/ntp'
require 'msf/core/auxiliary/pii'
require 'msf/core/auxiliary/redis'
require 'msf/core/auxiliary/sms'
require 'msf/core/auxiliary/mms'

#
# Custom HTTP modules
#
require 'msf/core/auxiliary/cnpilot'
require 'msf/core/auxiliary/epmp'
require 'msf/core/auxiliary/etcd'
