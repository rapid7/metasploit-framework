# -*- coding: binary -*-

require 'packetfu'

# packetfu 2.0.0 (the latest release) ships a StructFu#typecast that recovers
# the setter it was called from by matching the caller backtrace against the
# MRI <= 3.3 format (`method='). Ruby 3.4 reformatted backtraces to the form
# 'Klass#method=', so the old pattern returns nil and every PacketFu field
# assignment, including the ones inside each packet's own initialize, raises
# "undefined method '[]' for nil". Grab the trailing setter name in a way
# that works on both formats until packetfu is fixed upstream. Safe on 3.2
# and 3.3 too; the captured name is identical there.
#
# This shim was first added inline in Msf::Exploit::Remote::Ipv6, where it
# only loaded for modules that mix the IPv6 helper in. Moving it next to the
# `require 'packetfu'` call so every entry point that pulls in packetfu
# (Msf::Exploit::Capture, Msf::Exploit::Remote::Ipv6, future callers) picks
# up the fix. Covers scanner/discovery/arp_sweep and the rest of the Capture
# mixin surface - see rapid7/metasploit-framework#21721.
module StructFu
  def typecast(val)
    name = caller(1..1).first[/([A-Za-z0-9_]+)=['`]/, 1]
    self[name.to_sym].read val
  end
end
