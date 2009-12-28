# $Id: vlan.rb 14 2008-03-02 05:42:30Z warchild $
#
# Copyright (c) 2008, Jon Hart 
# All rights reserved.
# 
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#     * Redistributions of source code must retain the above copyright
#       notice, this list of conditions and the following disclaimer.
#     * Redistributions in binary form must reproduce the above copyright
#       notice, this list of conditions and the following disclaimer in the
#       documentation and/or other materials provided with the distribution.
#     * Neither the name of the <organization> nor the
#       names of its contributors may be used to endorse or promote products
#       derived from this software without specific prior written permission.
# 
# THIS SOFTWARE IS PROVIDED BY Jon Hart ``AS IS'' AND ANY
# EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL Jon Hart BE LIABLE FOR ANY
# DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
# (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
# ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
# SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#
module Racket
module L2
# IEEE 802.1Q VLAN tag (http://en.wikipedia.org/wiki/IEEE_802.1Q)
class VLAN < RacketPart
  ETHERTYPE_IPV4 = 0x0800
  ETHERTYPE_ARP = 0x0806
  ETHERTYPE_RARP = 0x8035
  ETHERTYPE_APPLETALK = 0x809b
  ETHERTYPE_AARP = 0x80f3
  ETHERTYPE_8021Q = 0x8100
  ETHERTYPE_IPX = 0x8137
  ETHERTYPE_NOVELL = 0x8138
  ETHERTYPE_IPV6 = 0x86DD
  ETHERTYPE_MPLS_UNICAST = 0x8847
  ETHERTYPE_MPLS_MULTICAST = 0x8848
  ETHERTYPE_PPPOE_DISCOVERY = 0x8863
  ETHERTYPE_PPPOE_SESSION = 0x8864
  ETHERTYPE_8021X = 0x888E
  ETHERTYPE_ATAOE = 0x88A2
  ETHERTYPE_8021AE = 0x88E5

  # Frame priority level
  unsigned :priority, 3
  # Canonical format indicator
  unsigned :cfi, 1
  # VLAN ID
  unsigned :id, 12
  # L3 protocol type.  Defaults to IPV4
  unsigned :type, 16, { :default => ETHERTYPE_IPV4 }
  rest :payload
end
end
end
# vim: set ts=2 et sw=2:
