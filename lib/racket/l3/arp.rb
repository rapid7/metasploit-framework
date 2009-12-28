# $Id: arp.rb 14 2008-03-02 05:42:30Z warchild $
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
module L3
# Address Resolution Protocol: ARP
# RFC826 (http://www.faqs.org/rfcs/rfc826.html)
class ARP < RacketPart
  ARPOP_REQUEST = 0x0001
  ARPOP_REPLY = 0x0002
  
  # Hardware type 
  unsigned :htype, 16, { :default => 1 }
  # Protocol type 
  unsigned :ptype, 16, { :default => 0x0800 }
  # Hardware address length
  unsigned :hlen, 8, { :default => 6 }
  # Protocol address length
  unsigned :plen, 8, { :default => 4 }
  # Opcode
  unsigned :opcode, 16
  # XXX: This is not entirely correct.  Technically, sha, spa, tha and
  # tpa should be sized according to hlen and plen.  This is good enough for
  # Ethernet and IPv4.

  # Source hardware address
  hex_octets :sha, 48
  # Source protocol address
  octets :spa, 32
  # Target hardware address
  hex_octets :tha, 48
  # Target protcol address
  octets :tpa, 32
  # Payload
  rest :payload
end
end
end
# vim: set ts=2 et sw=2:
