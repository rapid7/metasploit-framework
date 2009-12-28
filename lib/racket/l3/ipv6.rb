# $Id: ipv6.rb 14 2008-03-02 05:42:30Z warchild $
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
# Internet Protocol Version 6 (IPV6)
# RFC2460
class IPv6 < RacketPart
  # IP Version (defaults to 6)
  unsigned :version, 4, { :default => 6 }
  # Traffic class
  unsigned :tclass, 8
  # Flow label
  unsigned :flow, 20
  # Payload length
  unsigned :plen, 16
  # Next header type
  unsigned :nhead, 8
  # Hop limit
  unsigned :ttl, 8, { :default => 200 }
  # Source IP address.  Must be passed as an integer
  unsigned :src_ip, 128
  # Destination IP address.  Must be passed as an integer
  unsigned :dst_ip, 128
  # Payload
  rest :payload

  def initialize(*args)
    @headers = []
    super
    @autofix = true
  end

  # Adjust plen to match the payload
  def fix!
    self.plen = self.payload.length
  end

end
end
end
# vim: set ts=2 et sw=2:
