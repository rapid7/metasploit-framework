# $Id: ipv4.rb 14 2008-03-02 05:42:30Z warchild $
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
# Internet Protcol Version 4 (IPV4)
#
# RFC791 (http://www.ietf.org/rfc/rfc791.txt)
module Racket
class IPv4 < RacketPart
  # Version (defaults to 4)
  unsigned :version, 4, { :default => 4 }
  # Header length in multiples of 4 octets (defaults to 5)
  unsigned :hlen, 4, { :default => 5 }
  # Type of Service
  unsigned :tos, 8
  # Datagram length
  unsigned :len, 16
  # Identifier
  unsigned :id, 16
  # Flags
  unsigned :flags, 3
  # Fragmentation offset
  unsigned :foffset, 13
  # Time-to-live
  unsigned :ttl, 8
  # Protocol
  unsigned :protocol, 8
  # Checksum
  unsigned :csum, 16, "Checksum"
  # Source IP address
  octets :src_ip, 32
  # Destination IP address
  octets :dst_ip, 32
  # Payload
  rest :payload

  def initialize(*args)
    @options = []
    super
  end

  # Add an IPv4 option to this IPv4 object.
  # All rejiggering will happen when the call to fix! 
  # happens automagically
  def add_option(number, value)
    t = TLV.new(1,1)
    t.type = number
    t.value = value
    t.length = value.length + 2
    @options << t.encode
  end

  # Check the checksum for this IP datagram
  def checksum?
    self.csum == compute_checksum
  end

  # Compute and set the checksum for this IP datagram
  def checksum!
    self.csum = compute_checksum
  end

  # Perform all the niceties necessary prior to sending
  # this IP datagram out.  Append the options, update len and hlen,
  # and fix the checksum.
  def fix!
    newpayload = @options.join
    
    # pad to a multiple of 32 bits
    if (newpayload.length % 4 != 0) 
      # fill the beginning as needed with NOPs
      while (newpayload.length % 4 != 3)
        newpayload = "\x01#{newpayload}"
      end

      # make sure the last byte is an EOL
      if (newpayload.length % 4 == 3)
        newpayload += "\x00"
      end
    end

    self.payload = newpayload + self.payload
    self.hlen += newpayload.length/4
    self.len = self.payload.length + self.class.bit_length/8
    self.checksum!
  end

 
private
  # Compute the checksum for this IP datagram
  def compute_checksum
    pseudo = []
    pseudo << ((((self.version << 4) | self.hlen) << 8) | self.tos)
    pseudo << self.len
    pseudo << self.id
    pseudo << ((self.flags << 13) | self.foffset)
    pseudo << ((self.ttl << 8) | self.protocol)
    pseudo << 0 
    pseudo << L3::Misc.ipv42long(self.src_ip)
    pseudo << L3::Misc.ipv42long(self.dst_ip)
    L3::Misc.checksum(pseudo.pack("nnnnnnNN"))
  end
end
end
# vim: set ts=2 et sw=2:
