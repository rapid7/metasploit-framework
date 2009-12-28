# $Id: igrp.rb 14 2008-03-02 05:42:30Z warchild $
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
module L4
# Internet Gateway Routing Protocol: IGRP
#
# http://www.cisco.com/warp/public/103/5.html
#
# Every routing entry  has the following fields:
#   uchar number[3];       /* 3 significant octets of IP address */
#   uchar delay[3];        /* delay, in tens of microseconds */
#   uchar bandwidth[3];    /* bandwidth, in units of 1 Kbit/sec */
#   uchar mtu[2];          /* MTU, in octets */
#   uchar reliability;     /* percent packets successfully tx/rx */
#   uchar load;            /* percent of channel occupied */
#   uchar hopcount;        /* hop count */
class IGRP < RacketPart
  IGRP_UPDATE  = 1
  IGRP_REQUEST = 2

  # Version of the IGRP message contained in this packet.    
  # Defaults to 1.  Anything else is currently invalid
  unsigned :version, 4, { :default => 1 }
  # Type of the IGRP message contained in this packet.
  unsigned :opcode, 4 
  # Serial number which is incremented whenever the routing
  # table is updated.
  unsigned :edition, 8 
  # Autonomous system number
  unsigned :asystem, 16
  # Number of interior routes contained in this update message
  unsigned :ninterior, 16
  # Number of system routes contained in this update message
  unsigned :nsystem, 16
  # Number of exterior routes contained in this update message
  unsigned :nexterior, 16
  # Checksum (IP)
  unsigned :checksum, 16
  # Payload.  Generally unused.
  rest :payload

  def initialize(*args)
    @interior_routes = []
    @system_routes = []
    @exterior_routes = []
    super
  end

  # Add a system route to this IGRP packet
  def add_system(ip, delay, bw, mtu, rel, load, hop)
    @system_routes << add_entry(ip, delay, bw, mtu, rel, load, hop)
    self.nsystem += 1
  end

  # Add an interior route to this IGRP packet
  def add_interior(ip, delay, bw, mtu, rel, load, hop)
    @interior_routes << add_entry(ip, delay, bw, mtu, rel, load, hop)
    self.ninterior += 1
  end

  # Add an exterior route to this IGRP packet
  def add_exterior(ip, delay, bw, mtu, rel, load, hop)
    @exterior_routes << add_entry(ip, delay, bw, mtu, rel, load, hop)
    self.nexterior += 1
  end

  # Compute and set the checksum of this IGRP packet
  def checksum! 
    self.checksum = compute_checksum
  end

  # Is the checksum correct?
  def checksum?
    self.checksum == compute_checksum
  end

  # Fix everything up in preparation for sending.
  def fix!
    [@interior_routes, @system_routes, @exterior_routes].flatten.each do |r|
      self.payload += r
    end
    checksum!
  end

private

  def add_entry(ip, delay, bw, mtu, rel, load, hop)
    # tmp should be 12 bytes long
    tmp = ((((((((ip << 8*3) | delay) << 8*3) | bw) << 8*2) | mtu) << 8*1)| rel)
    # now split it up into 3, 4-byte chunks suitable for an 'N' pack
    tmp1 = (0xffffffff0000000000000000 & tmp) >> 8*8
    tmp2 = (0x00000000ffffffff00000000 & tmp) >> 8*4
    tmp3 = (0x0000000000000000ffffffff & tmp)
    [tmp1, tmp2, tmp3, load, hop].pack("NNNCC")
  end

  def compute_checksum
    tmp = []
    tmp << (self.version << 4 | self.opcode)
    tmp << self.edition
    tmp << self.asystem
    tmp << self.ninterior
    tmp << self.nsystem
    tmp << self.nexterior
    tmp << 0
    tmp << payload
    L3::Misc.checksum(tmp.pack("Cnnnnnna*"))
  end
end
end
end

# vim: set ts=2 et sw=2:
