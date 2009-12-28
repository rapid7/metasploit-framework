# $Id: cdp.rb 14 2008-03-02 05:42:30Z warchild $
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
# CDP -- Cisco Discovery Protocol
# http://www.cisco.biz/univercd/cc/td/doc/product/lan/trsrb/frames.htm#xtocid12
class CDP < RacketPart
  # CDP Version (generally 1)
  unsigned :version, 8, { :default => 1 }
  # Time-to-live of the data in this message
  unsigned :ttl, 8
  # Checksum
  unsigned :checksum, 16
  # Payload of this CDP message.  Generally untouched.
  rest :payload
  

  def initialize(*args)
    super(*args)
  end

  # Add a new field to this CDP message.
  def add_field(type, value) 
    t = Racket::Misc::TLV.new(2,2)
    t.type = type
    t.value = value
    t.length = 4 + value.length
    self.payload += t.encode   
  end 

  # Check the checksum for this IP datagram
  def checksum? 
    self.checksum == compute_checksum
  end 

  # Compute and set the checksum for this IP datagram
  def checksum! 
    self.checksum = compute_checksum
  end 
  
  # Fix this CDP message up for sending.
  def fix! 
    self.checksum!
  end 

private

  # Compute the checksum for this IP datagram
  def compute_checksum
    pseudo = []
    pseudo << ((self.version << 8) | self.ttl)
    pseudo << 0
    pseudo << self.payload
    L3::Misc.checksum(pseudo.pack("nna*"))
  end 

end
end
end
# vim: set ts=2 et sw=2:
