# $Id: udp.rb 14 2008-03-02 05:42:30Z warchild $
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
# User Datagram Protocol: UDP
#
# RFC768 (http://www.faqs.org/rfcs/rfc768.html)
class UDP < RacketPart
  # Source Port
  unsigned :src_port, 16
  # Destination Port
  unsigned :dst_port, 16
  # Datagram Length
  unsigned :len, 16
  # Checksum
  unsigned :checksum, 16
  # Payload
  rest :payload
  
  # Check the checksum for this UDP datagram
  def checksum?(src_ip, dst_ip)
    self.checksum == 0 || (self.checksum == compute_checksum(src_ip, dst_ip))
  end

  # Compute and set the checksum for this UDP datagram
  def checksum!(src_ip, dst_ip)
    # set the checksum to 0 for usage in the pseudo header...
    self.checksum = 0
    self.checksum = compute_checksum(src_ip, dst_ip)
  end

  # Fix this packet up for proper sending.  Sets the length
  # and checksum properly.
  def fix!(src_ip, dst_ip)
    self.len = self.class.bit_length/8 + self.payload.length
    self.checksum!(src_ip, dst_ip)
  end

  def initialize(*args)
    super
    @autofix = false
  end 

private
  # Compute the checksum for this UDP datagram
  def compute_checksum(src_ip, dst_ip)
    # pseudo header used for checksum calculation as per RFC 768 
    pseudo = [L3::Misc.ipv42long(src_ip), L3::Misc.ipv42long(dst_ip), 17, self.payload.length + self.class.bit_length/8 ]
    header = [self.src_port, self.dst_port, self.payload.length + self.class.bit_length/8, 0, self.payload]
    L3::Misc.checksum((pseudo << header).flatten.pack("NNnnnnnna*"))
  end

end
end
end
# vim: set ts=2 et sw=2:
