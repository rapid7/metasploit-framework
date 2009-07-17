# $Id: icmp.rb 14 2008-03-02 05:42:30Z warchild $
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
# Internet Control Message Protcol.  
#
# RFC792 (http://www.faqs.org/rfcs/rfc792.html)
module Racket
class ICMP < RacketPart
  ICMP_TYPE_ECHO_REPLY = 0
  ICMP_TYPE_DESTINATION_UNREACHABLE = 3
  ICMP_TYPE_SOURCE_QUENCH = 4
  ICMP_TYPE_REDIRECT = 5
  ICMP_TYPE_ECHO_REQUEST = 8 
  ICMP_TYPE_MOBILE_IP_ADVERTISEMENT = 9
  ICMP_TYPE_ROUTER_SOLICITATION = 10
  ICMP_TYPE_TIME_EXCEEDED = 11
  ICMP_TYPE_PARAMETER_PROBLEM = 12
  ICMP_TYPE_TIMESTAMP_REQUEST = 13
  ICMP_TYPE_TIMESTAMP_REPLY = 14
  ICMP_TYPE_INFO_REQUEST = 15
  ICMP_TYPE_INFO_REPLY = 16
  ICMP_TYPE_ADDRESS_MASK_REQUEST = 17
  ICMP_TYPE_ADDRESS_MASK_REPLY = 18

  # Type
  unsigned :type, 8
  # Code
  unsigned :code, 8
  # Checksum
  unsigned :csum, 16
  # ID
  unsigned :id, 16
  # Sequence number
  unsigned :seq, 16
  # Payload
  rest :payload

  # check the checksum for this ICMP packet
  def checksum?
    self.csum == compute_checksum
  end

  # compute and set the checksum for this ICMP packet
  def checksum!
    self.csum = compute_checksum
  end

  # 'fix' this ICMP packet up for sending.
  # (really, just set the checksum)
  def fix!
    self.checksum!
  end

private
  def compute_checksum
    # pseudo header used for checksum calculation as per RFC 768 
    pseudo = [ self.type, self.code, 0,  self.id, self.seq, self.payload ]
    L3::Misc.checksum(pseudo.pack("CCnnna*"))
  end
end
end
# vim: set ts=2 et sw=2:
