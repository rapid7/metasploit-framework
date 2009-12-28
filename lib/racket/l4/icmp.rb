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
module Racket
module L4
# Internet Control Message Protcol.  
#
# RFC792 (http://www.faqs.org/rfcs/rfc792.html)
#
# Generic ICMP class from which all ICMP variants spawn.  This should never be used directly.
class ICMPGeneric < RacketPart
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
  unsigned :checksum, 16
  rest :message

  # check the checksum for this ICMP packet
  def checksum?
    self.checksum == compute_checksum
  end

  def initialize(*args)
    super(*args)
    @autofix = false
  end


  # compute and set the checksum for this ICMP packet
  def checksum!
    self.checksum = compute_checksum
  end

  # 'fix' this ICMP packet up for sending.
  # (really, just set the checksum)
  def fix!
    self.checksum!
  end

private
  def compute_checksum
    # pseudo header used for checksum calculation as per RFC 768 
    pseudo = [ self.type, self.code, 0, self.message ]
    L3::Misc.checksum(pseudo.pack("CCna*"))
  end
end

# Send raw ICMP packets of your own design
class ICMP < ICMPGeneric
  rest :payload
end

# ICMP Echo.  Generic class that ICMPEchoRequest and ICMPEchoReply inherit
class ICMPEcho < ICMPGeneric
  # ID for tracking requests/replies
  unsigned :id, 16
  # sequence number for tracking request/replies
  unsigned :sequence, 16
  rest :payload

  def initialize(*args)
    super(*args)
    self.type = 8 
    self.code = 0
  end
end

# ICMP Echo Request
class ICMPEchoRequest < ICMPEcho
  rest :payload

  def initialize(*args)
    super(*args)
    self.type = 8 
    self.code = 0
  end
end

# ICMP Echo Reply
class ICMPEchoReply < ICMPEcho
  rest :payload

  def initialize(*args)
    super(*args)
    self.type = 0 
    self.code = 0
  end
end

# ICMP Destination Unreachable Message
class ICMPDestinationUnreachable < ICMPGeneric
  ICMP_CODE_NETWORK_UNREACHABLE = 0 
  ICMP_CODE_HOST_UNREACHABLE = 1
  ICMP_CODE_PROTOCOL_UNREACHABLE = 2 
  ICMP_CODE_PORT_UNREACHABLE = 3 
  ICMP_CODE_FRAG_NEEDED_DF_SET = 4 
  ICMP_CODE_SOURCE_ROUTE_FAILED = 5 
  # This is never used according to the RFC
  unsigned :unused, 32
  # Internet header + 64 bits of original datagram
  rest :payload

  def initialize(*args)
    super(*args)
    self.type = 3 
  end
end

# ICMP Time Exceeded Message 
class ICMPTimeExceeded < ICMPGeneric
  ICMP_CODE_TTL_EXCEEDED_IN_TRANSIT = 0 
  ICMP_CODE_FRAG_REASSEMBLY_TIME_EXCEEDED = 1
  # This is never used according to the RFC
  unsigned :unused, 32
  # Internet header + 64 bits of original datagram
  rest :payload

  def initialize(*args)
    super(*args)
    self.type = 11 
  end
end

# ICMP Parameter Problem Message 
class ICMPParameterProblem < ICMPGeneric
  # pointer to the octet where the error was detected
  unsigned :pointer, 8
  # This is never used according to the RFC
  unsigned :unused, 24
  # Internet header + 64 bits of original datagram
  rest :payload

  def initialize(*args)
    super(*args)
    self.type = 12
    self.code = 0
  end
end

# ICMP Source Quench Message 
class ICMPSourceQuench < ICMPGeneric
  # This is never used according to the RFC
  unsigned :unused, 32 
  # Internet header + 64 bits of original datagram
  rest :payload

  def initialize(*args)
    super(*args)
    self.type = 4 
    self.code = 0
  end
end

# ICMP Redirect Message 
class ICMPRedirect < ICMPGeneric
  ICMP_CODE_REDIRECT_NETWORK = 0 
  ICMP_CODE_REDIRECT_HOST = 1
  ICMP_CODE_REDIRECT_TOS_NETWORK = 2
  ICMP_CODE_REDIRECT_TOS_HOST = 3

  # Gateway internet address
  octets :gateway_ip, 32 
  # Internet header + 64 bits of original datagram
  rest :payload

  def initialize(*args)
    super(*args)
    self.type = 5 
    self.code = 0
  end
end

# Generic ICMP Timestamp Message from which ICMPTimestampRequest and
# ICMPTimestampReply inherit
class ICMPTimestamp < ICMPGeneric
  # an identifier to add in matching timestamp and replies
  unsigned :id, 16
  # a sequence number to aid in matching timestamp and replies
  unsigned :sequence, 16
  # time the sender last touched the message before sending it in number of milliseconds since midnight UT
  unsigned :originate_timestamp, 32
  # time the echoer first touched it on receipt in number of milliseconds since midnight UT
  unsigned :receive_timestamp, 32
  # time the echoers last touched the message on sending it in number of milliseconds since midnight UT
  unsigned :transmit_timestamp, 32
  # probably never used ...
  rest :payload

  def initialize(*args)
    super(*args)
  end

end

# ICMP Timestamp Request Message
class ICMPTimestampRequest < ICMPTimestamp
  # probably never used ...
  rest :payload

  def initialize(*args)
    super(*args)
    self.type = 13
    self.code = 0
  end
end

# ICMP Timestamp Reply Message
class ICMPTimestampReply < ICMPTimestamp
  # probably never used ...
  rest :payload

  def initialize(*args)
    super(*args)
    self.type = 14 
    self.code = 0
  end
end

# ICMP Information Request Message
class ICMPInformationRequest < ICMPGeneric
  # an identifier to add in matching timestamp and replies
  unsigned :id, 16
  # a sequence number to aid in matching timestamp and replies
  unsigned :sequence, 16
  # probably never used ...
  rest :payload

  def initialize(*args)
    super(*args)
    self.type = 15
    self.code = 0
  end

end

# ICMP Information Reply Message
class ICMPInformationReply < ICMPGeneric
  # an identifier to add in matching timestamp and replies
  unsigned :id, 16
  # a sequence number to aid in matching timestamp and replies
  unsigned :sequence, 16
  # probably never used ...
  rest :payload

  def initialize(*args)
    super(*args)
    self.type = 16 
    self.code = 0
  end
end
end
end
# vim: set ts=2 et sw=2:
