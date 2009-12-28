# $Id: icmpv6.rb 157 2009-12-14 15:27:32Z jhart $
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
# Internet Control Message Protcol, v6
#
# http://en.wikipedia.org/wiki/ICMPv6
#
# Generic ICMP class from which all ICMP variants spawn.  This should never be used directly.
class ICMPv6Generic < RacketPart
  ICMPv6_TYPE_ECHO_REPLY = 129
  ICMPv6_TYPE_DESTINATION_UNREACHABLE = 1
  ICMPv6_TYPE_PACKET_TOO_BIG = 2
  ICMPv6_TYPE_ECHO_REQUEST = 128
  ICMPv6_TYPE_TIME_EXCEEDED = 3
  ICMPv6_TYPE_PARAMETER_PROBLEM = 4
  ICMPv6_TYPE_MLD_QUERY = 130
  ICMPv6_TYPE_MLD_REPORT = 131
  ICMPv6_TYPE_MLD_DONE = 132
  ICMPv6_TYPE_ROUTER_SOLICITATION = 133
  ICMPv6_TYPE_ROUTER_ADVERTISEMENT = 134
  ICMPv6_TYPE_NEIGHBOR_SOLICITATION = 135
  ICMPv6_TYPE_NEIGHBOR_ADVERTISEMENT = 136
  ICMPv6_TYPE_REDIRECT = 137
  ICMPv6_TYPE_INFORMATION_REQUEST = 139
  ICMPv6_TYPE_INFORMATION_REPLY = 140

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

  # Add an ICMPv6 option.  RFC claims that the value should be padded (with what?)
  # to land on a 64-bit boundary, however that doesn't always appear to be the case.  so, yeah,
  # try to pad on your own or pick strings that are multiples of 8 characters
  def add_option(type, value)
    t = Misc::TLV.new(1,1)
    t.type = type
    t.length = (value.length + 2) / 8
    just = value.length + 2 + (8 - ((value.length + 2) % 8))
    t.value = (value.length + 2) % 8 == 0 ? value : value.ljust(just, "\x00")
    self.payload = t.encode + self.payload 
  end

  # ignorantly assume the first parts of the payload contain ICMPv6 options
  # and find a return an array of Racket::Misc::TLV representing the options
  def get_options
    p = self.payload
    options = []
    until ((o = Misc::TLV.new(1,1,8,true).decode(p)).nil?)
      options << o[0..2]
      p = o[3]
    end
    options
  end

  # compute and set the checksum for this ICMP packet
  def checksum!(src_ip, dst_ip)
    self.checksum = compute_checksum(src_ip, dst_ip)
  end

  # 'fix' this ICMP packet up for sending.
  # (really, just set the checksum)
  def fix!(src_ip, dst_ip)
    self.checksum!(src_ip, dst_ip)
  end

  # get the source link layer address of this message, if found
  def slla
    addr = nil
    self.get_options.each do |o|
      type, length, value, rest = o.flatten
      if (type == 1)
        addr = L2::Misc.string2mac(value)
      end
    end
    addr
  end

  # set the source link layer address of this message.
  # expects +addr+ in de:ad:ba:dc:af:e0 form
  def slla=(addr)
    self.add_option(1, L2::Misc.mac2string(addr))
  end

  # get the target link layer address of this message, if found
  def tlla
    addr = nil
    self.get_options.each do |o|
      type, length, value, rest = o.flatten
      if (type == 2)
        addr = L2::Misc.string2mac(value)
      end
    end
    addr
  end

  # set the target link layer address of this message
  # expects +addr+ in de:ad:ba:dc:af:e0 form
  def tlla=(addr)
    self.add_option(2, L2::Misc.mac2string(addr))
  end

private
  def compute_checksum(src_ip, dst_ip)
    s1 = src_ip >> 96 
    s2 = (src_ip >> 64) & 0xFFFFFFFF
    s3 = (src_ip >> 32) & 0xFFFFFFFF
    s4 = src_ip & 0xFFFFFFFF

    d1 = dst_ip >> 96 
    d2 = (dst_ip >> 64) & 0xFFFFFFFF
    d3 = (dst_ip >> 32) & 0xFFFFFFFF
    d4 = dst_ip & 0xFFFFFFFF

    # pseudo header used for checksum calculation as per RFC 768 
    pseudo = [ s1, s2, s3, s4, d1, d2, d3, d4, self.length, 58, self.type, self.code, 0, self.message ]
    L3::Misc.checksum(pseudo.pack("NNNNNNNNNNCCna*"))
  end
end
# Send raw ICMP packets of your own design
class ICMPv6 < ICMPv6Generic
  rest :payload
end

# Generic ICMPv6 echo, used by ICMPv6EchoRequest and ICMPv6EchoReply 
class ICMPv6Echo < ICMPv6Generic
  # identifier to aid in matching echo requests/replies
  unsigned :id, 16
  # sequence number to aid in matching requests/replies
  unsigned :sequence, 16
  rest :payload

  def initialize(*args)
    super(*args)
  end

end

# ICMPv6Echo Request
class ICMPv6EchoRequest < ICMPv6Echo
  rest :payload

  def initialize(*args)
    super(*args)
    self.type = ICMPv6_TYPE_ECHO_REQUEST
    self.code = 0
  end

end

# ICMPv6Echo Reply
class ICMPv6EchoReply < ICMPv6Echo
  rest :payload

  def initialize(*args)
    super(*args)
    self.type = ICMPv6_TYPE_ECHO_REPLY
    self.code = 0
  end
end

# ICMP Destination Unreachable Message
class ICMPv6DestinationUnreachable < ICMPv6Generic
  ICMPv6_CODE_NO_ROUTE = 0 
  ICMPv6_CODE_ADMIN_PROHIBITED = 1
  ICMPv6_CODE_BEYOND_SCOPE = 2 
  ICMPv6_CODE_ADDRESS_UNREACHABLE = 3 
  ICMPv6_CODE_PORT_UNREACHABLE = 4
  ICMPv6_CODE_FAILED_POLICY = 4 
  ICMPv6_CODE_REJECT_ROUTE = 5 
  # This is never used according to the RFC
  unsigned :unused, 32
  # Internet header + 64 bits of original datagram
  rest :payload

  def initialize(*args)
    super(*args)
    self.type = ICMPv6_TYPE_DESTINATION_UNREACHABLE
  end
end

class ICMPv6PacketTooBig < ICMPv6Generic
  # The Maximum Transmission Unit of the next-hop link
  unsigned :mtu, 32
  rest :payload

  def initialize(*args)
    super(*args)
    self.type = ICMPv6_TYPE_PACKET_TOO_BIG
  end

end

# ICMP Time Exceeded Message 
class ICMPv6TimeExceeded < ICMPv6Generic
  ICMPv6_CODE_TTL_EXCEEDED_IN_TRANSIT = 0 
  ICMPv6_CODE_FRAG_REASSEMBLY_TIME_EXCEEDED = 1
  # This is never used according to the RFC
  unsigned :unused, 32
  # As much of the original ICMPv6 packet without busting MTU
  rest :payload

  def initialize(*args)
    super(*args)
    self.type = ICMPv6_TYPE_TIME_EXCEEDED 
  end
end

# ICMPv6 Parameter Problem Message 
class ICMPv6ParameterProblem < ICMPv6Generic
  ICMPv6_CODE_ERRONEOUS_HEADER = 0
  ICMPv6_CODE_UNRECOGNIZED_NEXT_HEADER = 1
  ICMPv6_CODE_UNRECOGNIZED_OPTION = 2
  # pointer to the octet where the error was detected
  unsigned :pointer, 32 
  # As much of the original ICMPv6 packet without busting MTU
  rest :payload

  def initialize(*args)
    super(*args)
    self.type = ICMPv6_TYPE_PARAMETER_PROBLEM
  end
end

# ICMPv6 Multicast Listener Discovery (MLD)
# http://www.faqs.org/rfcs/rfc2710.html
class ICMPv6MulticastListener < ICMPv6Generic
  # maximum response delay
  unsigned :delay, 16
  # should be zero.  never used.
  unsigned :reserved, 16
  # multicast address
  unsigned :address, 128
  rest :payload

  def initialize(*args)
    super(*args)
  end
end

class ICMPv6MulticastListenerQuery < ICMPv6MulticastListener
  rest :payload

  def initialize(*args)
    super(*args)
    self.type = ICMPv6_TYPE_MLD_QUERY
  end
end

class ICMPv6MulticastListenerReport < ICMPv6MulticastListener
  rest :payload

  def initialize(*args)
    super(*args)
    self.type = ICMPv6_TYPE_MLD_REPORT
  end
end

class ICMPv6MulticastListenerDone < ICMPv6MulticastListener
  rest :payload

  def initialize(*args)
    super(*args)
    self.type = ICMPv6_TYPE_MLD_DONE
  end
end

# http://tools.ietf.org/html/rfc4861
class ICMPv6RouterSolicitation < ICMPv6Generic
  # should be 0, never used.
  unsigned :reserved, 32
  rest :payload

  def initialize(*args)
    super(*args)
    self.type = ICMPv6_TYPE_ROUTER_SOLICITATION
  end
end

# http://tools.ietf.org/html/rfc4861
class ICMPv6RouterAdvertisement < ICMPv6Generic
  # default value that should be placed in the hop count field of the IP header
  # for outgoing IP packets
  unsigned :hop_limit, 8
  # boolean, managed address configuration?
  unsigned :managed_config, 1
  # boolean, other configuration?
  unsigned :other_config, 1
  # set to 0, never used.
  unsigned :reserved, 6
  # lifetime associated with the default router in seconds
  unsigned :lifetime, 16
  # time in milliseconds that a node assumes a neighbor is reachable after having received a reachability confirmation
  unsigned :reachable_time, 32
  # time in milliseconds between retransmitted neighbor solicitation messages
  unsigned :retrans_time, 32
  rest :payload

  def initialize(*args)
    super(*args)
    self.type = ICMPv6_TYPE_ROUTER_ADVERTISEMENT
  end
end

# http://tools.ietf.org/html/rfc4861
class ICMPv6NeighborSolicitation < ICMPv6Generic
  # set to 0, never used.
  unsigned :reserved, 32
  # target address of the solicitation
  unsigned :address, 128
  rest :payload

  def initialize(*args)
    super(*args)
    self.type = ICMPv6_TYPE_NEIGHBOR_SOLICITATION
  end
end

# http://tools.ietf.org/html/rfc4861
class ICMPv6NeighborAdvertisement < ICMPv6Generic
  # normally this would be router (1), solicited (1), override(1) and reserved (2), however
  # a bit-struct byte boundary bug bites us here
  unsigned :bigbustedfield, 32
  # for solicited adverts, the target address field in the solicitation that prompted this.
  # for unsolicited adverts, the address whose link-layer address has changed 
  unsigned :address, 128
  rest :payload
  
  # set solicited flag
  def solicited=(f)
    self.bigbustedfield = (f << 30) ^ self.bigbustedfield
  end

  # set router flag
  def router=(f)
    self.bigbustedfield = (f << 31) ^ self.bigbustedfield
  end

  # set override flag
  def override=(f)
    self.bigbustedfield = (f << 29) ^ self.bigbustedfield
  end

  def initialize(*args)
    super(*args)
    self.type = ICMPv6_TYPE_NEIGHBOR_ADVERTISEMENT
  end
end

# http://tools.ietf.org/html/rfc4861
class ICMPv6Redirect < ICMPv6Generic
  # unused, should be 0
  unsigned :reserved, 32
  # the IP address that is a better first hop to use for the ICMP destination address
  unsigned :src_ip, 128
  # the IP address of the destination that is redirected to the target
  unsigned :dst_ip, 128
  rest :payload

  def initialize(*args)
    super(*args)
    self.type = ICMPv6_TYPE_REDIRECT
  end
end

# Generic class that IPv6NodeInformationRequest and Reply inherit from
# http://tools.ietf.org/html/rfc4620
class ICMPv6NodeInformation < ICMPv6Generic
  # type of information requested in a query or supplied in a reply
  unsigned :qtype, 16
  # qtype-specific flags that may be defined for certain qtypes and their replies
  unsigned :flags, 16
  # opaque field to help avoid spoofing and/or to aid in matching replies with queries
  text :nonce, 64 
  rest :payload

  def initialize(*args)
    super(*args)
  end
end

# http://tools.ietf.org/html/rfc4620
class ICMPv6NodeInformationRequest < ICMPv6NodeInformation
  ICMPv6_CODE_INFORMATION_REQUEST_IPv6 = 0
  ICMPv6_CODE_INFORMATION_REQUEST_NAME = 1 
  ICMPv6_CODE_INFORMATION_REQUEST_IPv4 = 2

  def initialize(*args)
    super(*args)
    self.type = ICMPv6_TYPE_INFORMATION_REQUEST
  end
end

# http://tools.ietf.org/html/rfc4620
class ICMPv6NodeInformationReply < ICMPv6NodeInformation
  ICMPv6_CODE_INFORMATION_REPLY_SUCCESS = 0
  ICMPv6_CODE_INFORMATION_REPLY_REFUSE = 1 
  ICMPv6_CODE_INFORMATION_REPLY_UNKNOWN = 2

  def initialize(*args)
    super(*args)
    self.type = ICMPv6_TYPE_INFORMATION_REPLY
  end
end
end
end
# vim: set ts=2 et sw=2:
