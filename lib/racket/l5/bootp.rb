# $Id: bootp.rb 14 2008-03-02 05:42:30Z warchild $
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
# Bootstrap Protocol -- BOOTP
#
# RFC951 (http://www.faqs.org/rfcs/rfc951.html)
module Racket
class BOOTP < RacketPart
  BOOTP_REQUEST = 1
  BOOTP_REPLY = 2

  # Message type
  unsigned :type, 8 
  # Hardware address type
  unsigned :hwtype, 8, { :default => 1 }
  # Hardware adddress length
  unsigned :hwlen, 8, { :default => 6 }
  # Hops between client and server
  unsigned :hops, 8
  # Transaction ID
  unsigned :id, 32 
  # Seceonds elapsed since client started trying to boot
  unsigned :secs, 16
  # Flags.  Generally unused
  unsigned :flags, 16
  # Client IP address
  octets :cip, 32
  # "Your" (client) IP address.
  octets :yip, 32
  # Server IP address
  octets :sip, 32
  # Gateway IP address
  octets :gip, 32
  # Client hardware address
  hex_octets :chaddr, 128
  # Optional server host name
  text :server, 512
  # Boot file name
  text :file, 1024
  # Payload
  rest :payload

  def add_option(number, value)
    o = TLV.new(1,1)
    o.type = number
    o.value = value
    o.length = value.length
    @options << o.encode
  end

  def fix!
    # tack on an EOL to the options
    newpayload = @options.join + "\xff"
   
    # pad out to 64 bytes
    while (newpayload.length != 64)
      newpayload += "\x00"
    end

    self.payload = newpayload + self.payload
  end

  def to_s
    puts "to_s"
  end

  def to_str
    puts to_str
  end

  def initialize(*args)
    @options = []
    @options << "\x63\x82\x53\x63" # magic
    super
    @autofix = false
  end

end
end
# vim: set ts=2 et sw=2:
