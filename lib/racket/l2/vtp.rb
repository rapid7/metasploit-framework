# $Id: vtp.rb 127 2009-11-29 01:30:46Z jhart $
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
module L2
# VLAN Trunking Protocol (VTP)
# http://en.wikipedia.org/wiki/VLAN_Trunking_Protocol
# http://www.cisco.com/en/US/tech/tk389/tk689/technologies_tech_note09186a0080094c52.shtml
# This is just a base class from which all VTP messages inherit and should never be used directly
class VTPGeneric < RacketPart
  # VTP version (1-3)
  unsigned :version, 8 
  # Message code (summary advertisement, subset advertisement, advertisement request, VTP join)
  unsigned :code, 8 
  # Sometimes used, sometimes not, depends on the type
  unsigned :reserved, 8  
  # Length of the management domain
  unsigned :domain_length, 8
  # management domain name, zero padded to 32 bytes
  text :domain, 256

  # Adjust +domain_length+ and +domain+ accordingly prior to sending
  def fix!
    self.domain_length = self.domain.length 
    self.domain = self.domain.ljust(32, "\x00")
  end
end

# A raw VTP message
class VTPRaw < VTPGeneric
  rest :payload
end

class VTPSubsetAdvertisement < VTPGeneric
  # Configuration revision
  unsigned :revision, 32
  # all of the vlan info fields
  rest :payload

  def add_vlan_info(status, type, id, mtu, index, name)
    name_length = name.length
    # zero pad name to a multiple of 4 bytes
    name = name.length % 4 == 0 ? name : name.ljust(name.length + (4 - (name.length % 4)), "\x00")
    length = 12 + name.length
    @vlan_info << [length, status, type, name_length, id, mtu, index, name]
  end

  def fix!
    @vlan_info.each do |v|
      self.payload += v.pack("CCCCnnNa*")
    end
    super
  end

  def initialize(*args)
    @vlan_info = []
    super(*args)
    self.code = 2 
  end
end

class VTPSummaryAdvertisement < VTPGeneric
  # Configuration revision number
  unsigned :revision, 32
  # Updater identity (IP)
  octets :updater, 32
  # update timestamp
  unsigned :timestamp, 96
  # MD5 digest of VTP password
  text :md5, 128 
  rest :payload

  def initialize(*args)
    super(*args)
    self.code = 1
  end
end

class VTPAdvertisementRequest < VTPGeneric
  # This is used in cases in which there are several subset advertisements. If the first (n) subset advertisement has been received and the subsequent one (n+1) has not been received, the Catalyst only requests advertisements from the (n+1)th one.
  unsigned :start, 32
  rest :payload
  def initialize(*args)
    super(*args)
    self.code = 3
  end

end


class VTPJoin < VTPGeneric
  def initialize(*args)
    super(*args)
    self.code = 4
  end
end

end
end
# vim: set ts=2 et sw=2:
