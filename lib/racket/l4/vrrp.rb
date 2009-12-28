# $Id: vrrp.rb 127 2009-11-29 01:30:46Z jhart $
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
# Virtual Router Redundancy Protocol (VRRP)
# http://tools.ietf.org/html/rfc2338
# http://tools.ietf.org/html/rfc3768
class VRRP < RacketPart
  # Version
  unsigned :version, 4
  # VRRP packet type 
  unsigned :type, 4 
  # Virtual Router Identifier (VRID)
  unsigned :id, 8
  # the sending VRRP router's priority for the virtual router.
  # Higher values equal higher priority.
  unsigned :priority, 8
  # Total number of IPs contained in this VRRP message
  unsigned :num_ips, 8
  # Authentication type (0, 1, 2)
  unsigned :auth_type, 8
  # Advertisement interval
  unsigned :interval, 8
  # Checksum
  unsigned :checksum, 16
  rest :payload

  # Add a new IP to this message
  def add_ip(ip)
    @ips << L3::Misc.ipv42long(ip)
  end

  # Add authentication data
  def add_auth(authdata)
    @authdata = authdata[0,8].ljust(32, "\x00")
  end

  # Validate the checksum
  def checksum?
    self.checksum == compute_checksum
  end

  # compute and set the checksum
  def checksum!
    self.checksum = compute_checksum
  end

  # (really, just set the checksum)
  def fix!
    self.payload = [@ips, @authdata].flatten.pack("N#{@ips.size}a*")
    self.num_ips = @ips.size
    self.checksum!
  end

  def initialize(*args)
    @ips = []
    @authdata = ""
    super
  end

private
  def compute_checksum
    # pseudo header used for checksum calculation as per RFC 768 
    pseudo = [ ((self.version << 4) | self.type), self.id, self.priority, self.num_ips, self.auth_type, self.interval, 0, self.payload ] 
    L3::Misc.checksum(pseudo.pack("CCCCCCna*"))
  end
end
end
end
# vim: set ts=2 et sw=2:
