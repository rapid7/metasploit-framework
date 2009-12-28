# $Id: hsrp.rb 14 2008-03-02 05:42:30Z warchild $
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
module L5
# Hot Standby Router Protocol: HSRP
#
# RFC2281 (http://www.faqs.org/rfcs/rfc2281.html)
class HSRP < RacketPart
  HSRP_HELLO = 0
  HSRP_COUP = 1
  HSRP_RESIGN = 2

  HSRP_INITIAL = 0
  HSRP_LEARN   = 1 
  HSRP_LISTEN  = 2 
  HSRP_SPEAK   = 4 
  HSRP_STANDBY = 8
  HSRP_ACTIVE  = 16

  # Version of the HSRP message contained in this packet.  Defaults to 0
  unsigned :version, 8
  # Type of the HSRP message contained in this packet.
  unsigned :opcode, 8
  # Current state of the router sending the message
  unsigned :state, 8
  # Time between the hello messages that this router sends.  Obviously only 
  # useful in hello messages
  unsigned :hellotime, 8
  # Length of time that this hello message should be considered valid.
  # Obviously only useful in hello messages.
  unsigned :holdtime, 8, { :default => 10 }
  # Priority used to determine active and standby routers.  Higher priorities
  # win, but a higher IP address wins in the event of a tie.
  unsigned :priority, 8
  # Standby group
  unsigned :group, 8
  # reserved, never used, should be 0
  unsigned :reserved, 8
  # Clear-text, 8-character reused password.  Defaults to 'cisco'
  text :password, 64, { :default => 'cisco' }
  # Virtual IP address used by this group
  octets :vip, 32
  # Payload.  Generally unused.
  rest :payload
end
end
end
# vim: set ts=2 et sw=2:
