# $Id: stp.rb 14 2008-03-02 05:42:30Z warchild $
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
# Spanning Tree Protocol
#
# http://en.wikipedia.org/wiki/Spanning_tree_protocol
class STP < RacketPart
  # Protocol identifier
  unsigned :protocol, 16, { :default => 0 }
  # Protocol version 
  unsigned :version, 8, { :default => 2}
  # BPDU type
  unsigned :bpdu_type, 8, { :default => 2 }
  # BPDU Flag -- Topology Change Acknowledgement
  unsigned :bpdu_flag_change_ack, 1
  # BPDU Flag -- Agreement
  unsigned :bpdu_flag_agreement, 1
  # BPDU Flag -- Forwarding
  unsigned :bpdu_flag_forwarding, 1
  # BPDU Flag -- Learning
  unsigned :bpdu_flag_learning, 1
  # BPDU Flag -- Port Role
  unsigned :bpdu_flag_port_role, 2
  # BPDU Flag -- Proposal
  unsigned :bpdu_flag_proposal, 1
  # BPDU Flag -- Topology Change
  unsigned :bpdu_flag_change, 1
  # Root wtf?  Not sure what this is XXX
  unsigned :root_wtf, 16
  # Root Identifier
  hex_octets :root_id, 48
  # Root Path Cost
  unsigned :root_cost, 32
  # Bridge WTF? Not sure what this is XXX
  unsigned :bridge_wtf, 16
  # Bridge Identifier
  hex_octets :bridge_id, 48
  # Port Identifier
  unsigned :port_id, 16
  # Message age
  unsigned :msg_age, 16
  # Max age
  unsigned :max_age, 16
  # Hello time
  unsigned :hello_time, 16
  # Forward delay
  unsigned :forward_delay, 16
  # Version 1 Length
  unsigned :v1_len, 8
  # Payload
  rest :payload
end
end
end
# vim: set ts=2 et sw=2:
