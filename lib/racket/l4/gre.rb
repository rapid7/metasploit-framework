# $Id: gre.rb 14 2008-03-02 05:42:30Z warchild $
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
#     XXX: currently broken.  all of the "optional" fields must be made dynamic
class GRE < RacketPart
  # Is a checksum present?
  unsigned :checksum_present, 1
  # Is routing information present?
  unsigned :routing_present, 1
  # Is a key present?
  unsigned :key_present, 1
  # Is a sequence number present?
  unsigned :seq_present, 1
  # Strict source route
  unsigned :ssr, 1
  # How many additional encapsulations are present?
  unsigned :recursion, 3
  # Flags
  unsigned :flags, 5
  # Version
  unsigned :version, 3
  # Protocol type
  unsigned :protocol, 16
  # Checksum
  unsigned :checksum, 16
  # Offset
  unsigned :offset, 16
  # Key
  unsigned :key, 32
  # Sequence Number
  unsigned :seq, 32
  # Routing
  unsigned :routing, 32
  # Payload
  rest :payload
end
end
end
# vim: set ts=2 et sw=2:
