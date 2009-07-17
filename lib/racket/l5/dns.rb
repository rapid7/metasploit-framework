# $Id: dns.rb 14 2008-03-02 05:42:30Z warchild $
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
# Domain Name System
module Racket
class DNS < RacketPart
  # Transaction ID
  unsigned :tx_id, 16
  # Response
  unsigned :response, 1
  # Opcode
  unsigned :opcode, 4
  # Authoritative?
  unsigned :authoritative, 1
  # Truncated?
  unsigned :truncated, 1
  # Recursion Desired?
  unsigned :recursion_d, 1
  # Recursion Available?
  unsigned :recursion_a, 1
  # Reserved
  unsigned :reserved, 1
  # Answer authenticated?
  unsigned :auth, 1
  # Non-authenticated data OK?
  unsigned :nonauth, 1
  # Reply Code
  unsigned :reply_code, 4
  # Number of questions
  unsigned :question_rr, 16
  # Number of answer RR
  unsigned :answer_rr, 16
  # Number of authority RR
  unsigned :authority_rr, 16
  # Number of additional RR
  unsigned :additional_rr, 16
  rest :payload

  def initialize(*args)
    super
  end

  # Add an additional record.  Automatically increases +additional_rr+
  def add_additional(name, type, klass)
    self.payload += self.add_record(name, type, klass).encode
    self.additional_rr += 1
  end

  # Add an answer record.  Automatically increases +answer_rr+
  def add_answer(name, type, klass)
    self.payload += self.add_record(name, type, klass).encode
    self.answer_rr += 1
  end

  # Add an authority record.  Automatically increases +authority_rr+
  # XXX: broken.  authns records are much more complicated than this.
  def add_authority(name, type, klass)
    self.payload += self.add_record(name, type, klass).encode
    self.authority_rr += 1
  end

  # Add a question record.  Automatically increases +question_rr+
  def add_question(name, type, klass)
    self.payload += add_record(name, type, klass).encode
    self.question_rr += 1
  end

private
  def add_record(name, type, klass)
    q = VT.new(2,2)
    name.split(/\./).each do |p|
      lv = LV.new(1)
      lv.values << p
      lv.lengths << p.length
      q.value << lv.encode 
    end
    q.types << type
    q.types << klass
    q
  end

end
end
# vim: set ts=2 et sw=2:
