# --
# Copyright 2007 Nominet UK
# 
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# 
#     http://www.apache.org/licenses/LICENSE-2.0
# 
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
# ++

require_relative 'spec_helper'

require "digest/md5"
class TestTKey < Minitest::Test
  def is_empty(string)
    return (string == "; no data" || string == "; rdlength = 0")
  end

  def test_tkey


    # ------------------------------------------------------------------------------
    #  Canned data.
    # ------------------------------------------------------------------------------

    zone	= "example.com"
    name	= "123456789-test"
    klass	= "IN"
    type	= Dnsruby::Types.TKEY
    algorithm   = "fake.algorithm.example.com"
    key         = "fake key"
    inception   = 100000 # use a strange fixed inception time to give a fixed
    #  checksum
    expiration  = inception + 24*60*60

    rr = nil

    # ------------------------------------------------------------------------------
    #  Packet creation.
    # ------------------------------------------------------------------------------

    rr = Dnsruby::RR.create(
      :name       => name,
      :type       => "TKEY",
      :ttl        => 0,
      :klass      => "ANY",
      :algorithm  => algorithm,
      :inception  => inception,
      :expiration => expiration,
      :mode       => 3, # GSSAPI
      :key        => "fake key",
      :other_data => ""
    )

    packet = Dnsruby::Message.new(name, Dnsruby::Types.TKEY, "IN")
    packet.add_answer(rr)

    z = (packet.zone)[0]

    assert(packet,                                'new() returned packet')  #2
    assert_equal(Dnsruby::OpCode.QUERY,       packet.header.opcode, 'header opcode correct')  #3
    assert_equal(name,                      z.zname.to_s,  'zname correct')          #4
    assert_equal(Dnsruby::Classes.IN,                       z.zclass, 'zclass correct')         #5
    assert_equal(Dnsruby::Types.TKEY,                     z.ztype,  'ztype correct')          #6

    # @TODO@ Test TKEY against server!

  end

  end
