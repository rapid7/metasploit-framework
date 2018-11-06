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

class TestPacketUniquePush < Minitest::Test

  include Dnsruby

  #   def test_packUniquePush
  # 
  # 
  #     testProc('unique_push');
  #   end
  # 
  # #  def test_packetSafePush
  # #    begin
  # #      testProc('safe_push');
  # #      flunk("Shouldn't work!")
  # #    rescue Exception
  # #    end
  # #  end

  #   def testProc (method)
  def test_proc
    domain = 'example.com';

    tests = [
    [
    1,
    RR.create('foo.example.com 60 IN A 10.0.0.1'),
    RR.create('foo.example.com 60 IN A 10.0.0.1'),
    ],
    [
    2,
    RR.create('foo.example.com 60 IN A 10.0.0.1'),
    RR.create('bar.example.com 60 IN A 10.0.0.1'),
    ],
    [
    1, # RFC 2136 section 1.1
    RR.create('foo.example.com 60 IN A 10.0.0.1'),
    RR.create('foo.example.com 60 IN A 10.0.0.1'),
    RR.create('foo.example.com 90 IN A 10.0.0.1'),
    ],
    [
    3,
    RR.create('foo.example.com 60 IN A 10.0.0.1'),
    RR.create('foo.example.com 60 IN A 10.0.0.2'),
    RR.create('foo.example.com 60 IN A 10.0.0.3'),
    ],
    [
    3,
    RR.create('foo.example.com 60 IN A 10.0.0.1'),
    RR.create('foo.example.com 60 IN A 10.0.0.2'),
    RR.create('foo.example.com 60 IN A 10.0.0.3'),
    RR.create('foo.example.com 60 IN A 10.0.0.1'),
    ],
    [
    3,
    RR.create('foo.example.com 60 IN A 10.0.0.1'),
    RR.create('foo.example.com 60 IN A 10.0.0.2'),
    RR.create('foo.example.com 60 IN A 10.0.0.1'),
    RR.create('foo.example.com 60 IN A 10.0.0.4'),
    ],
    ]

    methods = {
		'add_answer'     => 'ancount',
		'add_authority'  => 'nscount',
		'add_additional' => 'arcount',
    }

    tests.each do | try |
      count = try.shift;
      rrs = try;

      methods.each do |method, count_meth|

        packet = Message.new(domain)

        rrs.each do |rr|
          packet.send(method,rr)
        end

        assert_equal(count, packet.header.send(count_meth), "#{method} right for #{rrs.inspect}");
        assert_equal(count, packet.header.send(count_meth), "#{method} right for #{rrs.inspect}");

      end
    end
  end
end
