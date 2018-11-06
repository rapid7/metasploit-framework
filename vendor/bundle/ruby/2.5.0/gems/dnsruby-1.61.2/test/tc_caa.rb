
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
require 'pry'

class TestCAA < Minitest::Test

  include Dnsruby

  def test_caa
    {'foo.com. IN CAA 0 issue "ca.example.net"' => [0, 'issue', 'ca.example.net'],
     'foo.com. IN CAA 1 issue "ca.example.net"' => [1, 'issue', 'ca.example.net'],
     'foo.com. IN CAA 0 issuewild "ca.example.net"' => [0, 'issuewild', 'ca.example.net'],
     'foo.com. IN CAA 0 iodef "mailto:security@example.com"' => [0, 'iodef', 'mailto:security@example.com'],
     'foo.com. IN CAA 0 issue "ca.example.net; account=230123"' => [0, 'issue', 'ca.example.net; account=230123']
    }.each do |text, data|
      caa = RR.create(text)
      assert_equal(data[0], caa.flag)
      assert_equal(data[1], caa.property_tag)
      assert_equal(data[2], caa.property_value)
      m = Dnsruby::Message.new
      m.add_additional(caa)
      data = m.encode
      m2 = Dnsruby::Message.decode(data)
      caa2 = m2.additional()[0]
      assert(caa.flag == caa2.flag)
      assert(caa.property_tag == caa2.property_tag)
      assert(caa.property_value == caa2.property_value)
      assert(caa == caa2)
    end
  end

end

