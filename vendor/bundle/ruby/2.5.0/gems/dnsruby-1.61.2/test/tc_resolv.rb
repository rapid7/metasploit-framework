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
require_relative '../lib/dnsruby/resolv'

class TestResolv < Minitest::Test

  RELATIVE_NAME = 'google-public-dns-a.google.com'
  ABSOLUTE_NAME = RELATIVE_NAME + '.'
  IPV4_ADDR     = '8.8.8.8'
  IPV6_ADDR     = '2001:4860:4860::8888'
  ADDRESSES     = [IPV4_ADDR, IPV6_ADDR]


  def test_resolv_name_to_addresses

    assert_equal(IPV4_ADDR, Dnsruby::Resolv.getaddress(ABSOLUTE_NAME).to_s)

    addresses = Dnsruby::Resolv.getaddresses(ABSOLUTE_NAME)

    case addresses.length
      when 1
        assert_equal IPV4_ADDR, addresses.first.to_s
        Dnsruby::Resolv.each_address(ABSOLUTE_NAME) do |address|
          assert_equal IPV4_ADDR, address.to_s
        end
      when 2
        assert_equal ADDRESSES.sort, addresses.map(&:to_s).sort
        addresses_from_each = []
        Dnsruby::Resolv.each_address(ABSOLUTE_NAME) do |address|
          addresses_from_each << address.to_s
        end
        assert_equal ADDRESSES.sort, addresses_from_each.sort
      else
        raise "Addresses length must be 1 or 2 but was #{addresses.length}"
    end
  end


  def test_resolv_address_to_name

    assert_equal(RELATIVE_NAME, Dnsruby::Resolv.getname(IPV4_ADDR).to_s)

    assert_raises(Dnsruby::ResolvError) do
      Dnsruby::Resolv.getname(RELATIVE_NAME)
    end

    names = Dnsruby::Resolv.getnames(IPV4_ADDR)
    assert_equal(1, names.size)
    assert_equal(RELATIVE_NAME, names.first.to_s)
    Dnsruby::Resolv.each_name(IPV4_ADDR) { |name| assert_equal(RELATIVE_NAME, name.to_s)}
  end

  def test_resolv_address_to_address
    local = '127.0.0.1'
    assert_equal(local, Dnsruby::Resolv.new.getaddress(local))
  end
end
