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

class TestValidator < Minitest::Test

  include Dnsruby

  def test_validation
#    Dnsruby::TheLog.level = Logger::DEBUG
    Dnsruby::Dnssec.clear_trusted_keys
    Dnsruby::Dnssec.clear_trust_anchors
    res = Dnsruby::Resolver.new("dnssec.nominet.org.uk")
    res.dnssec=true
    res.do_validation = true
    Dnsruby::Dnssec.do_validation_with_recursor(false)
    Dnsruby::Dnssec.default_resolver=(res) # This is a closed zone (not reachable by recursion)

    trusted_key = Dnsruby::RR.create({:name => "uk-dnssec.nic.uk.",
        :type => Dnsruby::Types.DNSKEY,
        :flags => RR::IN::DNSKEY::SEP_KEY | RR::IN::DNSKEY::ZONE_KEY,
        :key=> "AQPJO6LjrCHhzSF9PIVV7YoQ8iE31FXvghx+14E+jsv4uWJR9jLrxMYm sFOGAKWhiis832ISbPTYtF8sxbNVEotgf9eePruAFPIg6ZixG4yMO9XG LXmcKTQ/cVudqkU00V7M0cUzsYrhc4gPH/NKfQJBC5dbBkbIXJkksPLv Fe8lReKYqocYP6Bng1eBTtkA+N+6mSXzCwSApbNysFnm6yfQwtKlr75p m+pd0/Um+uBkR4nJQGYNt0mPuw4QVBu1TfF5mQYIFoDYASLiDQpvNRN3 US0U5DEG9mARulKSSw448urHvOBwT9Gx5qF2NE4H9ySjOdftjpj62kjb Lmc8/v+z"
      })
    ret = Dnsruby::Dnssec.add_trust_anchor(trusted_key)

    r = res.query("aaa.bigzone.uk-dnssec.nic.uk", Dnsruby::Types.A)
    assert(r.security_level.code == Message::SecurityLevel::SECURE, "Level = #{r.security_level.string}")
    ret = Dnsruby::Dnssec.validate(r)
    assert(ret, "Dnssec validation failed")

    #  @TODO@ Test other validation policies!!
  end

  def test_resolver_cd_validation_fails
    #  Should be able to check Nominet test-zone here - no keys point to it
    res = Resolver.new
    res.dnssec=true
    r = res.query("uk-dnssec.nic.uk", Dnsruby::Types.A)
    assert(r.security_level = Message::SecurityLevel::INSECURE)
  end

  def test_eventtype_api
    #  @TODO@ TEST THE Resolver::EventType interface!
    print "Test EventType API!\n"
  end

  def test_config_api
    #  @TODO@ Test the different configuration options for the validator,
    #  and their defaults
    # 
    #  Should be able to set :
    #   o Whether or not validation happens
    #   o The async API queue tuples etc.
    #   o Whether to use authoritative nameservers for validation
    #   o Whether to use authoritative nameservers generally
    # 
    print "Test validation configuration options!\n"
  end


end
