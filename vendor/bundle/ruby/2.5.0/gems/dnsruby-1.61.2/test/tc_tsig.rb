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
class TestTSig < Minitest::Test

  include Dnsruby

  KEY_NAME="rubytsig"
  KEY = "8n6gugn4aJ7MazyNlMccGKH1WxD2B3UvN/O/RA6iBupO2/03u9CTa3Ewz3gBWTSBCH3crY4Kk+tigNdeJBAvrw=="
  def is_empty(string)
    return (string == "; no data" || string == "; rdlength = 0")
  end
  def test_signed_update
    #     Dnsruby::Resolver::use_eventmachine(false)
    run_test_client_signs
    run_test_resolver_signs
  end
  #   def test_signed_update_em
  #     begin
  #       Dnsruby::Resolver::use_eventmachine(true)
  #     rescue RuntimeError
  #       Dnsruby.log.error("EventMachine not installed - not running tsig EM tests")
  #       return
  #     end
  #     run_test_client_signs
  #     run_test_resolver_signs
  #     Dnsruby::Resolver::use_eventmachine(false)
  #   end

  def run_test_client_signs
    #  NOTE - client signing is only appropriate if DNSSEC and EDNS are switched
    #  off. Otherwise, the resolver will attempt to alter the flags and add an
    #  EDNS OPT psuedo-record to the query message, invalidating the signing.
    tsig = Dnsruby::RR.create({
        :name        => KEY_NAME,
        :type        => "TSIG",
        :ttl         => 0,
        :klass       => "ANY",
        :algorithm   => "hmac-md5",
        :fudge       => 300,
        :key         => KEY,
        :error       => 0
      })

    update = Dnsruby::Update.new("validation-test-servers.nominet.org.uk")
    #  Generate update record name, and test it has been made. Then delete it and check it has been deleted
    update_name = generate_update_name
    update.absent(update_name)
    update.add(update_name, 'TXT', 100, "test signed update")
    tsig.apply(update)
    assert(update.signed?, "Update has not been signed")

    res = Dnsruby::Resolver.new("ns0.validation-test-servers.nominet.org.uk")
    res.udp_size=512 # Or else we needed to add OPT record already
    res.dnssec=false
    res.recurse=false
    res.query_timeout = 20
    response = res.send_message(update)

    assert_equal( Dnsruby::RCode.NOERROR, response.rcode)
    assert(response.verified?, "Response has not been verified")

    #  Now check the record exists
    rr = res.query(update_name, 'TXT')
    assert_equal("test signed update", rr.answer()[0].strings.join(" "), "TXT record has not been created in zone")

    #  Now delete the record
    update = Dnsruby::Update.new("validation-test-servers.nominet.org.uk")
    update.present(update_name, 'TXT')
    update.delete(update_name)
    tsig.apply(update)
    assert(update.signed?, "Update has not been signed")
    response = res.send_message(update)
    assert_equal( Dnsruby::RCode.NOERROR, response.rcode)
    assert(response.verified?, "Response has not been verified")

    #  Now check the record does not exist
    Dnsruby::PacketSender.clear_caches
    #  Or else the cache will tell us it still deos!
    begin
      rr = res.query(update_name, 'TXT')
      assert(false)
    rescue Dnsruby::NXDomain
    end
  end

  @@fudge = 0
  def generate_update_name
    update_name = Time.now.to_i.to_s + @@fudge.to_s
    @@fudge+=1
    update_name += ".update.validation-test-servers.nominet.org.uk"
    return update_name
  end

  def run_test_resolver_signs
    res = Dnsruby::Resolver.new("ns0.validation-test-servers.nominet.org.uk")
    res.query_timeout=20
    res.tsig=KEY_NAME, KEY

    update = Dnsruby::Update.new("validation-test-servers.nominet.org.uk")
    #  Generate update record name, and test it has been made. Then delete it and check it has been deleted
    update_name = generate_update_name
    update.absent(update_name)
    update.add(update_name, 'TXT', 100, "test signed update")
    assert(!update.signed?, "Update has been signed")

    response = res.send_message(update)

    assert_equal( Dnsruby::RCode.NOERROR, response.rcode)
    assert(response.verified?, "Response has not been verified")

    #  Now check the record exists
    rr = res.query(update_name, 'TXT')
    assert_equal("test signed update", rr.answer()[0].strings.join(" "), "TXT record has not been created in zone")

    #  Now delete the record
    update = Dnsruby::Update.new("validation-test-servers.nominet.org.uk")
    update.present(update_name, 'TXT')
    update.delete(update_name)
    tsig = Dnsruby::RR.create({
        :type => 'TSIG', :klass => 'ANY',
        :name        => KEY_NAME,
        :key         => KEY
      })
    tsig.apply(update)
    assert(update.signed?, "Update has not been signed")
    res.dnssec=false # Or else we needed to add OPT record already
    res.udp_size = 512
    response = res.send_message(update)
    assert_equal( Dnsruby::RCode.NOERROR, response.rcode)
    assert(response.verified?, "Response has not been verified")

    #  Now check the record does not exist
    Dnsruby::PacketSender.clear_caches
    #  Make sure the cache doesn't have an old copy!
    begin
      rr = res.query(update_name, 'TXT')
      assert(false)
    rescue Dnsruby::NXDomain
    end
  end

  def test_message_signing
    m = Dnsruby::Message.new("example.com")
    m.set_tsig("name", "key")
    assert(!m.signed?)
    m.encode
    assert(m.signed?)

    m = Dnsruby::Message.new("example.com")
    m.set_tsig("name", "key")
    assert(!m.signed?)
    m.sign!
    assert(m.signed?)

    m = Dnsruby::Message.new("example.com")
    assert(!m.signed?)
    m.sign!("name", "key")
    assert(m.signed?)
  end

  def test_signed_zone_transfer
    #  test TSIG over TCP session
    axfr
    ixfr
  end

  def axfr
    zt = Dnsruby::ZoneTransfer.new
    zt.transfer_type = Dnsruby::Types.AXFR
    zt.tsig=KEY_NAME, KEY
    zt.server = "ns0.validation-test-servers.nominet.org.uk"
    zone = zt.transfer("validation-test-servers.nominet.org.uk")
    assert(zone.length > 0)
    assert(zt.last_tsigstate==:Verified)
  end

  #  We also test IXFR here - this is because we need to update a record (using
  #  TSIG) before we can test ixfr...
  def ixfr
    #  Check the SOA serial, do an update, check that the IXFR for that soa serial gives us the update we did,
    #  then delete the updated record
    start_soa_serial = get_soa_serial("validation-test-servers.nominet.org.uk")

    #  Now do an update
    res = Dnsruby::Resolver.new("ns0.validation-test-servers.nominet.org.uk")
    res.query_timeout=10
    res.tsig=KEY_NAME, KEY

    update = Dnsruby::Update.new("validation-test-servers.nominet.org.uk")
    #  Generate update record name, and test it has been made. Then delete it and check it has been deleted
    update_name = Time.now.to_i.to_s + rand(100).to_s + ".update.validation-test-servers.nominet.org.uk"
    update.absent(update_name)
    update.add(update_name, 'TXT', 100, "test zone transfer")
    assert(!update.signed?, "Update has been signed")

    response = res.send_message(update)
    assert(response.rcode == Dnsruby::RCode.NOERROR)

    end_soa_serial = get_soa_serial("validation-test-servers.nominet.org.uk")

    zt = Dnsruby::ZoneTransfer.new
    zt.transfer_type = Dnsruby::Types.IXFR
    zt.server = "ns0.validation-test-servers.nominet.org.uk"
    zt.serial = start_soa_serial # 2007090401
    deltas = zt.transfer("validation-test-servers.nominet.org.uk")
    assert(deltas.length > 0)
    assert(deltas.last.class == Dnsruby::ZoneTransfer::Delta)
    assert_equal("test zone transfer", deltas.last.adds.last.strings.join(" "))
    assert(zt.last_tsigstate==nil)

    #  Now delete the updated record
    update = Dnsruby::Update.new("validation-test-servers.nominet.org.uk")
    update.present(update_name, 'TXT')
    update.delete(update_name)
    response = res.send_message(update)
    assert_equal( Dnsruby::RCode.NOERROR, response.rcode)
  end

  def get_soa_serial(name)
    soa_serial = nil
    Dnsruby::DNS.open {|dns|
      soa_rr = dns.getresource(name, 'SOA')
      soa_serial = soa_rr.serial
    }
    return soa_serial
  end

  def test_bad_tsig
    res = Resolver.new
    res.query_timeout=10
    res.tsig=KEY_NAME, KEY
    begin
      ret = res.query("example.com")
      assert(false, "Should not have got TSIG response from non-TSIG server!\n #{ret}\n")
    rescue TsigError => e
    end
  end
end
