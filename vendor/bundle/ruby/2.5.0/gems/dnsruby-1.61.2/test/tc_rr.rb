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

class TestRR < Minitest::Test

  include Dnsruby

  def test_rr
    # ------------------------------------------------------------------------------
    #  Canned data.
    # ------------------------------------------------------------------------------

    name			= "foo.example.com";
    klass			= "IN";
    ttl				= 43200;

    rrs = [
    {  	#[0]
      :type        => Types.A,
      :address     => '10.0.0.1',
    },
    {	#[1]
      :type      => Types::AAAA,
      :address     => '102:304:506:708:90a:b0c:d0e:ff10',
    },
    {	#[2]
      :type         => 'AFSDB',
      :subtype      => 1,
      :hostname     => 'afsdb-hostname.example.com',
    },
    {	#[3]
      :type         => Types.CNAME,
      :domainname        => 'cname-cname.example.com',
    },
    {   #[4]
      :type         => Types.DNAME,
      :domainname        => 'dname.example.com',
    },
    {	#[5]
      :type         => Types.HINFO,
      :cpu          => 'test-cpu',
      :os           => 'test-os',
    },
    {	#[6]
      :type         => Types.ISDN,
      :address      => '987654321',
      :subaddress           => '001',
    },
    {	#[7]
      :type         => Types.MB,
      :domainname      => 'mb-madname.example.com',
    },
    {	#[8]
      :type         => Types.MG,
      :domainname   => 'mg-mgmname.example.com',
    },
    {	#[9]
      :type         => Types.MINFO,
      :rmailbx      => 'minfo-rmailbx.example.com',
      :emailbx      => 'minfo-emailbx.example.com',
    },
    {	#[10]
      :type         => Types.MR,
      :domainname      => 'mr-newname.example.com',
    },
    {	#[11]
      :type         => Types.MX,
      :preference   => 10,
      :exchange     => 'mx-exchange.example.com',
    },
    {	#[12]
      :type        => Types.NAPTR,
      :order        => 100,
      :preference   => 10,
      :flags        => 'naptr-flags',
      :service      => 'naptr-service',
      :regexp       => 'naptr-regexp',
      :replacement  => 'naptr-replacement.example.com',
    },
    {	#[13]
      :type         => Types.NS,
      :domainname      => 'ns-nsdname.example.com',
    },
    {	#[14]
      :type         => Types.NSAP,
      :afi          => '47',
      :idi          => '0005',
      :dfi          => '80',
      :aa           => '005a00',
      :rd           => '1000',
      :area         => '0020',
      :id           => '00800a123456',
      :sel          => '00',
      #       #:address => '4700580005a001000002000800a12345600'
      #       :address => '47000580005a0000001000002000800a12345600'
    },
    {	#[15]
      :type         => Types.PTR,
      :domainname     => 'ptr-ptrdname.example.com',
    },
    {	#[16]
      :type         => Types.PX,
      :preference   => 10,
      :map822       => 'px-map822.example.com',
      :mapx400      => 'px-mapx400.example.com',
    },
    {	#[17]
      :type         => Types.RP,
      :mailbox		 => 'rp-mbox.example.com',
      :txtdomain     => 'rp-txtdname.example.com',
    },
    {	#[18]
      :type         => Types.RT,
      :preference   => 10,
      :intermediate => 'rt-intermediate.example.com',
    },
    {	#[19]
      :type         => Types.SOA,
      :mname        => 'soa-mname.example.com',
      :rname        => 'soa-rname.example.com',
      :serial       => 12345,
      :refresh      => 7200,
      :retry        => 3600,
      :expire       => 2592000,
      :minimum      => 86400,
    },
    {	#[20]
      :type         => Types.SRV,
      :priority     => 1,
      :weight       => 2,
      :port         => 3,
      :target       => 'srv-target.example.com',
    },
    {	#[21]
      :type         => Types.TXT,
      :strings => 'txt-txtdata',
    },
    {	#[22]
      :type         => Types.X25,
      :address      => '123456789',
    },
    {	#[23]
      :type        => Types.LOC,
      :version      => 0,
      :size         => 3000,
      :horiz_pre    => 500000,
      :vert_pre     => 500,
      :latitude     => 2001683648,
      :longitude    => 1856783648,
      :altitude     => 9997600,
    }, 	#[24]
    {
      :type         => Types.CERT,
      :certtype   => 3,
      :keytag			 => 1,
      :alg    => 1,
      :cert  => 'ffsayw1dvk7higuvhn56r26uwjx/',
    },
    {	#[25]
      :type         => Types.SPF,
      :strings      => 'txt-txtdata',
    },
        {
      :type         => Types.KX,
      :preference   => 10,
      :exchange     => 'kx-exchange.example.com',
    },
    {	# [26]
      :type         => Types.APL,
      :prefixes     => '1:10.0.0.0/8 !1:172.16.0.0/12 1:192.168.0.0/16 !1:192.168.0.0/24',
    },
    {	# [27]
      :type         => Types.APL,
      :prefixes     => '!2:fe80::/10 2:2001:db8::/32 2:2001:db8::/64',
    },
    {	# [28]
      :type         => Types.APL,
      :prefixes     => '1:0.0.0.0/0 1:255.255.255.255/32 2:::/0 2:::1/128',
    }
    ]


    # ------------------------------------------------------------------------------
    #  Create the packet
    # ------------------------------------------------------------------------------

    message = Message.new
    assert(message,         'Message created');


    rrs.each do |data|
      data.update({	   :name => name,
        :ttl  => ttl,
      })
      rr=RR.create(data)

      message.add_answer(rr);
    end

    # ------------------------------------------------------------------------------
    #  Re-create the packet from data.
    # ------------------------------------------------------------------------------
    data = message.encode;
    assert(data,            'Packet has data after pushes');

    message=nil;
    message= Message.decode(data);

    assert(message,          'Packet reconstructed from data');

    answer = message.answer;

    i = 0
    rrs.each do |rec|
      ret_rr = answer[i]
      i += 1
      rec.each do |key, value|
        #         method = key+'=?'
        x = ret_rr.send(key)
        if (ret_rr.kind_of?RR::CERT and (key == :alg or key == :certtype))
          assert_equal(value.to_s, x.code.to_s.downcase, "Packet returned wrong answer section for #{ret_rr.to_s}, #{key}")
        elsif (ret_rr.kind_of?RR::TXT and (key == :strings))
          assert_equal(value.to_s.downcase, x[0].to_s.downcase, "TXT strings wrong")
        else
          if (key == :type)
            assert_equal(Types.new(value).to_s.downcase, x.to_s.downcase, "Packet returned wrong answer section for #{ret_rr.to_s}, #{key}")
          else
            assert_equal(value.to_s.downcase, x.to_s.downcase, "Packet returned wrong answer section for #{ret_rr.to_s}, #{key}")
          end
        end
      end
    end



    while (!answer.empty? and !rrs.empty?)
      data = rrs.shift;
      rr   = answer.shift;
      type = data[:type];

      assert(rr,                         "#{type} - RR defined");
      assert_equal(name,       	rr.name.to_s,    "#{type} - name() correct");
      assert_equal(klass,      	rr.klass.to_s,   "#{type} - class() correct");
      assert_equal(ttl,        	rr.ttl,     "#{type} - ttl() correct");

      # 	foreach my $meth (keys %{data}) {
      data.keys.each do |meth|
        ret = rr.send(meth)
        if (rr.kind_of?RR::CERT and (meth == :alg or meth == :certtype))
          assert_equal(data[meth].to_s, ret.code.to_s.downcase, "#{type} - #{meth}() correct")
        elsif (rr.kind_of?RR::TXT and (meth == :strings))
          assert_equal(data[meth].to_s, ret[0].to_s.downcase, "TXT strings wrong")
        else
          if (meth == :type)
            assert_equal(Types.new(data[meth]).to_s.downcase, ret.to_s.downcase, "#{type} - #{meth}() correct");
          else
            assert_equal(data[meth].to_s, ret.to_s.downcase, "#{type} - #{meth}() correct");
          end
        end
      end

      rr2 = RR.new_from_string(rr.to_s)
      assert_equal(rr.to_s,   rr2.to_s, "#{type} - Parsing from string works")
    end
  end

  def test_naptr
    update = Update.new
    update.add('example.com.','NAPTR', 3600, '1 0 "s" "SIP+D2T" "" _sip._tcp.example.com.')
    update.encode
  end

  def test_uri
    rrString = "_ftp._tcp.\t300\tIN\tURI\t10\ 1 \"ftp://ftp1.example.com/public\""
    rr = RR.create(rrString)
    assert(rrString.to_s == rr.to_s)
    m = Dnsruby::Message.new
    m.add_additional(rr)
    m2 = Message.decode(m.encode)
    rr2 = m2.additional()[0]
    assert(rr == rr2)
  end

  def test_cds
    rrString = "dskey.example.com.\t86400\tIN\tCDS\t60485 RSASHA1 1 ( 2BB183AF5F22588179A53B0A98631FAD1A292118 )"
    rr = RR.create(rrString)
    assert(rrString.to_s == rr.to_s)
    m = Dnsruby::Message.new
    m.add_additional(rr)
    m2 = Message.decode(m.encode)
    rr2 = m2.additional()[0]
    assert(rr.to_s == rr2.to_s)
  end

  def test_cdnskey
    rrString = "tjeb.nl.\t3600\tIN\tCDNSKEY\t256 3 RSASHA1-NSEC3-SHA1 ( AwEAAcglEOS7bECRK5fqTuGTMJycmDhTzmUu/EQbAhKJOYJxDb5SG/RYqsJgzG7wgtGy0W1aP7I4k6SPtHmwcqjLaZLVUwRNWCGr2adjb9JTFyBR7F99Ngi11lEGM6Uiw/eDRk66lhoSGzohjj/rmhRTV6gN2+0ADPnafv3MBkPgryA3 ) ; key_tag=53177"
    rr = RR.create(rrString)
    assert(rrString.to_s == rr.to_s)
    m = Dnsruby::Message.new
    m.add_additional(rr)
    m2 = Message.decode(m.encode)
    rr2 = m2.additional()[0]
    assert(rr.to_s == rr2.to_s)
  end

  def test_cert
    rr = RR.create("test.kht.se. 60 IN CERT PGP 0 0 mQGiBDnY2vERBAD3cOxqoAYHYzS+xttvuyN9wZS8CrgwLIlT8Ewo/CCFI11PEO+gJyNPvWPRQsyt1SE60reaIsie2bQTg3DYIg0PmH+ZOlNkpKesPULzdlw4Rx3dD/M3Lkrm977h4Y70ZKC+tbvoYKCCOIkUVevny1PVZ+mB94rb0mMgawSTrct03QCg/w6aHNJFQV7O9ZQ1Fir85M3RS8cEAOo4/1ASVudz3qKZQEhU2Z9O2ydXqpEanHfGirjWYi5RelVsQ9IfBSPFaPAWzQ24nvQ18NU7TgdDQhP4meZXiVXcLBR5Mee2kByf2KAnBUF9aah5s8wZbSrC6u8xEZLuiauvWmCUIWe0Ylc1/L37XeDjrBI2pT+k183X119d6Fr1BACGfZVGsot5rxBUEFPPSrBqYXG/0hRYv9Eq8a4rJAHK2IUWYfivZgL4DtrJnHlha+H5EPQVYkIAN3nGjXoHmosY+J3Sk+GyR+dCBHEwCkoHMKph3igczCEfxAWgqKeYd5mf+QQq2JKrkn2jceiIO7s3CrepeEFAjDSGuxhZjPJVm7QoRGFuaWVsIFAuIE1haG9uZXkgPGRhbm1AcHJpbWUuZ3VzaGkub3JnPohOBBARAgAOBQI52NrxBAsDAQICGQEACgkQ+75aMGJLskn6LgCbBXUD7UmGla5e1zyhuY667hP3F+UAoJIeDZJyRFkQAmb+u8KekRyLD1MLtDJEYW5pZWwgTWFob25leSAoU2Vjb25kYXJ5IEVtYWlsKSA8Z3VzaGlAZ3VzaGkub3JnPohgBBMRAgAgBQJF1J/XAhsjBgsJCAcDAgQVAggDBBYCAwECHgECF4AACgkQ+75aMGJLskkVhACggsivQ9qLhfdA1rGm6f8LRJBSC4wAoI930h+/hshClj6AkNwGRtHdf5XJuQINBDnY2vQQCAD2Qle3CH8IF3KiutapQvMF6PlTETlPtvFuuUs4INoBp1ajFOmPQFXz0AfGy0OplK33TGSGSfgMg71l6RfUodNQ+PVZX9x2Uk89PY3bzpnhV5JZzf24rnRPxfx2vIPFRzBhznzJZv8V+bv9kV7HAarTW56NoKVyOtQa8L9GAFgr5fSI/VhOSdvNILSd5JEHNmszbDgNRR0PfIizHHxbLY7288kjwEPwpVsYjY67VYy4XTjTNP18F1dDox0YbN4zISy1Kv884bEpQBgRjXyEpwpy1obEAxnIByl6ypUM2Zafq9AKUJsCRtMIPWakXUGfnHy9iUsiGSa6q6Jew1XpMgs7AAICB/9eGjzF2gDh6U7I72x/6bSdlExx2LvIF92OZKc0S55IOS4Lgzs7Hbfm1aOL4oJt7wBg94xkF4cerxz7y8R9J+k3GNl14KOjbYaMAh1rdxdAzikYMH1p1hS78GMtwxky6jE5en87BGGMmnbC84JlxwN+MD7diu8D0Gkgjj/pxOp32D5jEe02wBPVjFTpFLJjpFniLUY6AohRDEdSuZwWPuoKVWhpeWkasNn5qgwGyDREbXpyPsU02BkwE4JiGs+JMMdOn9KMh5dxiuwsMM9gHiQZS3mSNBBKPWI5ZXsdStVFvapjf2FUFDXLUbTROPv1Xhqf0u7YYORFnWeVtvzKIxVaiEYEGBECAAYFAjnY2vQACgkQ+75aMGJLsklBWgCeN7z9xk52y/aoaCuF6hYb0d+3k98AoMRxvHuXI1Nc2FXY/x65PwHiUbaY")
    rr = RR.create("all.rr.org.             IN      CERT            6 0 0 FFsAyW1dVK7hIGuvhN56r26UwJx/")
#    rr = RR.create("all.rr.org.             IN      WKS             128.32.0.10 UDP who route timed domain")
    rr = RR.create('selector._domainkey.all.rr.org. IN      TXT             "v=DKIM1; n=Use=20DKIM; p=AwEAAZfbYw8SffZwsbrCLbC+JLErREIF6Yfe9aqsa1Pz6tpGWiLxm9rSL6/YoBvNP3UWX91YDF0JMo6lhu3UIZjITvIwDhx+RJYko9vLzaaJKXGf3ygy6z+deWoZJAV1lTY0Ltx9genboe88CSCHw9aSLkh0obN9Ck8R6zAMYR19ciM/; t=s"')
  end

  def test_dhcid
    rr = RR.create("all.rr.org.		IN	DHCID		AAIBY2/AuCccgoJbsaxcQc9TUapptP69lOjxfNuVAA2kjEA=")
      m = Dnsruby::Message.new
      m.add_additional(rr)
      data = m.encode
      m2 = Dnsruby::Message.decode(data)
      rr2 = m2.additional()[0]
      assert(rr == rr2)
  end

  def test_loc
    rr = RR.create("all.rr.org.		IN	LOC		42 21 54 N 71 06 18 W -24m 30m")
    assert(rr.vert_pre == 1000)
    assert(rr.horiz_pre == 1000000)
    assert(rr.to_s.index("21"))
    assert(rr.to_s.index("71"))
    assert(rr.to_s.index("54"))
    assert(rr.to_s.index("71"))
    assert(rr.to_s.index("06"))
    assert(rr.to_s.index("18"))

    r2 = RR.create("helium				IN LOC	51 49 17.9 N 4 39 22.9 E 0m")
    assert(r2.size == 100)
    assert(r2.to_s.index("17.9"))
    assert(r2.to_s.index("22.9"))
  end

  def test_hinfo
    rr = RR.create('helium				IN HINFO	"Shuttle-ST61G4 Intel PIV3000" "FreeBSD 7.0-STABLE"')
    assert rr.to_s.index('"Shuttle-ST61G4 Intel PIV3000"')
    assert rr.to_s.index('"FreeBSD 7.0-STABLE"')
  end

  def test_private_method_really_private
    begin
      RR._get_subclass(nil, nil, nil, nil, nil)
      raise "This should not have gotten here; the method should have been private"
    rescue NoMethodError
      # We should be here because the method should not have been found.
    end
  end

  # TTL should be ignored when calculating the hash of an RR.
  def test_hash_ignores_ttl
    a1 = RR.new_from_string 'techhumans.com. 1111 IN A 69.89.31.97'
    a2 = RR.new_from_string 'techhumans.com. 1111 IN A 69.89.31.97'
    a3 = RR.new_from_string 'techhumans.com. 2222 IN A 69.89.31.97'
    assert_equal a1.hash, a2.hash
    assert_equal a1.hash, a3.hash
  end

  def _test_duplicate_answer(method_as_symbol)
    expected_count = case method_as_symbol
    when :add_answer
      1
    when :add_answer!
      2
    end

    rr = RR.new_from_string 'techhumans.com. 1111 IN A 69.89.31.97'
    message = Message.new
    2.times { message.send(method_as_symbol, rr) }
    assert_equal(expected_count, message.header.ancount)
  end

  def test_add_dup_answer_no_force
    _test_duplicate_answer(:add_answer)
  end

  def test_add_dup_answer_force
    _test_duplicate_answer(:add_answer!)
  end
end
