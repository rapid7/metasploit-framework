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

class DnskeyTest < Minitest::Test
  INPUT = "example.com. 86400 IN DNSKEY 256 3 5 ( AQPSKmynfzW4kyBv015MUG2DeIQ3" +
    "Cbl+BBZH4b/0PY1kxkmvHjcZc8no" +
    "kfzj31GajIQKY+5CptLr3buXA10h" +
    "WqTkF7H6RfoRqXQeogmMHfpftf6z" +
    "Mv1LyBUgia7za6ZEzOJBOztyvhjL" +
    "742iU/TpPSEDhm2SNKLijfUppn1U" +
    "aNvv4w==  )"
  BADINPUT = "example.com. 86400 IN DNSKEY 384 3 5 ( AQPSKmynfzW4kyBv015MUG2DeIQ3" +
    "Cbl+BBZH4b/0PY1kxkmvHjcZc8no" +
    "kfzj31GajIQKY+5CptLr3buXA10h" +
    "WqTkF7H6RfoRqXQeogmMHfpftf6z" +
    "Mv1LyBUgia7za6ZEzOJBOztyvhjL" +
    "742iU/TpPSEDhm2SNKLijfUppn1U" +
    "aNvv4w==  )"
  #   def test_bad_flag
  #     dnskey = Dnsruby::RR.create(BADINPUT)
  #     assert_equal(384, dnskey.flags)
  #     assert(dnskey.bad_flags?)
  #   end
  def test_dnskey_from_string
    dnskey = Dnsruby::RR.create(INPUT)
    #     assert(!dnskey.bad_flags?)
    assert_equal(3, dnskey.protocol)
    assert_equal(256, dnskey.flags)
    assert_equal(Dnsruby::Algorithms::RSASHA1, dnskey.algorithm)
    assert_equal(Dnsruby::RR::DNSKEY::ZONE_KEY, dnskey.flags & Dnsruby::RR::DNSKEY::ZONE_KEY)
    assert_equal(0, dnskey.flags & Dnsruby::RR::DNSKEY::SEP_KEY)

    dnskey2 = Dnsruby::RR.create(dnskey.to_s)
    assert(dnskey2.to_s == dnskey.to_s, "#{dnskey.to_s} not equal to \n#{dnskey2.to_s}")
  end

  def test_from_string_with_comments
    k = Dnsruby::RR.create("tjeb.nl.		 3600		 IN		 DNSKEY		 256 3 7 AwEAAcglEOS7bECRK5fqTuGTMJycmDhTzmUu/EQbAhKJOYJxDb5SG/RYqsJgzG7wgtGy0W1aP7I4k6SPtHmwcqjLaZLVUwRNWCGr2adjb9JTFyBR7F99Ngi11lEGM6Uiw/eDRk66lhoSGzohjj/rmhRTV6gN2+0ADPnafv3MBkPgryA3 ;{id = 53177 (zsk), size = 1024b}")
    assert_equal(53177, k.key_tag)
  end

  def test_dnskey_from_data
    dnskey = Dnsruby::RR.create(INPUT)
    m = Dnsruby::Message.new
    m.add_additional(dnskey)
    data = m.encode
    m2 = Dnsruby::Message.decode(data)
    dnskey3 = m2.additional()[0]
    assert_equal(dnskey.to_s, dnskey3.to_s)
  end

  def test_bad_values
    dnskey = Dnsruby::RR.create(INPUT)
    begin
      dnskey.protocol=4
      fail()
    rescue Dnsruby::DecodeError
    end
    dnskey.flags=4
    assert_equal(4, dnskey.flags)
    assert(dnskey.flags == 4)
    dnskey.flags=256
    assert_equal(256, dnskey.flags)
#    assert(!dnskey.bad_flags?)
    dnskey.flags=257
    assert_equal(257, dnskey.flags)
#    assert(!dnskey.bad_flags?)
    dnskey.flags=1
    assert_equal(1, dnskey.flags)
    dnskey.protocol=3

  end
end