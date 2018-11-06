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

class TestUpdate < Minitest::Test

  include Dnsruby

  def is_empty(string)
    return true if string == nil || string.length == 0

    return (string == "; no data" || string == "; rdlength = 0");
  end

  def test_update
    # ------------------------------------------------------------------------------
    #  Canned data.
    # ------------------------------------------------------------------------------

    zone	= "example.com";
    name	= "foo.example.com";
    klass	= Classes.CLASS32;
    klass2  = Classes.CH;
    type	= Types.A;
    ttl	    = 43200;
    rdata	= "10.1.2.3";
    rr      = nil;

    # ------------------------------------------------------------------------------
    #  Packet creation.
    # ------------------------------------------------------------------------------

    update = Dnsruby::Update.new(zone, klass);
    z = (update.zone)[0];

    assert(update,                                'new() returned packet');  #2
    assert_equal(update.header.opcode, OpCode.UPDATE,      'header opcode correct');  #3
    assert_equal(z.zname.to_s,  zone,                      'zname correct');          #4
    assert_equal(z.zclass.to_s, klass.to_s,                     'zclass correct');         #5
    assert_equal(z.ztype,  Types.SOA,                      'ztype correct');          #6

    # ------------------------------------------------------------------------------
    #  RRset exists (value-independent).
    # ------------------------------------------------------------------------------

    rr = update.present(name, type);

    assert(rr,                                    'yxrrset() returned RR');  #7
    assert_equal(name,                      rr.name.to_s,  'yxrrset - right name');   #8
    assert_equal(0,                          rr.ttl,   'yxrrset - right TTL');    #9
    assert_equal('ANY',                      rr.klass.string, 'yxrrset - right class');  #10
    assert_equal(type,                      rr.type,  'yxrrset - right type');   #11
    assert(is_empty(rr.rdata),                "yxrrset - data empty (#{rr.rdata})");   #12

    rr = nil

    # ------------------------------------------------------------------------------
    #  RRset exists (value-dependent).
    # ------------------------------------------------------------------------------

    rr = update.present(name, type, rdata, klass);

    assert(rr,                                    'yxrrset() returned RR');  #13
    assert_equal(name,                   rr.name.to_s,     'yxrrset - right name');   #14
    assert_equal(0,                       rr.ttl,      'yxrrset - right TTL');    #15
    assert_equal(klass,                  rr.klass.string,    'yxrrset - right class');  #16
    assert_equal(type,                   rr.type,     'yxrrset - right type');   #17
    assert_equal(rdata,                  rr.rdata, 'yxrrset - right data');   #18

    rr=nil

    # ------------------------------------------------------------------------------
    #  RRset does not exist.
    # ------------------------------------------------------------------------------

    rr = update.absent(name, type);

    assert(rr,                                    'nxrrset() returned RR');  #19
    assert_equal(name,                      rr.name.to_s,  'nxrrset - right name');   #20
    assert_equal(0,                          rr.ttl,   'nxrrset - right ttl');    #21
    assert_equal('NONE',                     rr.klass.string, 'nxrrset - right class');  #22
    assert_equal(type,                      rr.type,  'nxrrset - right type');   #23
    assert(is_empty(rr.rdata),                'nxrrset - data empty');   #24

    rr = nil

    # ------------------------------------------------------------------------------
    #  Name is in use.
    # ------------------------------------------------------------------------------

    rr = update.present(name);

    assert(rr,                                    'yxdomain() returned RR'); #25
    assert_equal(rr.name.to_s,  name,                      'yxdomain - right name');  #26
    assert_equal(rr.ttl,   0,                          'yxdomain - right ttl');   #27
    assert_equal(rr.klass.string, 'ANY',                      'yxdomain - right class'); #28
    assert_equal(rr.type.string,  'ANY',                      'yxdomain - right type');  #29
    assert(is_empty(rr.rdata),                'yxdomain - data empty');  #30

    rr = nil

    # ------------------------------------------------------------------------------
    #  Name is not in use. (No Class)
    # ------------------------------------------------------------------------------

    rr = update.absent(name);

    assert(rr,                                    'nxdomain() returned RR'); #31
    assert_equal(rr.name.to_s,  name,                      'nxdomain - right name');  #32
    assert_equal(rr.ttl,   0,                          'nxdomain - right ttl');   #33
    assert_equal(rr.klass.string, 'NONE',                     'nxdomain - right class'); #34
    assert_equal(rr.type.string,  'ANY',                      'nxdomain - right type');  #35
    assert(is_empty(rr.rdata),                'nxdomain - data empty');  #36

    rr = nil



    # ------------------------------------------------------------------------------
    #  Add to an RRset.
    # ------------------------------------------------------------------------------

    rr = update.add(name, type, ttl, rdata);

    assert(rr,                                    'rr_add() returned RR');   #37
    assert_equal(rr.name.to_s,     name,                   'rr_add - right name');    #38
    assert_equal(rr.ttl,      ttl,                    'rr_add - right ttl');     #39
    assert_equal(rr.klass,    klass,                  'rr_add - right class');   #40
    assert_equal(rr.type,     type,                   'rr_add - right type');    #41
    assert_equal(rr.rdata, rdata,                  'rr_add - right data');    #42

    rr = nil

    # ------------------------------------------------------------------------------
    #  Delete an RRset.
    # ------------------------------------------------------------------------------

    rr = update.delete(name, type);

    assert(rr,                                    'rr_del() returned RR');   #43
    assert_equal(name,                      rr.name.to_s,  'rr_del - right name');    #44
    assert_equal(0,                          rr.ttl,   'rr_del - right ttl');     #45
    assert_equal('ANY',                      rr.klass.string, 'rr_del - right class');   #46
    assert_equal(type,                      rr.type,  'rr_del - right type');    #47
    assert(is_empty(rr.rdata),                'rr_del - data empty');    #48

    rr = nil

    # ------------------------------------------------------------------------------
    #  Delete All RRsets From A Name.
    # ------------------------------------------------------------------------------

    rr = update.delete(name);

    assert(rr,                                    'rr_del() returned RR');   #49
    assert_equal(name,                      rr.name.to_s,  'rr_del - right name');    #50
    assert_equal(0,                          rr.ttl,   'rr_del - right ttl');     #51
    assert_equal(Classes.ANY,                      rr.klass, 'rr_del - right class');   #52
    assert_equal(Classes.ANY,                      rr.type,  'rr_del - right type');    #53
    assert(is_empty(rr.rdata),                'rr_del - data empty');    #54

    rr = nil

    # ------------------------------------------------------------------------------
    #  Delete An RR From An RRset.
    # ------------------------------------------------------------------------------

    rr = update.delete(name, type, rdata);

    assert(rr,                                    'rr_del() returned RR');   #55
    assert_equal(name,                   rr.name.to_s,     'rr_del - right name');    #56
    assert_equal(0,                       rr.ttl,      'rr_del - right ttl');     #57
    assert_equal('NONE',                  rr.klass.string,    'rr_del - right class');   #58
    assert_equal(type,                   rr.type,     'rr_del - right type');    #59
    assert_equal(rdata,                  rr.rdata, 'rr_del - right data');    #60

    rr = nil

    data = update.encode
    header = Header.new_from_data(data)
    assert(header.opcode == OpCode.Update)
    new_update = Message.decode(data)
    assert(new_update.header.opcode == OpCode.Update)

    # ------------------------------------------------------------------------------
    #  Make sure RRs in an update packet have the same class as the zone, unless
    #  the class is NONE or ANY.
    # ------------------------------------------------------------------------------

    update = Dnsruby::Update.new(zone, klass);
    assert(update,                               'packet created');          #61


    update.present(name, type, rdata);

    update.present(name, type, rdata);

    update.present(name, type);

    update.absent(name, type);

    pre = update.pre;

    assert_equal(3,                     pre.size, 'pushed inserted correctly'); #62
    assert_equal(klass,              pre[0].klass.string, 'first class right');         #63
    assert_equal(Classes.ANY,               pre[1].klass, 'third class right');         #65
    assert_equal(Classes.NONE,              pre[2].klass, 'forth class right');         #66
  end

  def test_absent_cname
    update = Update.new()
    rr = update.absent("target_name", "CNAME")
    assert(rr,                                    'nxdomain() returned RR');
    assert_equal(rr.name.to_s,  "target_name",                      'nxdomain - right name');
    assert_equal(rr.ttl,   0,                          'nxdomain - right ttl');
    assert_equal(rr.klass.string, 'NONE',                     'nxdomain - right class');
    assert_equal(rr.type.string,  'CNAME',                      'nxdomain - right type');
    assert(is_empty(rr.rdata),                'nxdomain - data empty');

    encoded_msg = Message.decode(update.encode)
    rr = encoded_msg.answer.first
    assert(rr,                                    'nxdomain() returned RR')
    assert_equal(rr.name.to_s,  "target_name",                      'nxdomain - right name')
    assert_equal(rr.ttl,   0,                          'nxdomain - right ttl')
    assert_equal(rr.klass.string, 'NONE',                     'nxdomain - right class')
    assert_equal(rr.type.string,  'CNAME',                      'nxdomain - right type')
    # assert_nil(rr.rdata, 'nxdomain - data empty')
    assert(is_empty(rr.rdata), 'nxdomain - data empty')
  end

  def test_delete_specific_cname
    update = Update.new 'example.com'
    update.delete 'test.example.com', 'CNAME', 'target.example.com'

    encoded_msg = Message.decode update.encode
    rr = encoded_msg.authority.first
    assert_equal rr.name.to_s, 'test.example.com', 'delete_cname - right name'
    assert_equal 0, rr.ttl, 'delete_cname - right ttl'
    assert_equal 'NONE', rr.klass.string, 'delete_cname - right class'
    assert_equal 'CNAME', rr.type.string, 'delete_cname - right type'
    assert_equal 'target.example.com', rr.rdata.to_s, 'delete_cname - right target'
  end

  def test_delete_cname
    update = Update.new 'example.com'
    update.delete 'test.example.com', 'CNAME'

    encoded_msg = Message.decode update.encode
    rr = encoded_msg.authority.first
    assert_equal rr.name.to_s, 'test.example.com', 'delete_cname - right name'
    assert_equal 0, rr.ttl, 'delete_cname - right ttl'
    assert_equal 'ANY', rr.klass.string, 'delete_cname - right class'
    assert_equal 'CNAME', rr.type.string, 'delete_cname - right type'
    assert(is_empty(rr.rdata), 'delete_cname - right rdata')
  end

  def test_txt
    update = Update.new()
    update.add("target_name", "TXT", 100, "test signed update")
    assert(update.to_s.index("test signed update"))
  end

  def test_delete_txt
    update = Update.new 'example.com'
    update.delete 'test.example.com', 'TXT', 'foo bar'

    encoded_msg = Message.decode update.encode
    rr = encoded_msg.authority.first
    assert_equal rr.name.to_s, 'test.example.com', 'delete_txt - right name'
    assert_equal 0, rr.ttl, 'delete_txt - right ttl'
    assert_equal 'TXT', rr.type.string, 'delete_txt - right type'
    assert_equal ['foo bar'], rr.rdata, 'delete_txt - right rdata'
  end

  def test_array
    update = Update.new
    update.add("target_name", "TXT", 100, ['"test signed update"', 'item#2'])
    assert(update.to_s.index("item"))
  end
end
