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

class TestEscapedChars < Minitest::Test

  include Dnsruby

  def test_one
    Name::Label.set_max_length(150)
    # 
    #  We test al sorts of escaped non-ascii characters.
    #  This is all to be protocol conform... so to speak.

    # 
    #  The collection of tests is somewhat of a hodgepodge that tried to
    #  assess sensitivity to combinations of characters that the regular
    #  expressions and perl itself are sensitive to. (like \\\\\.\..)
    #  Development versions of the code tried to split a domain name in
    #  invidual labels by a regular expression. It made no sense to remove
    #  the more ackward tests as they have to pass anyway ...


    #  Note that in perl the \\ in a presentation format can only be achieved
    #  through \\\\ .

    #  The hex codes are the names in wireformat:
    #  length octet. content octets, length octet, content , NULL octet


    #  Below are test combos, 1st and 2nd array elements are
    #  representations of the name. The output of the perl functions should
    #  yield the 2nd presentation (eg \037 gets presented as % )

    #  The 3rd element is a label count.
    #  The 4th element represents the number of octets per label
    #  The 5th element is a hexdump of the domain name in wireformat

    testcombos=[
    ['bla.fo\.o.org',
	 'bla.fo\.o.org',
    3,
    [3,4,3],
    # Wire:            3 b l a 4 f o . o 3 o r g 0
	 "03626c6104666f2e6f036f726700"
    ],

    [
	 'bla\255.foo.org',
	 'bla\255.foo.org',
    3,
    [4,3,3],
    # Wire:            4 b l a 0xff 3 f o o 3 o r g 0
	 "04626c61ff03666f6f036f726700"
    ],

    [
	 'bla.f\xa9oo.org',
	 'bla.f\169oo.org',
    3,
    [3,4,3] ,
    # Wire:            3 b l a 4 f 0xa9 o o 3 o r g 0
	 "03626c610466a96f6f036f726700"
    ],   # Note hex to decimal
    ['bla.fo\.o.org',
	 'bla.fo\.o.org',
    3,
    [3,4,3],
    # Wire:            3 b l a 4 f o . o 3 o r g 0
	 "03626c6104666f2e6f036f726700"
    ],

    ['bla\0000.foo.org',
	 'bla\0000.foo.org',
    3,
    [5,3,3],
    # Wire:            5 b l a 0x00 0 3 f o o 3 o r g 0
	 "05626c61003003666f6f036f726700"  ,
    ],

    ["bla.fo\o.org",
	 "bla.foo.org",
    3,
    [3,3,3],
    # Wire:            3 b l a 3 f o o 3 o r g 0   ignoring backslash on input
	 "03626c6103666f6f036f726700",
    ],
    # drops the \
    ['bla(*.foo.org',
	 'bla\(*.foo.org',
    3,
    [5,3,3],

    # Wire:            5 b l a ( * 3 f o o 3 o r g 0
	 "05626c61282a03666f6f036f726700"
    ],

    [' .bla.foo.org',
	 '\032.bla.foo.org',
    4,
    [1,3,3,3],
	 "012003626c6103666f6f036f726700",
    ],

    ["\\\\a.foo",
	 "\\\\a.foo",
    2,
    [2,3],
    # Wire:            2 \ a  3 f o o 0
	 "025c6103666f6f00"
    ],


    ['\\\\.foo',
	 '\\\\.foo',
    2,
    [1,3],
    # Wire:            1 \   3 f o o 0
	 "015c03666f6f00",
    ],

    ['a\\..foo',
	 'a\\..foo',
    2,
    [2,3],
    # Wire:            2 a  . 3 f o o 0
	 "02612e03666f6f00"
    ],

    ['a\\.foo.org',
	 'a\\.foo.org',
    2, [5,3],
    # Wire:            5 a . f o o 3 o r g 0
	 "05612e666f6f036f726700" ,
    ],

    ['\..foo.org',
	 '\..foo.org',
    3,
    [1,3,3],

    # Wire:            1  . 3 f o o 3 o r g 0
	 "012e03666f6f036f726700" ,
    ],

    [
	 '\046.\046',
	 '\..\.',
    2,
    [1,1],
	 '012e012e00',
    ],

    [ # all non \w characters :-)
	  '\000\001\002\003\004\005\006\007\008\009\010\011\012\013\014\015\016\017\018\019\020\021\022\023\024\025\026\027\028\029\030\031\032.\033\034\035\036\037\038\039\040\041\042\043\044\045\046\047\048.\058\059\060\061\062\063\064\065.\091\092\093\094\095\096.\123\124\125\126\127\128\129',
	  '\000\001\002\003\004\005\006\007\008\009\010\011\012\013\014\015\016\017\018\019\020\021\022\023\024\025\026\027\028\029\030\031\032.!\"#\$%&\'\(\)*+,-\./0.:\;<=>?\@a.[\\\\]^_`.{|}~\127\128\129',
    5,
    [33,16,8,6,7],
	  "21000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20102122232425262728292a2b2c2d2e2f30083a3b3c3d3e3f4061065b5c5d5e5f60077b7c7d7e7f808100",
    ],

    ]


    # foreach my $testinput (@testcombos){
    testcombos.each do |testinput|
      #  test back and forth

      name = Name.create(testinput[0])
      labels = Name.name2encodedlabels(testinput[0])

      # 	assert_equal(testinput[1], Net::labels2name(labels), "consistent name2labels labels2name for " + testinput[0])
#      name_from_labels = Name.encodedlabels2name(labels)
      name_from_labels = Name.new(labels)
      assert_equal(name.to_s, name_from_labels.to_s, "Name->Labels->Name for " + testinput[0])

      #  test number of labels
      assert_equal(testinput[2],labels.length(),"consistent labelcount (#{testinput[2]})")
      #  test number of elements within label.
      i=0
      #  Test length of each individual label
      while i<testinput[2]
        assert_equal(testinput[3][i], labels[i].length,
		    "labellength for label #{labels[i]} equals " + testinput[3][i].to_s)
        i = i + 1
      end

      #       wire=Name._name2wire(testinput[0])
      wire=MessageEncoder.new {|msg|
        msg.put_name(name, true)}.to_s

      wireinhex=wire.unpack("H*")[0]
      assert_equal( testinput[4].to_s, wireinhex.to_s,"Wireinhex for " + testinput[0] )
      #  And now call DN_EXPAND
      #       name,offset=Name.dn_expand(wire,0)


      MessageDecoder.new(wire) {|msg|
        name = msg.get_name}

      assert_equal(name.to_s,testinput[1],"DN_EXPAND (pp) consistent")
    end

    #  QUESTION SECTION
    # \\.eg.secret-wg.org.		IN	TXT
    # 
    #  ANSWER SECTION:
    # \\.eg.secret-wg.org.	10	IN	TXT	"WildCard Match"
    # 
    #  AUTHORITY SECTION:
    # eg.secret-wg.org.	600	IN	NS	ns.eg.secret-wg.org.
    # 
    #  ADDITIONAL SECTION:
    # ns.eg.secret-wg.org.	600	IN	A	10.0.53.208
    # 

    uuencodedPacket=%w{
c8 d5 85 00 00 01 00 01  00 01 00 01 02 5c 5c 02
65 67 09 73 65 63 72 65  74 2d 77 67 03 6f 72 67
00 00 10 00 01 c0 0c 00  10 00 01 00 00 00 0a 00
0f 0e 57 69 6c 64 43 61  72 64 20 4d 61 74 63 68
c0 0f 00 02 00 01 00 00  02 58 00 05 02 6e 73 c0
0f c0 4c 00 01 00 01 00  00 02 58 00 04 0a 00 35
d0
}

    # 	uuEncodedPacket =~ s/\s*//g
    # 	uuEncodedPacket =uuEncodedPacket.gsub("\s*", "")
    # 	packetdata = [uuEncodedPacket].pack('H*')

    uuencodedPacket.map!{|e| e.hex}
    packetdata = uuencodedPacket.pack('c*')
    packetdata = packetdata.gsub("\s*", "")

    packet     = Message.decode(packetdata)
    assert(packet, "nil packet returned from binary data")
    assert_equal( (packet.answer)[0].name.to_s,'\\\\\\\\.eg.secret-wg.org',"Correctly dealt escaped backslash from wireformat \\\\.eg.secret-wg.org")
  end

  def test_esoteric_stuff
    #  Now testing for the real esotheric stuff.
    #  domain names can contain NULL and space characters (on the wire)
    #  these should be properly expanded

    #  This only works if the dn_expand_XS()  is NOT used.

    #  The UUencoded packet contains a captured packet with this content:

    #  QUESTION SECTION:
    # \000.n\032ll.eg.secret-wg.org.	IN	TXT

    #  ANSWER SECTION:
    # \000.n ll.eg.secret-wg.org. 0	IN	TXT	"NULL byte ownername"
    #       ^ SPACE !!!
    #  AUTHORITY SECTION:
    # eg.secret-wg.org.	600	IN	NS	ns.eg.secret-wg.org.

    #  ADDITIONAL SECTION:
    # ns.eg.secret-wg.org.	600	IN	A	10.0.53.208

    uuencodedPacket =%w{
 a6 58 85 00 00 01 00 01  00 01 00 01 01 00 04 6e
 20 6c 6c 02 65 67 09 73  65 63 72 65 74 2d 77 67
 03 6f 72 67 00 00 10 00  01 c0 0c 00 10 00 01 00
 00 00 00 00 14 13 4e 55  4c 4c 20 62 79 74 65 20
 6f 77 6e 65 72 6e 61 6d  65 c0 13 00 02 00 01 00
 00 02 58 00 05 02 6e 73  c0 13 c0 55 00 01 00 01
 00 00 02 58 00 04 0a 00  35 d0
}

    uuencodedPacket.map!{|e| e.hex}
    packetdata = uuencodedPacket.pack('c*')
    packetdata = packetdata.gsub("\s*", "")
    packet     = Message.decode(packetdata)
    assert_equal( '\000.n\\032ll.eg.secret-wg.org',(packet.answer)[0].name.to_s,"Correctly dealt with NULL bytes in domain names")


    # slightly modified \\ .eg.secret-wg.org instead of \\\\.eg.secret-wg.org
    #   That is escaped backslash space
    uuencodedPacket=%w{
c8 d5 85 00 00 01 00 01  00 01 00 01 02 5c 20 02
65 67 09 73 65 63 72 65  74 2d 77 67 03 6f 72 67
00 00 10 00 01 c0 0c 00  10 00 01 00 00 00 0a 00
0f 0e 57 69 6c 64 43 61  72 64 20 4d 61 74 63 68
c0 0f 00 02 00 01 00 00  02 58 00 05 02 6e 73 c0
0f c0 4c 00 01 00 01 00  00 02 58 00 04 0a 00 35
d0
}

    uuencodedPacket.map!{|e| e.hex}
    packetdata = uuencodedPacket.pack('c*')
    packetdata.gsub!("\s*", "")
    packet     = Message.decode(packetdata)


    assert_equal( '\\\\\\032.eg.secret-wg.org',(packet.answer)[0].name.to_s,"Correctly dealt escaped backslash from wireformat \\e.eg.secret-wg.org")

    # slightly modified \\e.eg.secret-wg.org instead of \\\\.eg.secret-wg.org
    uuencodedPacket=%w{
c8 d5 85 00 00 01 00 01  00 01 00 01 02 5c 65 02
65 67 09 73 65 63 72 65  74 2d 77 67 03 6f 72 67
00 00 10 00 01 c0 0c 00  10 00 01 00 00 00 0a 00
0f 0e 57 69 6c 64 43 61  72 64 20 4d 61 74 63 68
c0 0f 00 02 00 01 00 00  02 58 00 05 02 6e 73 c0
0f c0 4c 00 01 00 01 00  00 02 58 00 04 0a 00 35
d0
}

    # 	uuEncodedPacket =~ s/\s*//g
    #         packetdata = uuEncodedPacket.pack('H*')
    #         packetdata = packetdata.gsub("\s*", "")
    uuencodedPacket.map!{|e| e.hex}
    packetdata = uuencodedPacket.pack('c*')
    packet     = Message.decode(packetdata)


    assert_equal( '\\\\e.eg.secret-wg.org',(packet.answer)[0].name.to_s,"Correctly dealt escaped backslash from wireformat \\e.eg.secret-wg.org")


    # slightly modified \\\..eg.secret-wg.org instead of \\e.eg.secret-wg.org
    uuencodedPacket=%w{
c8 d5 85 00 00 01 00 01  00 01 00 01 02 5c 65 02
65 67 09 73 65 63 72 65  74 2d 77 67 03 6f 72 67
00 00 10 00 01 c0 0c 00  10 00 01 00 00 00 0a 00
0f 0e 57 69 6c 64 43 61  72 64 20 4d 61 74 63 68
c0 0f 00 02 00 01 00 00  02 58 00 05 02 6e 73 c0
0f c0 4c 00 01 00 01 00  00 02 58 00 04 0a 00 35
d0
}

    # #	uuEncodedPacket =~ s/\s*//g
    #         packetdata = uuEncodedPacket.pack('H*')
    #         packetdata = packetdata.gsub("\s*", "")
    uuencodedPacket.map!{|e| e.hex}
    packetdata = uuencodedPacket.pack('c*')
    packet     = Message.decode(packetdata)
    assert_equal( '\\\\e.eg.secret-wg.org',(packet.answer)[0].name.to_s,"Correctly dealt escaped backslash from wireformat \\\..eg.secret-wg.org")

    testrr=RR.create(
                           :name => '\\e.eg.secret-wg.org',
    :type         => 'TXT',
    :txtdata      => '"WildCard Match"',
    :ttl          =>  10,
    :class        => "IN"
    )



    klass = "IN"
    ttl = 43200
    name = 'def0au&lt.example.com'



    rrs = [
    { #[0]
      :name => '\..bla\..example.com',
      :type => Types.A,
      :address => '10.0.0.1',
    },
    { #[2]
      :name => name,
      :type => 'AFSDB',
      :subtype => 1,
      :hostname =>'afsdb-hostname.example.com',
    },
    { #[3]
      :name => '\\.funny.example.com',
      :type         => Types::CNAME,
      :domainname        => 'cname-cn\244ame.example.com',
    },
    {   #[4]
      :name => name,
      :type         => Types.DNAME,
      :domainname        => 'dn\222ame.example.com',
    },
    {	#[9]
      :name => name,
      :type         => Types.MINFO,
      :rmailbx      => 'minfo\.rmailbx.example.com',
      :emailbx      => 'minfo\007emailbx.example.com',
    },

    {	#[13]
      :name => name,
      :type         => Types.NS,
      :domainname      => '\001ns-nsdname.example.com',
    },

    {	#[19]
      :name => name,
      :type         => Types.SOA,
      :mname        => 'soa-mn\001ame.example.com',
      :rname        => 'soa\.rname.example.com',
      :serial       => 12345,
      :refresh      => 7200,
      :retry        => 3600,
      :expire       => 2592000,
      :minimum      => 86400,
    },

    ]

    # ------------------------------------------------------------------------------
    #  Create the packet.
    # ------------------------------------------------------------------------------
    packet = nil
    packet = Message.new(name)
    assert(packet,         'Packet created')

    rrs.each do |data|
      data.update({:ttl  => ttl,})

      rec = RR.create(data)
      packet.add_answer(rec)
    end


    # ------------------------------------------------------------------------------
    #  Re-create the packet from data.
    # ------------------------------------------------------------------------------
    data = packet.encode

    assert(data,            'Packet has data after pushes')

    packet = nil

    packet = Message.decode(data)

    assert(packet,          'Packet reconstructed from data')

    answer = packet.answer

    # 	assert(answer && answer == rrs, 'Packet returned correct answer section')
    rrs.each do |rr|
      record = nil
      answer.each do |ansrec|
        if (ansrec.type == rr[:type])
          record = ansrec
          break
        end
      end
      assert(record!=nil, "can't find answer record for #{rr}")
      rr.keys.each do |key|
        if (key == :type)
          assert_equal(Types.new(rr[key]).string, record.send(key).to_s, "value not right for key #{key} for rr #{rr}")
        else
          assert_equal(rr[key].to_s, record.send(key).to_s, "value not right for key #{key} for rr #{rr}")
        end
      end
    end


    while (answer.size>0 and rrs.size>0)
      data = rrs.shift
      rr   = answer.shift
      type = data[:type]
      # 		foreach my $meth (keys %{$data}) {
       (data.keys.each do |meth|
        if (meth == :type)
          assert_equal(Types.new(data[meth]).to_s, rr.send(meth).to_s, "#{type} - #meth() correct")
        else
          assert_equal(data[meth].to_s, rr.send(meth).to_s, "#{type} - #meth() correct")
        end
        end)

        rr2 = RR.new_from_string(rr.to_s)
        assert_equal(rr.to_s,   rr2.to_s, "#{type} - Parsing from string works")
      end

    Name::Label.set_max_length(Name::Label::MaxLabelLength)
    end
  end
