# -*- coding:binary -*-
require 'rex/post/meterpreter/packet'
require 'rex/post/meterpreter/packet_parser'


describe Rex::Post::Meterpreter::PacketParser do
  subject(:parser){
    Rex::Post::Meterpreter::PacketParser.new
  }
  before(:each) do
    @req_packt = Rex::Post::Meterpreter::Packet.new(
          Rex::Post::Meterpreter::PACKET_TYPE_REQUEST,
          "test_method")
    @raw = @req_packt.to_r
    @sock = double('Socket')
    @sock.stub(:read) do |arg|
      @raw.slice!(0,arg)
    end
  end

  it "should initialise with expected defaults" do
    parser.send(:raw).should == ""
    parser.send(:hdr_length_left).should == 8
    parser.send(:payload_length_left).should == 0
  end

  it "should parse valid raw data into a packet object" do
    while @raw.length >0
      parsed_packet = parser.recv(@sock)
    end
    parsed_packet.should be_a Rex::Post::Meterpreter::Packet
    parsed_packet.type.should == Rex::Post::Meterpreter::PACKET_TYPE_REQUEST
    parsed_packet.method?("test_method").should == true
  end

end
