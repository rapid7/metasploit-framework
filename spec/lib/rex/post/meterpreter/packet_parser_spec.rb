# -*- coding:binary -*-
require 'rex/post/meterpreter/packet'
require 'rex/post/meterpreter/packet_parser'


RSpec.describe Rex::Post::Meterpreter::PacketParser do
  subject(:parser){
    Rex::Post::Meterpreter::PacketParser.new
  }
  before(:example) do
    @req_packt = Rex::Post::Meterpreter::Packet.new(
          Rex::Post::Meterpreter::PACKET_TYPE_REQUEST,
          "test_method")
    @raw = @req_packt.to_r
    @sock = double('Socket')
    allow(@sock).to receive(:read) do |arg|
      @raw.slice!(0,arg)
    end
  end

  it "should initialise with expected defaults" do
    expect(parser.send(:raw)).to eq ""
    expect(parser.send(:hdr_length_left)).to eq 12
    expect(parser.send(:payload_length_left)).to eq 0
  end

  it "should parse valid raw data into a packet object" do
    while @raw.length >0
      parsed_packet, in_progress = parser.recv(@sock)
    end
    expect(parsed_packet).to be_a Rex::Post::Meterpreter::Packet
    expect(parsed_packet.type).to eq Rex::Post::Meterpreter::PACKET_TYPE_REQUEST
    expect(parsed_packet.method?("test_method")).to eq true
    expect(in_progress).to eq false
  end

end
