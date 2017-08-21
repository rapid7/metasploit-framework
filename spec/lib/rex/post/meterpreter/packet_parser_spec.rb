# -*- coding:binary -*-
require 'rex/post/meterpreter/packet'
require 'rex/post/meterpreter/packet_parser'
require 'stringio'

RSpec.describe Rex::Post::Meterpreter::PacketParser do
  subject(:parser){
    Rex::Post::Meterpreter::PacketParser.new
  }
  before(:example) do
    @request_packet = Rex::Post::Meterpreter::Packet.create_request("test_method")
    @sock = StringIO.new(@request_packet.to_r)
  end

  it "should parse valid raw data into a packet object" do
    begin
      parsed_packet = parser.recv(@sock)
    end while parsed_packet.nil?
    parsed_packet.from_r
    expect(parsed_packet).to be_a Rex::Post::Meterpreter::Packet
    expect(parsed_packet.type).to eq Rex::Post::Meterpreter::PACKET_TYPE_REQUEST
    expect(parsed_packet.method?("test_method")).to eq true
  end

end
