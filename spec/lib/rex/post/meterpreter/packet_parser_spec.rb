require 'rex/post/meterpreter/packet'
require 'rex/post/meterpreter/packet_parser'


describe Rex::Post::Meterpreter::PacketParser do
  subject{
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

  it "should respond to cipher" do
    subject.should respond_to :cipher
  end

  it "should respond to raw" do
    subject.should respond_to :raw
  end

  it "should respond to reset" do
    subject.should respond_to :reset
  end

  it "should respond to recv" do
    subject.should respond_to :recv
  end

  it "should respond to hdr_length_left" do
    subject.should respond_to :hdr_length_left
  end

  it "should respond to payload_length_left" do
    subject.should respond_to :payload_length_left
  end

  it "should initialise with expected defaults" do
    subject.send(:raw).should == ""
    subject.send(:hdr_length_left).should == 8
    subject.send(:payload_length_left).should == 0
  end

  it "should parse valid raw data into a packet object" do
    while @raw.length >0
      parsed_packet = subject.recv(@sock)
    end
    parsed_packet.class.should == Rex::Post::Meterpreter::Packet
    parsed_packet.type.should == Rex::Post::Meterpreter::PACKET_TYPE_REQUEST
    parsed_packet.method?("test_method").should == true
  end

end
