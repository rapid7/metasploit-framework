# encoding: BINARY
# Encoding is set to binary, so that the binary packets aren't validated as UTF-8

$:.unshift(File.dirname(__FILE__))

require 'spec_helper'

describe MQTT::Packet do

  describe "when creating a new packet" do
    it "should allow you to set the packet flags as a hash parameter" do
      packet = MQTT::Packet.new( :flags => [true, false, true, false] )
      expect(packet.flags).to eq([true, false, true, false])
    end

    it "should have a custom inspect method" do
      packet = MQTT::Packet.new
      expect(packet.inspect).to eq('#<MQTT::Packet>')
    end

    it "should have a type_id method to get the integer ID of the packet type" do
      packet = MQTT::Packet::Pingreq.new
      expect(packet.type_id).to eq(12)
    end
  end

  it "should let you change attributes using the update_attributes method" do
    packet = MQTT::Packet.new(:flags => [false, false, false, true])
    packet.update_attributes(:flags => [false, false, true, true])
    expect(packet.flags).to eq([false, false, true, true])
  end

  describe "protected methods" do
    let(:packet) { MQTT::Packet.new }

    it "should provide a encode_bytes method to get some bytes as Integers" do
      data = packet.send(:encode_bytes, 0x48, 0x65, 0x6c, 0x6c, 'o'.unpack('C1')[0])
      expect(data).to eq('Hello')
    end

    it "should provide a encode_bits method to encode an array of bits to a string" do
      data = packet.send(:encode_bits, [false, true, true, false, true, false, true, false])
      expect(data).to eq('V')
    end

    it "should provide a add_short method to get a big-endian unsigned 16-bit integer" do
      data = packet.send(:encode_short, 1024)
      expect(data).to eq("\x04\x00")
      expect(data.encoding.to_s).to eq("ASCII-8BIT")
    end

    it "should provide a add_string method to get a string preceeded by its length" do
      data = packet.send(:encode_string, 'quack')
      expect(data).to eq("\x00\x05quack")
      expect(data.encoding.to_s).to eq("ASCII-8BIT")
    end

    it "should provide a shift_short method to get a 16-bit unsigned integer" do
      buffer = "\x22\x8Bblahblah"
      expect(packet.send(:shift_short,buffer)).to eq(8843)
      expect(buffer).to eq('blahblah')
    end

    it "should provide a shift_byte method to get one byte as integers" do
      buffer = "\x01blahblah"
      expect(packet.send(:shift_byte,buffer)).to eq(1)
      expect(buffer).to eq('blahblah')
    end

    it "should provide a shift_byte method to get one byte as integers" do
      buffer = "Yblahblah"
      expect(packet.send(:shift_bits, buffer)).to eq([true, false, false, true, true, false, true, false])
      expect(buffer).to eq('blahblah')
    end

    it "should provide a shift_string method to get a string preceeded by its length" do
      buffer = "\x00\x05Hello World"
      expect(packet.send(:shift_string,buffer)).to eq("Hello")
      expect(buffer).to eq(' World')
    end
  end

  describe "deprecated attributes" do
    it "should still have a message_id method that is that same as id" do
      packet = MQTT::Packet.new
      packet.message_id = 1234
      expect(packet.message_id).to eq(1234)
      expect(packet.id).to eq(1234)
      packet.id = 4321
      expect(packet.message_id).to eq(4321)
      expect(packet.id).to eq(4321)
    end
  end
end

describe MQTT::Packet::Publish do
  describe "when creating a packet" do
    it "should allow you to set the packet QoS level as a hash parameter" do
      packet = MQTT::Packet::Publish.new( :qos => 2 )
      expect(packet.qos).to eq(2)
    end

    it "should allow you to set the packet retain flag as a hash parameter" do
      packet = MQTT::Packet::Publish.new( :retain => true )
      expect(packet.retain).to be_truthy
    end

    it "should raise an exception the QoS is greater than 2" do
      expect {
        packet = MQTT::Packet::Publish.new( :qos => 3 )
      }.to raise_error(
        'Invalid QoS value: 3'
      )
    end

    it "should raise an exception the QoS is less than 0" do
      expect {
        packet = MQTT::Packet::Publish.new( :qos => -1 )
      }.to raise_error(
        'Invalid QoS value: -1'
      )
    end
  end

  describe "when setting attributes on a packet" do
    let(:packet) {
      MQTT::Packet::Publish.new(
        :duplicate => false,
        :qos => 0,
        :retain => false
      )
    }

    it "should let you change the dup flag of a packet" do
      packet.duplicate = true
      expect(packet.duplicate).to be_truthy
    end

    it "should let you change the dup flag of a packet using an integer" do
      packet.duplicate = 1
      expect(packet.duplicate).to be_truthy
    end

    it "should let you change the QoS value of a packet" do
      packet.qos = 1
      expect(packet.qos).to eq(1)
    end

    it "should let you change the retain flag of a packet" do
      packet.retain = true
      expect(packet.retain).to be_truthy
    end

    it "should let you change the retain flag of a packet using an integer" do
      packet.retain = 1
      expect(packet.retain).to be_truthy
    end
  end

  describe "when serialising a packet" do
    it "should output the correct bytes for a packet with default QoS and no flags" do
      packet = MQTT::Packet::Publish.new( :topic => 'test', :payload => 'hello world' )
      expect(packet.to_s).to eq("\x30\x11\x00\x04testhello world")
    end

    it "should output the correct bytes for a packet with QoS 1 and no flags" do
      packet = MQTT::Packet::Publish.new( :id => 5, :qos => 1, :topic => 'a/b', :payload => 'hello world' )
      expect(packet.to_s).to eq("\x32\x12\x00\x03a/b\x00\x05hello world")
    end

    it "should output the correct bytes for a packet with QoS 2 and retain flag set" do
      packet = MQTT::Packet::Publish.new( :id => 5, :qos => 2, :retain => true, :topic => 'c/d', :payload => 'hello world' )
      expect(packet.to_s).to eq("\x35\x12\x00\x03c/d\x00\x05hello world")
    end

    it "should output the correct bytes for a packet with QoS 2 and dup flag set" do
      packet = MQTT::Packet::Publish.new( :id => 5, :qos => 2, :duplicate => true, :topic => 'c/d', :payload => 'hello world' )
      expect(packet.to_s).to eq("\x3C\x12\x00\x03c/d\x00\x05hello world")
    end

    it "should output the correct bytes for a packet with an empty payload" do
      packet = MQTT::Packet::Publish.new( :topic => 'test' )
      expect(packet.to_s).to eq("\x30\x06\x00\x04test")
    end

    it "should output a string as binary / 8-bit ASCII" do
      packet = MQTT::Packet::Publish.new( :topic => 'test', :payload => 'hello world' )
      expect(packet.to_s.encoding.to_s).to eq("ASCII-8BIT")
    end

    it "should support passing in non-strings to the topic and payload" do
      packet = MQTT::Packet::Publish.new( :topic => :symbol, :payload => 1234 )
      expect(packet.to_s).to eq("\x30\x0c\x00\x06symbol1234")
    end

    it "should raise an exception when there is no topic name" do
      expect {
        MQTT::Packet::Publish.new.to_s
      }.to raise_error(
        'Invalid topic name when serialising packet'
      )
    end

    it "should raise an exception when there is an empty topic name" do
      expect {
        MQTT::Packet::Publish.new( :topic => '' ).to_s
      }.to raise_error(
        'Invalid topic name when serialising packet'
      )
    end
  end

  describe "when serialising an oversized packet" do
    it "should raise an exception when body is bigger than 256MB" do
      expect {
        packet = MQTT::Packet::Publish.new( :topic => 'test', :payload => 'x'*268435455 )
        packet.to_s
      }.to raise_error(
        'Error serialising packet: body is more than 256MB'
      )
    end
  end

  describe "when parsing a packet with QoS 0" do
    let(:packet) { MQTT::Packet.parse( "\x30\x11\x00\x04testhello world" ) }

    it "should correctly create the right type of packet object" do
      expect(packet.class).to eq(MQTT::Packet::Publish)
    end

    it "should set the QoS level correctly" do
      expect(packet.qos).to eq(0)
    end

    it "should set the RETAIN flag correctly" do
      expect(packet.retain).to be_falsey
    end

    it "should set the DUP flag correctly" do
      expect(packet.duplicate).to be_falsey
    end

    it "should set the topic name correctly" do
      expect(packet.topic).to eq('test')
      expect(packet.topic.encoding.to_s).to eq('UTF-8')
    end

    it "should set the payload correctly" do
      expect(packet.payload).to eq('hello world')
      expect(packet.payload.encoding.to_s).to eq('ASCII-8BIT')
    end
  end

  describe "when parsing a packet with QoS 2 and retain and dup flags set" do
    let(:packet) { MQTT::Packet.parse( "\x3D\x12\x00\x03c/d\x00\x05hello world" ) }

    it "should correctly create the right type of packet object" do
      expect(packet.class).to eq(MQTT::Packet::Publish)
    end

    it "should set the QoS level correctly" do
      expect(packet.qos).to eq(2)
    end

    it "should set the RETAIN flag correctly" do
      expect(packet.retain).to be_truthy
    end

    it "should set the DUP flag correctly" do
      expect(packet.duplicate).to be_truthy
    end

    it "should set the topic name correctly" do
      expect(packet.topic).to eq('c/d')
      expect(packet.topic.encoding.to_s).to eq('UTF-8')
    end

    it "should set the payload correctly" do
      expect(packet.payload).to eq('hello world')
      expect(packet.payload.encoding.to_s).to eq('ASCII-8BIT')
    end
  end

  describe "when parsing a packet with an empty payload" do
    let(:packet) { MQTT::Packet.parse( "\x30\x06\x00\x04test" ) }

    it "should correctly create the right type of packet object" do
      expect(packet.class).to eq(MQTT::Packet::Publish)
    end

    it "should set the topic name correctly" do
      expect(packet.topic).to eq('test')
    end

    it "should set the payload correctly" do
      expect(packet.payload).to be_empty
    end
  end

  describe "when parsing a packet with a QoS value of 3" do
    it "should raise an exception" do
      expect {
        packet = MQTT::Packet.parse( "\x36\x12\x00\x03a/b\x00\x05hello world" )
      }.to raise_error(
        MQTT::ProtocolException,
        'Invalid packet: QoS value of 3 is not allowed'
      )
    end
  end

  describe "when parsing a packet with QoS value of 0 and DUP set" do
    it "should raise an exception" do
      expect {
        packet = MQTT::Packet.parse( "\x38\x10\x00\x03a/bhello world" )
      }.to raise_error(
        MQTT::ProtocolException,
        'Invalid packet: DUP cannot be set for QoS 0'
      )
    end
  end

  describe "when parsing a packet with a body of 314 bytes" do
    let(:packet) {
      # 0x30 = publish
      # 0xC1 = (65 * 1)
      # 0x02 = (2 * 128)
      MQTT::Packet.parse( "\x30\xC1\x02\x00\x05topic" + ('x' * 314) )
    }

    it "should parse the packet type correctly" do
      expect(packet.class).to eq(MQTT::Packet::Publish)
    end

    it "should get the topic name correctly" do
      expect(packet.topic).to eq('topic')
    end

    it "should get the body length correctly" do
      expect(packet.payload.bytesize).to eq(314)
    end
  end

  describe "when parsing a packet with a body of 16kbytes" do
    let(:packet) do
      # 0x30 = publish
      # 0x87 = (7 * 1)
      # 0x80 = (0 * 128)
      # 0x01 = (1 * 16384)
      MQTT::Packet.parse( "\x30\x87\x80\x01\x00\x05topic" + ('x'*16384) )
    end

    it "should parse the packet type correctly" do
      expect(packet.class).to eq(MQTT::Packet::Publish)
    end

    it "should get the topic name correctly" do
      expect(packet.topic).to eq('topic')
    end

    it "should get the body length correctly" do
      expect(packet.payload.bytesize).to eq(16384)
    end
  end

  describe "processing a packet containing UTF-8 character" do
    let(:packet) do
      MQTT::Packet::Publish.new(
        :topic => "Test ①".force_encoding("UTF-8"),
        :payload => "Snowman: ☃".force_encoding("UTF-8")
      )
    end

    it "should have the correct topic byte length" do
      expect(packet.topic.bytesize).to eq(8)
    end

    it "should have the correct topic string length", :unless => RUBY_VERSION =~ /^1\.8/ do
      # Ruby 1.8 doesn't support UTF-8 properly
      expect(packet.topic.length).to eq(6)
    end

    it "should have the correct payload byte length" do
      expect(packet.payload.bytesize).to eq(12)
    end

    it "should have the correct payload string length", :unless => RUBY_VERSION =~ /^1\.8/ do
      # Ruby 1.8 doesn't support UTF-8 properly
      expect(packet.payload.length).to eq(10)
    end

    it "should encode to MQTT packet correctly" do
      expect(packet.to_s).to eq("\x30\x16\x00\x08Test \xE2\x91\xA0Snowman: \xE2\x98\x83".force_encoding('BINARY'))
    end

    it "should parse the serialised packet" do
      packet2 = MQTT::Packet.parse( packet.to_s )
      expect(packet2.topic).to eq("Test ①".force_encoding('UTF-8'))
      expect(packet2.payload).to eq("Snowman: ☃".force_encoding('BINARY'))
    end
  end

  describe "reading a packet from a socket" do
    let(:socket) { StringIO.new("\x30\x11\x00\x04testhello world") }
    let(:packet) { MQTT::Packet.read(socket) }

    it "should correctly create the right type of packet object" do
      expect(packet.class).to eq(MQTT::Packet::Publish)
    end

    it "should set the body length is read correctly" do
      expect(packet.body_length).to eq(17)
    end

    it "should set the QoS level correctly" do
      expect(packet.qos).to eq(0)
    end

    it "should set the RETAIN flag correctly" do
      expect(packet.retain).to be_falsey
    end

    it "should set the DUP flag correctly" do
      expect(packet.duplicate).to be_falsey
    end

    it "should set the topic name correctly" do
      expect(packet.topic).to eq('test')
      expect(packet.topic.encoding.to_s).to eq('UTF-8')
    end

    it "should set the payload correctly" do
      expect(packet.payload).to eq('hello world')
      expect(packet.payload.encoding.to_s).to eq('ASCII-8BIT')
    end
  end

  describe "when calling the inspect method" do
    it "should output the payload, if it is less than 16 bytes" do
      packet = MQTT::Packet::Publish.new( :topic => "topic", :payload => "payload" )
      expect(packet.inspect).to eq("#<MQTT::Packet::Publish: d0, q0, r0, m0, 'topic', 'payload'>")
    end

    it "should output the length of the payload, if it is more than 16 bytes" do
      packet = MQTT::Packet::Publish.new( :topic => "topic", :payload => 'x'*32 )
      expect(packet.inspect).to eq("#<MQTT::Packet::Publish: d0, q0, r0, m0, 'topic', ... (32 bytes)>")
    end

    it "should only output the length of a binary payload" do
      packet = MQTT::Packet.parse("\x31\x12\x00\x04test\x8D\xF8\x09\x40\xC4\xE7\x4f\xF0\xFF\x30\xE0\xE7")
      expect(packet.inspect).to eq("#<MQTT::Packet::Publish: d0, q0, r1, m0, 'test', ... (12 bytes)>")
    end
  end
end

describe MQTT::Packet::Connect do
  describe "when serialising a packet" do
    it "should output the correct bytes for a packet with no flags" do
      packet = MQTT::Packet::Connect.new( :client_id => 'myclient' )
      expect(packet.to_s).to eq("\020\026\x00\x06MQIsdp\x03\x02\x00\x0f\x00\x08myclient")
    end

    it "should output the correct bytes for a packet with clean session turned off" do
      packet = MQTT::Packet::Connect.new(
        :client_id => 'myclient',
        :clean_session => false
      )
      expect(packet.to_s).to eq("\020\026\x00\x06MQIsdp\x03\x00\x00\x0f\x00\x08myclient")
    end

    context "protocol version 3.1.0" do
      it "should raise an exception when there is no client identifier" do
        expect {
          MQTT::Packet::Connect.new(:version => '3.1.0', :client_id => '').to_s
        }.to raise_error(
          'Client identifier too short while serialising packet'
        )
      end

      it "should raise an exception when the client identifier is too long" do
        expect {
          client_id = '0EB8D2FE7C254715B4467C5B2ECAD100'
          MQTT::Packet::Connect.new(:version => '3.1.0', :client_id => client_id).to_s
        }.to raise_error(
          'Client identifier too long when serialising packet'
        )
      end
    end

    context "protocol version 3.1.1" do
      it "should allow no client identifier" do
        packet = MQTT::Packet::Connect.new(
          :version => '3.1.1',
          :client_id => '',
          :clean_session => true
        )
        expect(packet.to_s).to eq("\020\014\x00\x04MQTT\x04\x02\x00\x0f\x00\x00")
      end

      it "should allow a 32 character client identifier" do
        client_id = '0EB8D2FE7C254715B4467C5B2ECAD100'
        packet = MQTT::Packet::Connect.new(
          :version => '3.1.1',
          :client_id => client_id,
          :clean_session => true
        )
        expect(packet.to_s).to eq("\x10,\x00\x04MQTT\x04\x02\x00\x0F\x00\x200EB8D2FE7C254715B4467C5B2ECAD100")
      end
    end

    it "should raise an exception if the keep alive value is less than 0" do
      expect {
        MQTT::Packet::Connect.new(:client_id => 'test', :keep_alive => -2).to_s
      }.to raise_error(
        'Invalid keep-alive value: cannot be less than 0'
      )
    end

    it "should output the correct bytes for a packet with a Will" do
      packet = MQTT::Packet::Connect.new(
        :client_id => 'myclient',
        :clean_session => true,
        :will_qos => 1,
        :will_retain => false,
        :will_topic => 'topic',
        :will_payload => 'hello'
      )
      expect(packet.to_s).to eq(
        "\x10\x24"+
        "\x00\x06MQIsdp"+
        "\x03\x0e\x00\x0f"+
        "\x00\x08myclient"+
        "\x00\x05topic\x00\x05hello"
      )
    end

    it "should output the correct bytes for a packet with a username and password" do
      packet = MQTT::Packet::Connect.new(
        :client_id => 'myclient',
        :username => 'username',
        :password => 'password'
      )
      expect(packet.to_s).to eq(
        "\x10\x2A"+
        "\x00\x06MQIsdp"+
        "\x03\xC2\x00\x0f"+
        "\x00\x08myclient"+
        "\x00\x08username"+
        "\x00\x08password"
      )
    end

    it "should output the correct bytes for a packet with everything" do
      packet = MQTT::Packet::Connect.new(
        :client_id => '12345678901234567890123',
        :clean_session => true,
        :keep_alive => 65535,
        :will_qos => 2,
        :will_retain => true,
        :will_topic => 'will_topic',
        :will_payload => 'will_message',
        :username => 'user0123456789',
        :password => 'pass0123456789'
      )
      expect(packet.to_s).to eq(
        "\x10\x5F"+ # fixed header (2)
        "\x00\x06MQIsdp"+ # protocol name (8)
        "\x03\xf6"+ # protocol level + flags (2)
        "\xff\xff"+ # keep alive (2)
        "\x00\x1712345678901234567890123"+ # client identifier (25)
        "\x00\x0Awill_topic"+ # will topic (12)
        "\x00\x0Cwill_message"+ # will message (14)
        "\x00\x0Euser0123456789"+ # username (16)
        "\x00\x0Epass0123456789"
      )  # password (16)
    end

    context 'protocol version 3.1.1' do
      it "should output the correct bytes for a packet with no flags" do
        packet = MQTT::Packet::Connect.new( :version => '3.1.1', :client_id => 'myclient' )
        expect(packet.to_s).to eq("\020\024\x00\x04MQTT\x04\x02\x00\x0f\x00\x08myclient")
      end
    end

    context 'an invalid protocol version number' do
      it "should raise a protocol exception" do
        expect {
          packet = MQTT::Packet::Connect.new( :version => 'x.x.x', :client_id => 'myclient' )
        }.to raise_error(
          ArgumentError,
          "Unsupported protocol version: x.x.x"
        )
      end
    end

  end

  describe "when parsing a simple 3.1.0 Connect packet" do
    let(:packet) do
      MQTT::Packet.parse(
        "\x10\x16\x00\x06MQIsdp\x03\x00\x00\x0a\x00\x08myclient"
      )
    end

    it "should correctly create the right type of packet object" do
      expect(packet.class).to eq(MQTT::Packet::Connect)
    end

    it "should set the fixed header flags of the packet correctly" do
      expect(packet.flags).to eq([false, false, false, false])
    end

    it "should set the Protocol Name of the packet correctly" do
      expect(packet.protocol_name).to eq('MQIsdp')
      expect(packet.protocol_name.encoding.to_s).to eq('UTF-8')
    end

    it "should set the Protocol Level of the packet correctly" do
      expect(packet.protocol_level).to eq(3)
    end

    it "should set the Protocol version of the packet correctly" do
      expect(packet.version).to eq('3.1.0')
    end

    it "should set the Client Identifier of the packet correctly" do
      expect(packet.client_id).to eq('myclient')
      expect(packet.client_id.encoding.to_s).to eq('UTF-8')
    end

    it "should set the Keep Alive timer of the packet correctly" do
      expect(packet.keep_alive).to eq(10)
    end

    it "should set not have the clean session flag set" do
      expect(packet.clean_session).to be_falsey
    end

    it "should set the the username field of the packet to nil" do
      expect(packet.username).to be_nil
    end

    it "should set the the password field of the packet to nil" do
      expect(packet.password).to be_nil
    end
  end

  describe "when parsing a simple 3.1.1 Connect packet" do
    let(:packet) do
      MQTT::Packet.parse(
        "\x10\x14\x00\x04MQTT\x04\x00\x00\x0a\x00\x08myclient"
      )
    end

    it "should correctly create the right type of packet object" do
      expect(packet.class).to eq(MQTT::Packet::Connect)
    end

    it "should set the fixed header flags of the packet correctly" do
      expect(packet.flags).to eq([false, false, false, false])
    end

    it "should set the Protocol Name of the packet correctly" do
      expect(packet.protocol_name).to eq('MQTT')
      expect(packet.protocol_name.encoding.to_s).to eq('UTF-8')
    end

    it "should set the Protocol Level of the packet correctly" do
      expect(packet.protocol_level).to eq(4)
    end

    it "should set the Protocol version of the packet correctly" do
      expect(packet.version).to eq('3.1.1')
    end

    it "should set the Client Identifier of the packet correctly" do
      expect(packet.client_id).to eq('myclient')
      expect(packet.client_id.encoding.to_s).to eq('UTF-8')
    end

    it "should set the Keep Alive timer of the packet correctly" do
      expect(packet.keep_alive).to eq(10)
    end

    it "should set not have the clean session flag set" do
      expect(packet.clean_session).to be_falsey
    end

    it "should set the the username field of the packet to nil" do
      expect(packet.username).to be_nil
    end

    it "should set the the password field of the packet to nil" do
      expect(packet.password).to be_nil
    end
  end

  describe "when parsing a Connect packet with the clean session flag set" do
    let(:packet) do
      MQTT::Packet.parse(
        "\x10\x16\x00\x06MQIsdp\x03\x02\x00\x0a\x00\x08myclient"
      )
    end

    it "should set the clean session flag" do
      expect(packet.clean_session).to be_truthy
    end
  end

  describe "when parsing a Connect packet with a Will and Testament" do
    let(:packet) do
      MQTT::Packet.parse(
        "\x10\x24\x00\x06MQIsdp\x03\x0e\x00\x0a\x00\x08myclient\x00\x05topic\x00\x05hello"
      )
    end

    it "should correctly create the right type of packet object" do
      expect(packet.class).to eq(MQTT::Packet::Connect)
    end

    it "should set the fixed header flags of the packet correctly" do
      expect(packet.flags).to eq([false, false, false, false])
    end

    it "should set the Protocol Name of the packet correctly" do
      expect(packet.protocol_name).to eq('MQIsdp')
      expect(packet.protocol_name.encoding.to_s).to eq('UTF-8')
    end

    it "should set the Protocol Level of the packet correctly" do
      expect(packet.protocol_level).to eq(3)
    end

    it "should set the Protocol version of the packet correctly" do
      expect(packet.version).to eq('3.1.0')
    end

    it "should set the Client Identifier of the packet correctly" do
      expect(packet.client_id).to eq('myclient')
      expect(packet.client_id.encoding.to_s).to eq('UTF-8')
    end

    it "should set the clean session flag should be set" do
      expect(packet.clean_session).to be_truthy
    end

    it "should set the QoS of the Will should be 1" do
      expect(packet.will_qos).to eq(1)
    end

    it "should set the Will retain flag should be false" do
      expect(packet.will_retain).to be_falsey
    end

    it "should set the Will topic of the packet correctly" do
      expect(packet.will_topic).to eq('topic')
      expect(packet.will_topic.encoding.to_s).to eq('UTF-8')
    end

    it "should set the Will payload of the packet correctly" do
      expect(packet.will_payload).to eq('hello')
      expect(packet.will_payload.encoding.to_s).to eq('UTF-8')
    end
  end

  describe "when parsing a Connect packet with a username and password" do
    let(:packet) do
      MQTT::Packet.parse(
        "\x10\x2A"+
        "\x00\x06MQIsdp"+
        "\x03\xC0\x00\x0a"+
        "\x00\x08myclient"+
        "\x00\x08username"+
        "\x00\x08password"
      )
    end

    it "should correctly create the right type of packet object" do
      expect(packet.class).to eq(MQTT::Packet::Connect)
    end

    it "should set the fixed header flags of the packet correctly" do
      expect(packet.flags).to eq([false, false, false, false])
    end

    it "should set the Protocol Name of the packet correctly" do
      expect(packet.protocol_name).to eq('MQIsdp')
      expect(packet.protocol_name.encoding.to_s).to eq('UTF-8')
    end

    it "should set the Protocol Level of the packet correctly" do
      expect(packet.protocol_level).to eq(3)
    end

    it "should set the Protocol version of the packet correctly" do
      expect(packet.version).to eq('3.1.0')
    end

    it "should set the Client Identifier of the packet correctly" do
      expect(packet.client_id).to eq('myclient')
      expect(packet.client_id.encoding.to_s).to eq('UTF-8')
   end

    it "should set the Keep Alive Timer of the packet correctly" do
      expect(packet.keep_alive).to eq(10)
    end

    it "should set the Username of the packet correctly" do
      expect(packet.username).to eq('username')
      expect(packet.username.encoding.to_s).to eq('UTF-8')
    end

    it "should set the Username of the packet correctly" do
      expect(packet.password).to eq('password')
      expect(packet.password.encoding.to_s).to eq('UTF-8')
    end
  end

  describe "when parsing a Connect that has a username but no password" do
    let(:packet) do
      MQTT::Packet.parse(
        "\x10\x20\x00\x06MQIsdp\x03\x80\x00\x0a\x00\x08myclient\x00\x08username"
      )
    end

    it "should set the Username of the packet correctly" do
      expect(packet.username).to eq('username')
      expect(packet.username.encoding.to_s).to eq('UTF-8')
    end

    it "should set the Username of the packet correctly" do
      expect(packet.password).to be_nil
    end
  end

  describe "when parsing a Connect that has a password but no username" do
    let(:packet) do
      MQTT::Packet.parse(
        "\x10\x20\x00\x06MQIsdp\x03\x40\x00\x0a\x00\x08myclient\x00\x08password"
      )
    end

    it "should set the Username of the packet correctly" do
      expect(packet.username).to be_nil
    end

    it "should set the Username of the packet correctly" do
      expect(packet.password).to eq('password')
      expect(packet.password.encoding.to_s).to eq('UTF-8')
    end
  end

  describe "when parsing a Connect packet has the username and password flags set but doesn't have the fields" do
    let(:packet) do
      MQTT::Packet.parse(
        "\x10\x16\x00\x06MQIsdp\x03\xC0\x00\x0a\x00\x08myclient"
      )
    end

    it "should set the Username of the packet correctly" do
      expect(packet.username).to be_nil
    end

    it "should set the Username of the packet correctly" do
      expect(packet.password).to be_nil
    end
  end

  describe "when parsing a Connect packet with every option set" do
    let(:packet) do
      MQTT::Packet.parse(
        "\x10\x5F"+ # fixed header (2)
        "\x00\x06MQIsdp"+ # protocol name (8)
        "\x03\xf6"+ # protocol level + flags (2)
        "\xff\xff"+ # keep alive (2)
        "\x00\x1712345678901234567890123"+ # client identifier (25)
        "\x00\x0Awill_topic"+ # will topic (12)
        "\x00\x0Cwill_message"+ # will message (14)
        "\x00\x0Euser0123456789"+ # username (16)
        "\x00\x0Epass0123456789"  # password (16)
      )
    end

    it "should correctly create the right type of packet object" do
      expect(packet.class).to eq(MQTT::Packet::Connect)
    end

    it "should set the fixed header flags of the packet correctly" do
      expect(packet.flags).to eq([false, false, false, false])
    end

    it "should set the Protocol Name of the packet correctly" do
      expect(packet.protocol_name).to eq('MQIsdp')
      expect(packet.protocol_name.encoding.to_s).to eq('UTF-8')
    end

    it "should set the Protocol Level of the packet correctly" do
      expect(packet.protocol_level).to eq(3)
    end

    it "should set the Protocol version of the packet correctly" do
      expect(packet.version).to eq('3.1.0')
    end

    it "should set the Keep Alive Timer of the packet correctly" do
      expect(packet.keep_alive).to eq(65535)
    end

    it "should set the Client Identifier of the packet correctly" do
      expect(packet.client_id).to eq('12345678901234567890123')
      expect(packet.client_id.encoding.to_s).to eq('UTF-8')
    end

    it "should set the Will QoS of the packet correctly" do
      expect(packet.will_qos).to eq(2)
    end

    it "should set the Will retain flag of the packet correctly" do
      expect(packet.will_retain).to be_truthy
    end

    it "should set the Will topic of the packet correctly" do
      expect(packet.will_topic).to eq('will_topic')
      expect(packet.will_topic.encoding.to_s).to eq('UTF-8')
    end

    it "should set the Will payload of the packet correctly" do
      expect(packet.will_payload).to eq('will_message')
      expect(packet.will_payload.encoding.to_s).to eq('UTF-8')
    end

    it "should set the Username of the packet correctly" do
      expect(packet.username).to eq('user0123456789')
      expect(packet.username.encoding.to_s).to eq('UTF-8')
    end

    it "should set the Username of the packet correctly" do
      expect(packet.password).to eq('pass0123456789')
      expect(packet.password.encoding.to_s).to eq('UTF-8')
    end
  end

  describe "when parsing packet with an unknown protocol name" do
    it "should raise a protocol exception" do
      expect {
        packet = MQTT::Packet.parse(
          "\x10\x16\x00\x06FooBar\x03\x00\x00\x0a\x00\x08myclient"
        )
      }.to raise_error(
        MQTT::ProtocolException,
        "Unsupported protocol: FooBar/3"
      )
    end
  end

  describe "when parsing packet with an unknown protocol level" do
    it "should raise a protocol exception" do
      expect {
        packet = MQTT::Packet.parse(
          "\x10\x16\x00\x06MQIsdp\x02\x00\x00\x0a\x00\x08myclient"
        )
      }.to raise_error(
        MQTT::ProtocolException,
        "Unsupported protocol: MQIsdp/2"
      )
    end
  end

  describe "when parsing packet with invalid fixed header flags" do
    it "should raise a protocol exception" do
      expect {
        MQTT::Packet.parse(
          "\x13\x16\x00\x06MQIsdp\x03\x00\x00\x0a\x00\x08myclient"
        )
      }.to raise_error(
        MQTT::ProtocolException,
        "Invalid flags in CONNECT packet header"
      )
    end
  end

  describe "when calling the inspect method" do
    it "should output correct string for the default options" do
      packet = MQTT::Packet::Connect.new
      expect(packet.inspect).to eq("#<MQTT::Packet::Connect: keep_alive=15, clean, client_id=''>")
    end

    it "should output correct string when parameters are given" do
      packet = MQTT::Packet::Connect.new(
        :keep_alive => 10,
        :client_id => 'c123',
        :clean_session => false,
        :username => 'foo'
      )
      expect(packet.inspect).to eq("#<MQTT::Packet::Connect: keep_alive=10, client_id='c123', username='foo'>")
    end
  end

  describe "deprecated attributes" do
    it "should still have a protocol_version method that is that same as protocol_level" do
      packet = MQTT::Packet::Connect.new
      packet.protocol_version = 5
      expect(packet.protocol_version).to eq(5)
      expect(packet.protocol_level).to eq(5)
      packet.protocol_version = 4
      expect(packet.protocol_version).to eq(4)
      expect(packet.protocol_level).to eq(4)
    end
  end
end

describe MQTT::Packet::Connack do

  describe "when setting attributes on a packet" do
    let(:packet) {  MQTT::Packet::Connack.new }

    it "should let you change the session present flag of a packet" do
      packet.session_present = true
      expect(packet.session_present).to be_truthy
    end

    it "should let you change the session present flag of a packet using an integer" do
      packet.session_present = 1
      expect(packet.session_present).to be_truthy
    end

    it "should let you change the return code of a packet" do
      packet.return_code = 3
      expect(packet.return_code).to eq(3)
    end
  end

  describe "when serialising a packet" do
    it "should output the correct bytes for a sucessful connection acknowledgement packet without Session Present set" do
      packet = MQTT::Packet::Connack.new( :return_code => 0x00, :session_present => false )
      expect(packet.to_s).to eq("\x20\x02\x00\x00")
    end

    it "should output the correct bytes for a sucessful connection acknowledgement packet with Session Present set" do
      packet = MQTT::Packet::Connack.new( :return_code => 0x00, :session_present => true )
      expect(packet.to_s).to eq("\x20\x02\x01\x00")
    end
  end

  describe "when parsing a successful Connection Accepted packet" do
    let(:packet) do
      MQTT::Packet.parse( "\x20\x02\x00\x00" )
    end

    it "should correctly create the right type of packet object" do
      expect(packet.class).to eq(MQTT::Packet::Connack)
    end

    it "should set the fixed header flags of the packet correctly" do
      expect(packet.flags).to eq([false, false, false, false])
    end

    it "should set the Session Pression flag of the packet correctly" do
      expect(packet.session_present).to eq(false)
    end

    it "should set the return code of the packet correctly" do
      expect(packet.return_code).to eq(0x00)
    end

    it "should set the return message of the packet correctly" do
      expect(packet.return_msg).to match(/Connection Accepted/i)
    end
  end

  describe "when parsing a successful Connection Accepted packet with Session Present set" do
    let(:packet) do
      MQTT::Packet.parse( "\x20\x02\x01\x00" )
    end

    it "should correctly create the right type of packet object" do
      expect(packet.class).to eq(MQTT::Packet::Connack)
    end

    it "should set the fixed header flags of the packet correctly" do
      expect(packet.flags).to eq([false, false, false, false])
    end

    it "should set the Session Pression flag of the packet correctly" do
      expect(packet.session_present).to eq(true)
    end

    it "should set the return code of the packet correctly" do
      expect(packet.return_code).to eq(0x00)
    end

    it "should set the return message of the packet correctly" do
      expect(packet.return_msg).to match(/Connection Accepted/i)
    end
  end

  describe "when parsing a unacceptable protocol version packet" do
    let(:packet) do
      MQTT::Packet.parse( "\x20\x02\x00\x01" )
    end

    it "should correctly create the right type of packet object" do
      expect(packet.class).to eq(MQTT::Packet::Connack)
    end

    it "should set the return code of the packet correctly" do
      expect(packet.return_code).to eq(0x01)
    end

    it "should set the return message of the packet correctly" do
      expect(packet.return_msg).to match(/unacceptable protocol version/i)
    end
  end

  describe "when parsing a client identifier rejected packet" do
    let(:packet) { MQTT::Packet.parse( "\x20\x02\x00\x02" ) }

    it "should correctly create the right type of packet object" do
      expect(packet.class).to eq(MQTT::Packet::Connack)
    end

    it "should set the return code of the packet correctly" do
      expect(packet.return_code).to eq(0x02)
    end

    it "should set the return message of the packet correctly" do
      expect(packet.return_msg).to match(/client identifier rejected/i)
    end
  end

  describe "when parsing a server unavailable packet" do
    let(:packet) do
      MQTT::Packet.parse( "\x20\x02\x00\x03" )
    end

    it "should correctly create the right type of packet object" do
      expect(packet.class).to eq(MQTT::Packet::Connack)
    end

    it "should set the return code of the packet correctly" do
      expect(packet.return_code).to eq(0x03)
    end

    it "should set the return message of the packet correctly" do
      expect(packet.return_msg).to match(/server unavailable/i)
    end
  end

  describe "when parsing a server unavailable packet" do
    let(:packet) do
      MQTT::Packet.parse( "\x20\x02\x00\x04" )
    end

    it "should correctly create the right type of packet object" do
      expect(packet.class).to eq(MQTT::Packet::Connack)
    end

    it "should set the return code of the packet correctly" do
      expect(packet.return_code).to eq(0x04)
    end

    it "should set the return message of the packet correctly" do
      expect(packet.return_msg).to match(/bad user name or password/i)
    end
  end

  describe "when parsing a server unavailable packet" do
    let(:packet) do
      MQTT::Packet.parse( "\x20\x02\x00\x05" )
    end

    it "should correctly create the right type of packet object" do
      expect(packet.class).to eq(MQTT::Packet::Connack)
    end

    it "should set the return code of the packet correctly" do
      expect(packet.return_code).to eq(0x05)
    end

    it "should set the return message of the packet correctly" do
      expect(packet.return_msg).to match(/not authorised/i)
    end
  end

  describe "when parsing an unknown connection refused packet" do
    let(:packet) { MQTT::Packet.parse( "\x20\x02\x00\x10" ) }

    it "should correctly create the right type of packet object" do
      expect(packet.class).to eq(MQTT::Packet::Connack)
    end

    it "should set the return code of the packet correctly" do
      expect(packet.return_code).to eq(0x10)
    end

    it "should set the return message of the packet correctly" do
      expect(packet.return_msg).to match(/Connection refused: error code 16/i)
    end
  end

  describe "when parsing packet with invalid Connack flags set" do
    it "should raise an exception" do
      expect {
        packet = MQTT::Packet.parse( "\x20\x02\xff\x05" )
      }.to raise_error(
        MQTT::ProtocolException,
        "Invalid flags in Connack variable header"
      )
    end
  end

  describe "when parsing packet with extra bytes on the end" do
    it "should raise an exception" do
      expect {
        packet = MQTT::Packet.parse( "\x20\x03\x00\x00\x00" )
      }.to raise_error(
        MQTT::ProtocolException,
        "Extra bytes at end of Connect Acknowledgment packet"
      )
    end
  end

  describe "when parsing packet with invalid fixed header flags" do
    it "should raise a protocol exception" do
      expect {
        MQTT::Packet.parse( "\x23\x02\x00\x00" )
      }.to raise_error(
        MQTT::ProtocolException,
        "Invalid flags in CONNACK packet header"
      )
    end
  end

  describe "when calling the inspect method" do
    it "should output the right string when the return code is 0" do
      packet = MQTT::Packet::Connack.new( :return_code => 0x00 )
      expect(packet.inspect).to eq("#<MQTT::Packet::Connack: 0x00>")
    end
    it "should output the right string when the return code is 0x0F" do
      packet = MQTT::Packet::Connack.new( :return_code => 0x0F )
      expect(packet.inspect).to eq("#<MQTT::Packet::Connack: 0x0F>")
    end
  end
end

describe MQTT::Packet::Puback do
  describe "when serialising a packet" do
    it "should output the correct bytes for a packet with no flags" do
      packet = MQTT::Packet::Puback.new( :id => 0x1234 )
      expect(packet.to_s).to eq("\x40\x02\x12\x34")
    end
  end

  describe "when parsing a packet" do
    let(:packet) { MQTT::Packet.parse( "\x40\x02\x12\x34" ) }

    it "should correctly create the right type of packet object" do
      expect(packet.class).to eq(MQTT::Packet::Puback)
    end

    it "should set the message id of the packet correctly" do
      expect(packet.id).to eq(0x1234)
    end
  end

  describe "when parsing packet with extra bytes on the end" do
    it "should raise an exception" do
      expect {
        packet = MQTT::Packet.parse( "\x40\x03\x12\x34\x00" )
      }.to raise_error(
        MQTT::ProtocolException,
        "Extra bytes at end of Publish Acknowledgment packet"
      )
    end
  end

  describe "when parsing packet with invalid fixed header flags" do
    it "should raise a protocol exception" do
      expect {
        MQTT::Packet.parse( "\x43\x02\x12\x34" )
      }.to raise_error(
        MQTT::ProtocolException,
        "Invalid flags in PUBACK packet header"
      )
    end
  end

  it "should output the right string when calling inspect" do
    packet = MQTT::Packet::Puback.new( :id => 0x1234 )
    expect(packet.inspect).to eq("#<MQTT::Packet::Puback: 0x1234>")
  end
end

describe MQTT::Packet::Pubrec do
  describe "when serialising a packet" do
    it "should output the correct bytes for a packet with no flags" do
      packet = MQTT::Packet::Pubrec.new( :id => 0x1234 )
      expect(packet.to_s).to eq("\x50\x02\x12\x34")
    end
  end

  describe "when parsing a packet" do
    let(:packet) { MQTT::Packet.parse( "\x50\x02\x12\x34" ) }

    it "should correctly create the right type of packet object" do
      expect(packet.class).to eq(MQTT::Packet::Pubrec)
    end

    it "should set the message id of the packet correctly" do
      expect(packet.id).to eq(0x1234)
    end
  end

  describe "when parsing packet with extra bytes on the end" do
    it "should raise an exception" do
      expect {
        packet = MQTT::Packet.parse( "\x50\x03\x12\x34\x00" )
      }.to raise_error(
        MQTT::ProtocolException,
        "Extra bytes at end of Publish Received packet"
      )
    end
  end

  describe "when parsing packet with invalid fixed header flags" do
    it "should raise a protocol exception" do
      expect {
        MQTT::Packet.parse( "\x53\x02\x12\x34" )
      }.to raise_error(
        MQTT::ProtocolException,
        "Invalid flags in PUBREC packet header"
      )
    end
  end

  it "should output the right string when calling inspect" do
    packet = MQTT::Packet::Pubrec.new( :id => 0x1234 )
    expect(packet.inspect).to eq("#<MQTT::Packet::Pubrec: 0x1234>")
  end
end

describe MQTT::Packet::Pubrel do
  describe "when serialising a packet" do
    it "should output the correct bytes for a packet with no flags" do
      packet = MQTT::Packet::Pubrel.new( :id => 0x1234 )
      expect(packet.to_s).to eq("\x62\x02\x12\x34")
    end
  end

  describe "when parsing a packet" do
    let(:packet) { MQTT::Packet.parse( "\x62\x02\x12\x34" ) }

    it "should correctly create the right type of packet object" do
      expect(packet.class).to eq(MQTT::Packet::Pubrel)
    end

    it "should set the message id of the packet correctly" do
      expect(packet.id).to eq(0x1234)
    end
  end

  describe "when parsing packet with extra bytes on the end" do
    it "should raise an exception" do
      expect {
        packet = MQTT::Packet.parse( "\x62\x03\x12\x34\x00" )
      }.to raise_error(
        MQTT::ProtocolException,
        "Extra bytes at end of Publish Release packet"
      )
    end
  end

  describe "when parsing packet with invalid fixed header flags" do
    it "should raise a protocol exception" do
      expect {
        MQTT::Packet.parse( "\x60\x02\x12\x34" )
      }.to raise_error(
        MQTT::ProtocolException,
        "Invalid flags in PUBREL packet header"
      )
    end
  end

  it "should output the right string when calling inspect" do
    packet = MQTT::Packet::Pubrel.new( :id => 0x1234 )
    expect(packet.inspect).to eq("#<MQTT::Packet::Pubrel: 0x1234>")
  end
end

describe MQTT::Packet::Pubcomp do
  describe "when serialising a packet" do
    it "should output the correct bytes for a packet with no flags" do
      packet = MQTT::Packet::Pubcomp.new( :id => 0x1234 )
      expect(packet.to_s).to eq("\x70\x02\x12\x34")
    end
  end

  describe "when parsing a packet" do
    let(:packet) { MQTT::Packet.parse( "\x70\x02\x12\x34" ) }

    it "should correctly create the right type of packet object" do
      expect(packet.class).to eq(MQTT::Packet::Pubcomp)
    end

    it "should set the message id of the packet correctly" do
      expect(packet.id).to eq(0x1234)
    end
  end

  describe "when parsing packet with extra bytes on the end" do
    it "should raise an exception" do
      expect {
        MQTT::Packet.parse( "\x70\x03\x12\x34\x00" )
      }.to raise_error(
        MQTT::ProtocolException,
        "Extra bytes at end of Publish Complete packet"
      )
    end
  end

  describe "when parsing packet with invalid fixed header flags" do
    it "should raise a protocol exception" do
      expect {
        MQTT::Packet.parse( "\x72\x02\x12\x34" )
      }.to raise_error(
        MQTT::ProtocolException,
        "Invalid flags in PUBCOMP packet header"
      )
    end
  end

  it "should output the right string when calling inspect" do
    packet = MQTT::Packet::Pubcomp.new( :id => 0x1234 )
    expect(packet.inspect).to eq("#<MQTT::Packet::Pubcomp: 0x1234>")
  end
end

describe MQTT::Packet::Subscribe do
  describe "setting the packet's topics" do
    let(:packet)  { MQTT::Packet::Subscribe.new }

    it "should be able to set the topics from a String 'a/b'" do
      packet.topics = 'a/b'
      expect(packet.topics).to eq([["a/b", 0]])
    end

    it "should be able to set the multiple topics from an array ['a/b', 'b/c']" do
      packet.topics = ['a/b', 'b/c']
      expect(packet.topics).to eq([["a/b", 0], ['b/c', 0]])
    end

    it "should be able to set the topics from a Hash {'a/b' => 0, 'b/c' => 1}" do
      packet.topics = {'a/b' => 0, 'b/c' => 1}
      expect(packet.topics).to eq([["a/b", 0], ["b/c", 1]])
    end

    it "should be able to set the topics from a single level array ['a/b', 0]" do
      packet.topics = ['a/b', 0]
      expect(packet.topics).to eq([["a/b", 0]])
    end

    it "should be able to set the topics from a two level array [['a/b' => 0], ['b/c' => 1]]" do
      packet.topics = [['a/b', 0], ['b/c', 1]]
      expect(packet.topics).to eq([['a/b', 0], ['b/c', 1]])
    end

    it "should raise an exception when setting topic with a non-string" do
      expect {
        packet.topics = 56
      }.to raise_error(
        'Invalid topics input: 56'
      )
    end
  end

  describe "when serialising a packet" do
    it "should output the correct bytes for a packet with a single topic" do
      packet = MQTT::Packet::Subscribe.new( :id => 1, :topics => 'a/b' )
      expect(packet.to_s).to eq("\x82\x08\x00\x01\x00\x03a/b\x00")
    end

    it "should output the correct bytes for a packet with multiple topics" do
      packet = MQTT::Packet::Subscribe.new( :id => 6, :topics => [['a/b', 0], ['c/d', 1]] )
      expect(packet.to_s).to eq("\x82\x0e\000\x06\x00\x03a/b\x00\x00\x03c/d\x01")
    end

    it "should raise an exception when no topics are given" do
      expect {
        MQTT::Packet::Subscribe.new.to_s
      }.to raise_error(
        'no topics given when serialising packet'
      )
    end
  end

  describe "when parsing a packet with a single topic" do
    let(:packet) { MQTT::Packet.parse( "\x82\x08\x00\x01\x00\x03a/b\x00" ) }

    it "should correctly create the right type of packet object" do
      expect(packet.class).to eq(MQTT::Packet::Subscribe)
    end

    it "should set the fixed header flags of the packet correctly" do
      expect(packet.flags).to eq([false, true, false, false])
    end

    it "should set the Message ID correctly" do
      expect(packet.id).to eq(1)
    end

    it "should set the topic name correctly" do
      expect(packet.topics).to eq([['a/b',0]])
    end
  end

  describe "when parsing a packet with a two topics" do
    let(:packet) { MQTT::Packet.parse( "\x82\x0e\000\x06\x00\x03a/b\x00\x00\x03c/d\x01" ) }

    it "should correctly create the right type of packet object" do
      expect(packet.class).to eq(MQTT::Packet::Subscribe)
    end

    it "should set the fixed header flags of the packet correctly" do
      expect(packet.flags).to eq([false, true, false, false])
    end

    it "should set the Message ID correctly" do
      expect(packet.id).to eq(6)
    end

    it "should set the topic name correctly" do
      expect(packet.topics).to eq([['a/b',0],['c/d',1]])
    end
  end

  describe "when parsing packet with invalid fixed header flags" do
    it "should raise a protocol exception" do
      expect {
        MQTT::Packet.parse( "\x80\x08\x00\x01\x00\x03a/b\x00" )
      }.to raise_error(
        MQTT::ProtocolException,
        "Invalid flags in SUBSCRIBE packet header"
      )
    end
  end

  describe "when calling the inspect method" do
    it "should output correct string for a single topic" do
      packet = MQTT::Packet::Subscribe.new(:topics => 'test')
      expect(packet.inspect).to eq("#<MQTT::Packet::Subscribe: 0x00, 'test':0>")
    end

    it "should output correct string for multiple topics" do
      packet = MQTT::Packet::Subscribe.new(:topics => {'a' => 1, 'b' => 0, 'c' => 2})
      expect(packet.inspect).to eq("#<MQTT::Packet::Subscribe: 0x00, 'a':1, 'b':0, 'c':2>")
    end
  end
end

describe MQTT::Packet::Suback do
  describe "when serialising a packet" do
    it "should output the correct bytes for an acknowledgement to a single topic" do
      packet = MQTT::Packet::Suback.new( :id => 5, :return_codes => 0 )
      expect(packet.to_s).to eq("\x90\x03\x00\x05\x00")
    end

    it "should output the correct bytes for an acknowledgement to a two topics" do
      packet = MQTT::Packet::Suback.new( :id => 6 , :return_codes => [0,1] )
      expect(packet.to_s).to eq("\x90\x04\x00\x06\x00\x01")
    end

    it "should raise an exception when no granted QoSs are given" do
      expect {
        MQTT::Packet::Suback.new( :id => 7 ).to_s
      }.to raise_error(
        'no granted QoS given when serialising packet'
      )
    end

    it "should raise an exception if the granted QoS is not an integer" do
      expect {
        MQTT::Packet::Suback.new( :id => 8, :return_codes => :foo ).to_s
      }.to raise_error(
        'return_codes should be an integer or an array of return codes'
      )
    end
  end

  describe "when parsing a packet with a single QoS value of 0" do
    let(:packet) { MQTT::Packet.parse( "\x90\x03\x12\x34\x00" ) }

    it "should correctly create the right type of packet object" do
      expect(packet.class).to eq(MQTT::Packet::Suback)
    end

    it "should set the message id of the packet correctly" do
      expect(packet.id).to eq(0x1234)
    end

    it "should set the Granted QoS of the packet correctly" do
      expect(packet.return_codes).to eq([0])
    end
  end

  describe "when parsing a packet with two QoS values" do
    let(:packet) { MQTT::Packet.parse( "\x90\x04\x12\x34\x01\x01" ) }

    it "should correctly create the right type of packet object" do
      expect(packet.class).to eq(MQTT::Packet::Suback)
    end

    it "should set the message id of the packet correctly" do
      expect(packet.id).to eq(0x1234)
    end

    it "should set the Granted QoS of the packet correctly" do
      expect(packet.return_codes).to eq([1,1])
    end
  end

  describe "when parsing packet with invalid fixed header flags" do
    it "should raise a protocol exception" do
      expect {
        MQTT::Packet.parse( "\x92\x03\x12\x34\x00" )
      }.to raise_error(
        MQTT::ProtocolException,
        "Invalid flags in SUBACK packet header"
      )
    end
  end

  describe "when calling the inspect method" do
    it "should output correct string for a single granted qos" do
      packet = MQTT::Packet::Suback.new(:id => 0x1234, :return_codes => 0)
      expect(packet.inspect).to eq("#<MQTT::Packet::Suback: 0x1234, rc=0x00>")
    end

    it "should output correct string for multiple topics" do
      packet = MQTT::Packet::Suback.new(:id => 0x1235, :return_codes => [0,1,2])
      expect(packet.inspect).to eq("#<MQTT::Packet::Suback: 0x1235, rc=0x00,0x01,0x02>")
    end
  end

  describe "deprecated attributes" do
    it "should still have a granted_qos method that is that same as return_codes" do
      packet = MQTT::Packet::Suback.new
      packet.granted_qos = [0,1,2]
      expect(packet.granted_qos).to eq([0,1,2])
      expect(packet.return_codes).to eq([0,1,2])
      packet.return_codes = [0,1,0]
      expect(packet.granted_qos).to eq([0,1,0])
      expect(packet.return_codes).to eq([0,1,0])
    end
  end
end

describe MQTT::Packet::Unsubscribe do
  describe "when serialising a packet" do
    it "should output the correct bytes for a packet with single topic" do
      packet = MQTT::Packet::Unsubscribe.new( :id => 5, :topics => 'a/b' )
      expect(packet.to_s).to eq("\xa2\x07\x00\x05\x00\x03a/b")
    end

    it "should output the correct bytes for a packet with multiple topics" do
      packet = MQTT::Packet::Unsubscribe.new( :id => 6, :topics => ['a/b','c/d'] )
      expect(packet.to_s).to eq("\xa2\x0c\000\006\000\003a/b\000\003c/d")
    end

    it "should raise an exception when no topics are given" do
      expect {
        MQTT::Packet::Unsubscribe.new.to_s
      }.to raise_error(
        'no topics given when serialising packet'
      )
    end
  end

  describe "when parsing a packet" do
    let(:packet) { MQTT::Packet.parse( "\xa2\f\000\005\000\003a/b\000\003c/d" ) }

    it "should correctly create the right type of packet object" do
      expect(packet.class).to eq(MQTT::Packet::Unsubscribe)
    end

    it "should set the fixed header flags of the packet correctly" do
      expect(packet.flags).to eq([false, true, false, false])
    end

    it "should set the topic name correctly" do
      expect(packet.topics).to eq(['a/b','c/d'])
    end
  end

  describe "when parsing packet with invalid fixed header flags" do
    it "should raise a protocol exception" do
      expect {
        MQTT::Packet.parse( "\xa0\x07\x00\x05\x00\x03a/b" )
      }.to raise_error(
        MQTT::ProtocolException,
        "Invalid flags in UNSUBSCRIBE packet header"
      )
    end
  end

  describe "when calling the inspect method" do
    it "should output correct string for a single topic" do
      packet = MQTT::Packet::Unsubscribe.new(:topics => 'test')
      expect(packet.inspect).to eq("#<MQTT::Packet::Unsubscribe: 0x00, 'test'>")
    end

    it "should output correct string for multiple topics" do
      packet = MQTT::Packet::Unsubscribe.new( :id => 42, :topics => ['a', 'b', 'c'] )
      expect(packet.inspect).to eq("#<MQTT::Packet::Unsubscribe: 0x2A, 'a', 'b', 'c'>")
    end
  end
end

describe MQTT::Packet::Unsuback do
  describe "when serialising a packet" do
    it "should output the correct bytes for a packet with no flags" do
      packet = MQTT::Packet::Unsuback.new( :id => 0x1234 )
      expect(packet.to_s).to eq("\xB0\x02\x12\x34")
    end
  end

  describe "when parsing a packet" do
    let(:packet) do
      MQTT::Packet.parse( "\xB0\x02\x12\x34" )
    end

    it "should correctly create the right type of packet object" do
      expect(packet.class).to eq(MQTT::Packet::Unsuback)
    end

    it "should set the message id of the packet correctly" do
      expect(packet.id).to eq(0x1234)
    end
  end

  describe "when parsing packet with extra bytes on the end" do
    it "should raise an exception" do
      expect {
        packet = MQTT::Packet.parse( "\xB0\x03\x12\x34\x00" )
      }.to raise_error(
        MQTT::ProtocolException,
        "Extra bytes at end of Unsubscribe Acknowledgment packet"
      )
    end
  end

  describe "when parsing packet with invalid fixed header flags" do
    it "should raise a protocol exception" do
      expect {
        MQTT::Packet.parse( "\xB2\x02\x12\x34" )
      }.to raise_error(
        MQTT::ProtocolException,
        "Invalid flags in UNSUBACK packet header"
      )
    end
  end

  it "should output the right string when calling inspect" do
    packet = MQTT::Packet::Unsuback.new( :id => 0x1234 )
    expect(packet.inspect).to eq("#<MQTT::Packet::Unsuback: 0x1234>")
  end
end

describe MQTT::Packet::Pingreq do
  describe "when serialising a packet" do
    it "should output the correct bytes for a packet with no flags" do
      packet = MQTT::Packet::Pingreq.new
      expect(packet.to_s).to eq("\xC0\x00")
    end
  end

  describe "when parsing a packet" do
    it "should correctly create the right type of packet object" do
      packet = MQTT::Packet.parse( "\xC0\x00" )
      expect(packet.class).to eq(MQTT::Packet::Pingreq)
    end

    it "should raise an exception if the packet has a payload" do
      expect {
        MQTT::Packet.parse( "\xC0\x05hello" )
      }.to raise_error(
        'Extra bytes at end of Ping Request packet'
      )
    end
  end

  describe "when parsing packet with invalid fixed header flags" do
    it "should raise a protocol exception" do
      expect {
        MQTT::Packet.parse( "\xC2\x00" )
      }.to raise_error(
        MQTT::ProtocolException,
        "Invalid flags in PINGREQ packet header"
      )
    end
  end

  it "should output the right string when calling inspect" do
    packet = MQTT::Packet::Pingreq.new
    expect(packet.inspect).to eq("#<MQTT::Packet::Pingreq>")
  end
end

describe MQTT::Packet::Pingresp do
  describe "when serialising a packet" do
    it "should output the correct bytes for a packet with no flags" do
      packet = MQTT::Packet::Pingresp.new
      expect(packet.to_s).to eq("\xD0\x00")
    end
  end

  describe "when parsing a packet" do
    it "should correctly create the right type of packet object" do
      packet = MQTT::Packet.parse( "\xD0\x00" )
      expect(packet.class).to eq(MQTT::Packet::Pingresp)
    end

    it "should raise an exception if the packet has a payload" do
      expect {
        MQTT::Packet.parse( "\xD0\x05hello" )
      }.to raise_error(
        'Extra bytes at end of Ping Response packet'
      )
    end
  end

  describe "when parsing packet with invalid fixed header flags" do
    it "should raise a protocol exception" do
      expect {
        MQTT::Packet.parse( "\xD2\x00" )
      }.to raise_error(
        MQTT::ProtocolException,
        "Invalid flags in PINGRESP packet header"
      )
    end
  end

  it "should output the right string when calling inspect" do
    packet = MQTT::Packet::Pingresp.new
    expect(packet.inspect).to eq("#<MQTT::Packet::Pingresp>")
  end
end


describe MQTT::Packet::Disconnect do
  describe "when serialising a packet" do
    it "should output the correct bytes for a packet with no flags" do
      packet = MQTT::Packet::Disconnect.new
      expect(packet.to_s).to eq("\xE0\x00")
    end
  end

  describe "when parsing a packet" do
    it "should correctly create the right type of packet object" do
      packet = MQTT::Packet.parse( "\xE0\x00" )
      expect(packet.class).to eq(MQTT::Packet::Disconnect)
    end

    it "should raise an exception if the packet has a payload" do
      expect {
        MQTT::Packet.parse( "\xE0\x05hello" )
      }.to raise_error(
        'Extra bytes at end of Disconnect packet'
      )
    end
  end

  describe "when parsing packet with invalid fixed header flags" do
    it "should raise a protocol exception" do
      expect {
        MQTT::Packet.parse( "\xE2\x00" )
      }.to raise_error(
        MQTT::ProtocolException,
        "Invalid flags in DISCONNECT packet header"
      )
    end
  end

  it "should output the right string when calling inspect" do
    packet = MQTT::Packet::Disconnect.new
    expect(packet.inspect).to eq("#<MQTT::Packet::Disconnect>")
  end
end


describe "Serialising an invalid packet" do
  context "that has a no type" do
    it "should raise an exception" do
      expect {
        MQTT::Packet.new.to_s
      }.to raise_error(
        RuntimeError,
        "Invalid packet type: MQTT::Packet"
      )
    end
  end
end

describe "Reading in an invalid packet from a socket" do
  context "that has 0 length" do
    it "should raise an exception" do
      expect {
        socket = StringIO.new
        MQTT::Packet.read(socket)
      }.to raise_error(
        MQTT::ProtocolException,
        "Failed to read byte from socket"
      )
    end
  end

  context "that has an incomplete packet length header" do
    it "should raise an exception" do
      expect {
        socket = StringIO.new("\x30\xFF")
        MQTT::Packet.read(socket)
      }.to raise_error(
        MQTT::ProtocolException,
        "Failed to read byte from socket"
      )
    end
  end

  context "that has the maximum number of bytes in the length header" do
    it "should raise an exception" do
      expect {
        socket = StringIO.new("\x30\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF")
        MQTT::Packet.read(socket)
      }.to raise_error(
        MQTT::ProtocolException,
        "Failed to parse packet - input buffer (4) is not the same as the body length header (268435455)"
      )
    end
  end
end

describe "Parsing an invalid packet" do
  context "that has no length" do
    it "should raise an exception" do
      expect {
        MQTT::Packet.parse( "" )
      }.to raise_error(
        MQTT::ProtocolException,
        "Invalid packet: less than 2 bytes long"
      )
    end
  end

  context "that has an invalid type identifier" do
    it "should raise an exception" do
      expect {
        MQTT::Packet.parse( "\x00\x00" )
      }.to raise_error(
        MQTT::ProtocolException,
        "Invalid packet type identifier: 0"
      )
    end
  end

  context "that has an incomplete packet length header" do
    it "should raise an exception" do
      expect {
        MQTT::Packet.parse( "\x30\xFF" )
      }.to raise_error(
        MQTT::ProtocolException,
        "The packet length header is incomplete"
      )
    end
  end

  context "that has too many bytes in the length field" do
    it "should raise an exception" do
      expect {
        MQTT::Packet.parse( "\x30\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF" )
      }.to raise_error(
        MQTT::ProtocolException,
        'Failed to parse packet - input buffer (4) is not the same as the body length header (268435455)'
      )
    end
  end

  context "that has a bigger buffer than expected" do
    it "should raise an exception" do
      expect {
        MQTT::Packet.parse( "\x30\x11\x00\x04testhello big world" )
      }.to raise_error(
        MQTT::ProtocolException,
        "Failed to parse packet - input buffer (21) is not the same as the body length header (17)"
      )
    end
  end

  context "that has a smaller buffer than expected" do
    it "should raise an exception" do
      expect {
        MQTT::Packet.parse( "\x30\x11\x00\x04testhello" )
      }.to raise_error(
        MQTT::ProtocolException,
        "Failed to parse packet - input buffer (11) is not the same as the body length header (17)"
      )
    end
  end
end
