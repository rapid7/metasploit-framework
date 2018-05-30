# -*- coding:binary -*-
require 'rex/proto/proxy/socks5/packet'

RSpec.describe Rex::Proto::Proxy::Socks5::Packet do
  Socks5 = Rex::Proto::Proxy::Socks5

  describe "#address" do
    it "should parse an IPv4 address" do
      packet = Socks5::Packet.read("\x05\x02\x00\x01\x7f\x00\x00\x01\x00\x00")
      expect(packet.address_type).to eq(Socks5::Address::ADDRESS_TYPE_IPV4)
      expect(packet.address).to eq('127.0.0.1')
    end

    it "should parse an IPv6 address" do
      packet = Socks5::Packet.read("\x05\x02\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00")
      expect(packet.address_type).to eq(Socks5::Address::ADDRESS_TYPE_IPV6)
      expect(packet.address).to eq('::1')
    end

    it "should parse a domain name" do
      packet = Socks5::Packet.read("\x05\x02\x00\x03\x12www.metasploit.com\x00\x00")
      expect(packet.address_type).to eq(Socks5::Address::ADDRESS_TYPE_DOMAINNAME)
      expect(packet.address).to eq('www.metasploit.com')
    end
  end

  describe "#address=" do
    it "should set an IPv4 address" do
      packet = Socks5::Packet.new
      packet.address = '127.0.0.1'
      expect(packet.address_type).to eq(Socks5::Address::ADDRESS_TYPE_IPV4)
      expect(packet.address_array).to eq([0x7f, 0x00, 0x00, 0x01])
    end

    it "should set an IPv6 address" do
      packet = Socks5::Packet.new
      packet.address = '::1'
      expect(packet.address_type).to eq(Socks5::Address::ADDRESS_TYPE_IPV6)
      expect(packet.address_array).to eq([0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01])
    end

    it "should set a domain name" do
      packet = Socks5::Packet.new
      packet.address = 'www.metasploit.com'
      expect(packet.address_type).to eq(Socks5::Address::ADDRESS_TYPE_DOMAINNAME)
      expect(packet.address_array).to eq([0x77, 0x77, 0x77, 0x2e, 0x6d, 0x65, 0x74, 0x61, 0x73, 0x70, 0x6c, 0x6f, 0x69, 0x74, 0x2e, 0x63, 0x6f, 0x6d])
    end
  end

  describe "#command" do
    it "should parse a connect command" do
      packet = Socks5::Packet.read("\x05\x01\x00\x01\x7f\x00\x00\x01\x00\x00")
      expect(packet.command).to eq(Socks5::ServerClient::COMMAND_CONNECT)
    end

    it "should parse a bind command" do
      packet = Socks5::Packet.read("\x05\x02\x00\x01\x7f\x00\x00\x01\x00\x00")
      expect(packet.command).to eq(Socks5::ServerClient::COMMAND_BIND)
    end

    it "should parse a UDP associate command" do
      packet = Socks5::Packet.read("\x05\x03\x00\x01\x7f\x00\x00\x01\x00\x00")
      expect(packet.command).to eq(Socks5::ServerClient::COMMAND_UDP_ASSOCIATE)
    end
  end

  describe "#read" do
    it "should parse all fields" do
      packet = Socks5::Packet.read("\x05\x01\x00\x01\x7f\x00\x00\x01\x00\x50")
      expect(packet.version).to eq(Socks5::SOCKS_VERSION)
      expect(packet.command).to eq(Socks5::ServerClient::COMMAND_CONNECT)
      expect(packet.address_type).to eq(Socks5::Address::ADDRESS_TYPE_IPV4)
      expect(packet.address).to eq('127.0.0.1')
      expect(packet.port).to eq(80)
    end
  end

  describe "#to_binary_s" do
    it "should pack the data to a binary string" do
      packet = Socks5::Packet.new
      expect(packet.to_binary_s).to eq("\x05\x00\x00\x00\x00\x00")
    end
  end

  describe "#version" do
    it "should have the SOCKS5 version set by default" do
      packet = Socks5::Packet.new
      packet.version = Socks5::SOCKS_VERSION
    end
  end

end
