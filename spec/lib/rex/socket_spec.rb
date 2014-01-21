# -*- coding:binary -*-
require 'rex/socket/range_walker'

describe Rex::Socket do

  describe '.addr_itoa' do

    context 'with explicit v6' do
      it "should convert a number to a human-readable IPv6 address" do
        described_class.addr_itoa(1, true).should == "::1"
      end
    end

    context 'with explicit v4' do
      it "should convert a number to a human-readable IPv4 address" do
        described_class.addr_itoa(1, false).should == "0.0.0.1"
      end
    end

    context 'without explicit version' do
      it "should convert a number within the range of possible v4 addresses to a human-readable IPv4 address" do
        described_class.addr_itoa(0).should == "0.0.0.0"
        described_class.addr_itoa(1).should == "0.0.0.1"
        described_class.addr_itoa(0xffff_ffff).should == "255.255.255.255"
      end
      it "should convert a number larger than possible v4 addresses to a human-readable IPv6 address" do
        described_class.addr_itoa(0xfe80_0000_0000_0000_0000_0000_0000_0001).should == "fe80::1"
        described_class.addr_itoa(0x1_0000_0001).should == "::1:0:1"
      end
    end

  end

  describe '.addr_aton' do
    subject(:nbo) do
      described_class.addr_aton(try)
    end

    context 'with ipv6' do
      let(:try) { "fe80::1" }
      it { should be_a(String) }
      it { should have(16).bytes }
      it "should be in the right order" do
        nbo.should == "\xfe\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01"
      end
    end

    context 'with ipv4' do
      let(:try) { "127.0.0.1" }
      it { should be_a(String) }
      it { should have(4).bytes }
      it "should be in the right order" do
        nbo.should == "\x7f\x00\x00\x01"
      end
    end

    context 'with a hostname' do
      let(:try) { "localhost" }
      it "should resolve" do
        nbo.should be_a(String)
        nbo.encoding.should == Encoding.find('binary')
        [ 4, 16 ].should include(nbo.length)
      end
    end

  end

  describe '.compress_address' do

    subject(:compressed) do
      described_class.compress_address(try)
    end

    context 'with lots of single 0s' do
      let(:try) { "fe80:0:0:0:0:0:0:1" }
      it { should == "fe80::1" }
    end

  end

  describe '.getaddress' do

    subject { described_class.getaddress('whatever') }

    before(:each) do
      Socket.stub(:gethostbyname).and_return(['name', ['aliases'], response_afamily, *response_addresses])
    end

    context 'when ::Socket.gethostbyname returns IPv4 responses' do
      let(:response_afamily) { Socket::AF_INET }
      let(:response_addresses) { ["\x01\x01\x01\x01", "\x02\x02\x02\x02"] }

      it { should be_a(String) }
      it "should return the first ASCII address" do
        subject.should == "1.1.1.1"
      end
    end

    context 'when ::Socket.gethostbyname returns IPv6 responses' do
      let(:response_afamily) { Socket::AF_INET6 }
      let(:response_addresses) { ["\xfe\x80"+("\x00"*13)+"\x01", "\xfe\x80"+("\x00"*13)+"\x02"] }

      it { should be_a(String) }
      it "should return the first ASCII address" do
        subject.should == "fe80::1"
      end
    end

    context "with rubinius' bug returning ASCII addresses" do
      let(:response_afamily) { Socket::AF_INET }
      let(:response_addresses) { ["1.1.1.1", "2.2.2.2"] }

      it { should be_a(String) }
      it "should return the first ASCII address" do
        subject.should == "1.1.1.1"
      end

    end
  end

  describe '.getaddresses' do

    subject { described_class.getaddresses('whatever') }

    before(:each) do
      Socket.stub(:gethostbyname).and_return(['name', ['aliases'], response_afamily, *response_addresses])
    end

    context 'when ::Socket.gethostbyname returns IPv4 responses' do
      let(:response_afamily) { Socket::AF_INET }
      let(:response_addresses) { ["\x01\x01\x01\x01", "\x02\x02\x02\x02"] }

      it { should be_a(Array) }
      it { should have(2).addresses }
      it "should return the ASCII addresses" do
        subject.should include("1.1.1.1")
        subject.should include("2.2.2.2")
      end
    end

    context 'when ::Socket.gethostbyname returns IPv6 responses' do
      let(:response_afamily) { Socket::AF_INET6 }
      let(:response_addresses) { ["\xfe\x80"+("\x00"*13)+"\x01", "\xfe\x80"+("\x00"*13)+"\x02"] }

      it { should be_a(Array) }
      it { should have(2).addresses }
      it "should return the ASCII addresses" do
        subject.should include("fe80::1")
        subject.should include("fe80::2")
      end
    end

    context "with rubinius' bug returning ASCII addresses" do
      let(:response_afamily) { Socket::AF_INET }
      let(:response_addresses) { ["1.1.1.1", "2.2.2.2"] }

      it { should be_a(Array) }
      it { should have(2).addresses }
      it "should return the ASCII addresses" do
        subject.should include("1.1.1.1")
        subject.should include("2.2.2.2")
      end

    end
  end
end
