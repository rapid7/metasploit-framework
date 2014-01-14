# -*- coding:binary -*-
require 'rex/socket/range_walker'

describe Rex::Socket::RangeWalker do

  let(:args) { "::1" }
  subject(:walker) { described_class.new(args) }

  it { should respond_to(:length) }
  it { should respond_to(:valid?) }
  it { should respond_to(:each) }

  describe '.new' do

    context "with a hostname" do
      let(:args) { "localhost" }
      it { should be_valid }
      it { should have_at_least(1).address }
    end

    context "with a hostname and CIDR" do
      let(:args) { "localhost/24" }
      it { should be_valid }
      it { should have(256).addresses }
    end

    context "with an invalid hostname" do
      let(:args) { "asdf.foo." }
      it { should_not be_valid }
    end

    context "with an invalid hostname and CIDR" do
      let(:args) { "asdf.foo./24" }
      it { should_not be_valid }
    end

    context "with an IPv6 address range containing a scope" do
      let(:args) { "fe80::1%lo-fe80::100%lo" }
      it { should be_valid }
    end

    it "should handle single ipv6 addresses" do
      walker = Rex::Socket::RangeWalker.new("::1")
      walker.should be_valid
      walker.length.should == 1
    end

    it "should handle longform ranges" do
      walker = Rex::Socket::RangeWalker.new("10.1.1.1-10.1.1.2")
      walker.should be_valid
      walker.length.should == 2
      walker.next.should == "10.1.1.1"
    end

    context "with mulitple ranges" do
      let(:args) { "1.1.1.1-2 2.1-2.2.2 3.1-2.1-2.1 " }
      it { should be_valid }
      it { should have(8).addresses }
      it { should include("1.1.1.1") }
    end

    it "should handle ranges" do
      walker = Rex::Socket::RangeWalker.new("10.1.1.1-2")
      walker.should be_valid
      walker.length.should == 2
      walker.next.should == "10.1.1.1"
      walker = Rex::Socket::RangeWalker.new("10.1-2.1.1-2")
      walker.should be_valid
      walker.length.should == 4
      walker = Rex::Socket::RangeWalker.new("10.1-2.3-4.5-6")
      walker.should be_valid
      walker.length.should == 8
      walker.should include("10.1.3.5")
    end

    it 'should reject CIDR ranges with missing octets' do
      walker = Rex::Socket::RangeWalker.new('192.168/24')
      walker.should_not be_valid
    end

    it 'should reject a CIDR range with too many octets' do
      walker = Rex::Socket::RangeWalker.new('192.168.1.2.0/24')
      walker.should_not be_valid
    end

    it "should default the lower bound of a range to 0" do
      walker = Rex::Socket::RangeWalker.new("10.1.3.-17")
      walker.should be_valid
      walker.length.should == 18
      walker = Rex::Socket::RangeWalker.new("10.1.3.-255")
      walker.should be_valid
      walker.length.should == 256
    end

    it "should default the upper bound of a range to 255" do
      walker = Rex::Socket::RangeWalker.new("10.1.3.254-")
      walker.should be_valid
      walker.length.should == 2
    end

    it "should take * to mean 0-255" do
      walker = Rex::Socket::RangeWalker.new("10.1.3.*")
      walker.should be_valid
      walker.length.should == 256
      walker.next.should == "10.1.3.0"
      walker.should include("10.1.3.255")
      walker = Rex::Socket::RangeWalker.new("10.1.*.3")
      walker.should be_valid
      walker.length.should == 256
      walker.next.should == "10.1.0.3"
      walker.should include("10.1.255.3")
    end

    it "should handle lists" do
      #walker = Rex::Socket::RangeWalker.new("10.1.1.1,2")
      #walker.should be_valid
      #walker.length.should == 2
      walker = Rex::Socket::RangeWalker.new("10.1.1.1")
      walker.should be_valid
      walker.length.should == 1
      walker = Rex::Socket::RangeWalker.new("10.1.1.1,3")
      walker.should be_valid
      walker.length.should == 2
      walker.should_not include("10.1.1.2")
    end

    it "should produce the same ranges with * and 0-255" do
      a = Rex::Socket::RangeWalker.new("10.1.3.*")
      b = Rex::Socket::RangeWalker.new("10.1.3.0-255")
      a.ranges.should eq(b.ranges)
    end

    it "should handle ranges and lists together" do
      walker = Rex::Socket::RangeWalker.new("10.1.1.1-2,3")
      walker.should be_valid
      walker.length.should == 3
      walker = Rex::Socket::RangeWalker.new("10.1-2.1.1,2")
      walker.should be_valid
      walker.length.should == 4
      walker = Rex::Socket::RangeWalker.new("10.1,2.3,4.5,6")
      walker.length.should == 8
    end

    it "should handle cidr" do
      31.downto 16 do |bits|
        walker = Rex::Socket::RangeWalker.new("10.1.1.1/#{bits}")
        walker.should be_valid
        walker.length.should == (2**(32-bits))
      end
    end
  end

  describe '#each' do
    let(:args) { "10.1.1.1-2,2,3 10.2.2.2" }

    it "should yield all ips" do
      got = []
      walker.each { |ip|
        got.push ip
      }
      got.should == ["10.1.1.1", "10.1.1.2", "10.1.1.3", "10.2.2.2"]
    end

  end

  describe '#include_range?' do
    let(:args) { "10.1.1.*" }

    it "returns true for a sub-range" do
      other = described_class.new("10.1.1.1-255")
      walker.should be_include_range(other)
    end

  end

  describe '#next' do
    let(:args) { "10.1.1.1-5" }
    it "should return all addresses" do
      all = []
      while ip = walker.next
        all << ip
      end
      all.should == [ "10.1.1.1", "10.1.1.2", "10.1.1.3", "10.1.1.4", "10.1.1.5", ]
    end

    it "should not raise if called again after empty" do
      expect {
        (walker.length + 5).times { walker.next }
      }.not_to raise_error
    end

  end

end
