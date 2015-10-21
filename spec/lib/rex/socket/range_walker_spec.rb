# -*- coding:binary -*-
require 'rex/socket/range_walker'

RSpec.describe Rex::Socket::RangeWalker do

  let(:args) { "::1" }
  subject(:walker) { described_class.new(args) }

  it { is_expected.to respond_to(:length) }
  it { is_expected.to respond_to(:valid?) }
  it { is_expected.to respond_to(:each) }

  describe '.new' do

    context "with a hostname" do
      let(:args) { "localhost" }
      it { is_expected.to be_valid }
      it { expect(subject.length).to be >= 1 }
    end

    context "with a hostname and CIDR" do
      let(:args) { "localhost/24" }
      it { is_expected.to be_valid }
      it { expect(subject.length).to eq(256) }
    end

    context "with an invalid hostname" do
      let(:args) { "@!*^&.invalid-hostname-really." }
      it { is_expected.not_to be_valid }
    end

    context "with an invalid hostname and CIDR" do
      let(:args) { "@!*^&.invalid-hostname-really./24" }
      it { is_expected.not_to be_valid }
    end

    context "with an IPv6 address range containing a scope" do
      let(:args) { "fe80::1%lo-fe80::100%lo" }
      it { is_expected.to be_valid }
    end

    it "should handle single ipv6 addresses" do
      walker = Rex::Socket::RangeWalker.new("::1")
      expect(walker).to be_valid
      expect(walker.length).to eq 1
    end

    it "should handle longform ranges" do
      walker = Rex::Socket::RangeWalker.new("10.1.1.1-10.1.1.2")
      expect(walker).to be_valid
      expect(walker.length).to eq 2
      expect(walker.next).to eq "10.1.1.1"
    end

    context "with mulitple ranges" do
      let(:args) { "1.1.1.1-2 2.1-2.2.2 3.1-2.1-2.1 " }
      it { is_expected.to be_valid }
      it { expect(subject.length).to eq(8) }
      it { is_expected.to include("1.1.1.1") }
    end

    it "should handle ranges" do
      walker = Rex::Socket::RangeWalker.new("10.1.1.1-2")
      expect(walker).to be_valid
      expect(walker.length).to eq 2
      expect(walker.next).to eq "10.1.1.1"
      walker = Rex::Socket::RangeWalker.new("10.1-2.1.1-2")
      expect(walker).to be_valid
      expect(walker.length).to eq 4
      walker = Rex::Socket::RangeWalker.new("10.1-2.3-4.5-6")
      expect(walker).to be_valid
      expect(walker.length).to eq 8
      expect(walker).to include("10.1.3.5")
    end

    it 'should reject CIDR ranges with missing octets' do
      walker = Rex::Socket::RangeWalker.new('192.168/24')
      expect(walker).not_to be_valid
    end

    it 'should reject a CIDR range with too many octets' do
      walker = Rex::Socket::RangeWalker.new('192.168.1.2.0/24')
      expect(walker).not_to be_valid
    end

    it "should default the lower bound of a range to 0" do
      walker = Rex::Socket::RangeWalker.new("10.1.3.-17")
      expect(walker).to be_valid
      expect(walker.length).to eq 18
      walker = Rex::Socket::RangeWalker.new("10.1.3.-255")
      expect(walker).to be_valid
      expect(walker.length).to eq 256
    end

    it "should default the upper bound of a range to 255" do
      walker = Rex::Socket::RangeWalker.new("10.1.3.254-")
      expect(walker).to be_valid
      expect(walker.length).to eq 2
    end

    it "should take * to mean 0-255" do
      walker = Rex::Socket::RangeWalker.new("10.1.3.*")
      expect(walker).to be_valid
      expect(walker.length).to eq 256
      expect(walker.next).to eq "10.1.3.0"
      expect(walker).to include("10.1.3.255")
      walker = Rex::Socket::RangeWalker.new("10.1.*.3")
      expect(walker).to be_valid
      expect(walker.length).to eq 256
      expect(walker.next).to eq "10.1.0.3"
      expect(walker).to include("10.1.255.3")
    end

    it "should handle lists" do
      walker = Rex::Socket::RangeWalker.new("10.1.1.1")
      expect(walker).to be_valid
      expect(walker.length).to eq 1
      walker = Rex::Socket::RangeWalker.new("10.1.1.1,3")
      expect(walker).to be_valid
      expect(walker.length).to eq 2
      expect(walker).not_to include("10.1.1.2")
    end

    it "should produce the same ranges with * and 0-255" do
      a = Rex::Socket::RangeWalker.new("10.1.3.*")
      b = Rex::Socket::RangeWalker.new("10.1.3.0-255")
      expect(a.ranges).to eq(b.ranges)
    end

    it "should handle ranges and lists together" do
      walker = Rex::Socket::RangeWalker.new("10.1.1.1-2,3")
      expect(walker).to be_valid
      expect(walker.length).to eq 3
      walker = Rex::Socket::RangeWalker.new("10.1-2.1.1,2")
      expect(walker).to be_valid
      expect(walker.length).to eq 4
      walker = Rex::Socket::RangeWalker.new("10.1,2.3,4.5,6")
      expect(walker.length).to eq 8
    end

    it "should handle cidr" do
      31.downto 16 do |bits|
        walker = Rex::Socket::RangeWalker.new("10.1.1.1/#{bits}")
        expect(walker).to be_valid
        expect(walker.length).to eq (2**(32-bits))
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
      expect(got).to eq ["10.1.1.1", "10.1.1.2", "10.1.1.3", "10.2.2.2"]
    end

  end

  describe '#include_range?' do
    let(:args) { "10.1.1.*" }

    it "returns true for a sub-range" do
      other = described_class.new("10.1.1.1-255")
      expect(walker).to be_include_range(other)
    end

  end

  describe '#next' do
    let(:args) { "10.1.1.1-5" }
    it "should return all addresses" do
      all = []
      while ip = walker.next
        all << ip
      end
      expect(all).to eq [ "10.1.1.1", "10.1.1.2", "10.1.1.3", "10.1.1.4", "10.1.1.5", ]
    end

    it "should not raise if called again after empty" do
      expect {
        (walker.length + 5).times { walker.next }
      }.not_to raise_error
    end

  end

end
