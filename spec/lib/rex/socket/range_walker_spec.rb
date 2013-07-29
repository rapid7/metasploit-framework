# -*- coding:binary -*-
require 'rex/socket/range_walker'

describe Rex::Socket::RangeWalker do
  it "should have a num_ips attribute" do
    walker = Rex::Socket::RangeWalker.new("")
    walker.should respond_to("num_ips")
    walker.should respond_to("length")
    walker.num_ips.should == walker.length
  end
  it "should handle single ipv6 addresses" do
    walker = Rex::Socket::RangeWalker.new("::1")
    walker.should be_valid
    walker.length.should == 1
  end

  it "should handle ranges" do
    walker = Rex::Socket::RangeWalker.new("10.1.1.1-2")
    walker.should be_valid
    walker.length.should == 2
    walker.next_ip.should == "10.1.1.1"
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
    walker.next_ip.should == "10.1.3.0"
    walker.should include("10.1.3.255")
    walker = Rex::Socket::RangeWalker.new("10.1.*.3")
    walker.should be_valid
    walker.length.should == 256
    walker.next_ip.should == "10.1.0.3"
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

  it "should yield all ips" do
    walker = Rex::Socket::RangeWalker.new("10.1.1.1,2,3")
    got = []
    walker.each { |ip|
      got.push ip
    }
    got.should == ["10.1.1.1", "10.1.1.2", "10.1.1.3"]
  end
end
