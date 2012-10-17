$:.push("../../lib")
require 'rex'
require 'rex/socket'
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
		# Slow test on a 3.06 GHz proc
		#   ruby 1.9, ~ 11 seconds
		#   ruby 1.8.7, ~ 24 seconds
		#   ruby 1.8.6, ~ 23 seconds
		#walker = Rex::Socket::RangeWalker.new("10.0-255.0-255.0-255")
		#walker.should be_valid
		#walker.length.should == 256 * 256 * 256
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
		walker = Rex::Socket::RangeWalker.new("10.1.1.1/31")
		walker.should be_valid
		walker.length.should == 2
		walker = Rex::Socket::RangeWalker.new("10.1.1.1/30")
		walker.should be_valid
		walker.length.should == 4
		walker = Rex::Socket::RangeWalker.new("10.1.1.1/29")
		walker.should be_valid
		walker.length.should == 8
		walker = Rex::Socket::RangeWalker.new("10.1.1.1/28")
		walker.should be_valid
		walker.length.should == 16
		walker = Rex::Socket::RangeWalker.new("10.1.1.1/27")
		walker.should be_valid
		walker.length.should == 32
		walker = Rex::Socket::RangeWalker.new("10.1.1.1/26")
		walker.should be_valid
		walker.length.should == 64
		walker = Rex::Socket::RangeWalker.new("10.1.1.1/25")
		walker.should be_valid
		walker.length.should == 128
		pending("Decide whether cidr_crack should include 0")
		walker = Rex::Socket::RangeWalker.new("10.1.1.1/24")
		walker.should be_valid
		walker.length.should == 256
		walker = Rex::Socket::RangeWalker.new("10.1.1.1/23")
		walker.should be_valid
		walker.length.should == 512
	end

	it "should handle ipv6 cidr" do
		walker = Rex::Socket::RangeWalker.new("::1/127")
		walker.should be_valid
		walker.length.should == 2
		walker = Rex::Socket::RangeWalker.new("::1/122")
		walker.should be_valid
		walker.length.should == 2 ** 6
		walker = Rex::Socket::RangeWalker.new("::1/116")
		walker.should be_valid
		walker.length.should == 2 ** 12
	end

	#it "should handle ipv6 ranges" do
	#	pending("Need to define how this should be handled")
	#	walker = Rex::Socket::RangeWalker.new("::1-::1:1")
	#	walker.should be_valid
	#	walker.length.should == 2 ** 16
	#end

	it "should yield all ips" do
		walker = Rex::Socket::RangeWalker.new("10.1.1.1,2,3")
		got = []
		walker.each { |ip|
			got.push ip
		}
		got.should == ["10.1.1.1", "10.1.1.2", "10.1.1.3"]
	end
end
