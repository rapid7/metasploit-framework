#!/usr/bin/ruby

base = File.symlink?(__FILE__) ? File.readlink(__FILE__) : __FILE__
$:.unshift(File.join(File.dirname(base)))

require 'test/unit'
require 'pcaprub'

#
# Simple unit test, requires r00t.
#

class Pcap::UnitTest < Test::Unit::TestCase

	def test_version
		assert_equal(String, Pcap.version.class)
		puts "Pcaprub version: #{Pcap.version}"
	end
	
	def test_lookupdev
		assert_equal(String, Pcap.lookupdev.class)
		puts "Pcaprub default device: #{Pcap.lookupdev}"		
	end

	def test_lookupnet
		dev = Pcap.lookupdev
		assert_equal(Array, Pcap.lookupnet(dev).class)
		net = Pcap.lookupnet(dev)
		puts "Pcaprub net (#{dev}): #{net[0]} #{[net[1]].pack("N").unpack("H*")[0]}"		
	end
	
	def test_pcap_new
		o = Pcap.new
		assert_equal(Pcap, o.class)
	end
	
	def test_pcap_setfilter_bad
		e = nil
		o = Pcap.new
		begin
			o.setfilter("not ip")
		rescue ::Exception => e
		end
		
		assert_equal(e.class, ArgumentError)
	end

	def test_pcap_setfilter
		d = Pcap.lookupdev
		o = Pcap.open_live(d, 65535, true, 1)
		r = o.setfilter("not ip")
		assert_equal(Pcap, r.class)
	end

	def test_pcap_inject
		d = Pcap.lookupdev
		o = Pcap.open_live(d, 65535, true, 1)
		r = o.inject("X" * 512)
		assert_equal(512, r)
	end

	def test_pcap_datalink
		d = Pcap.lookupdev
		o = Pcap.open_live(d, 65535, true, 1)
		r = o.datalink
		assert_equal(Fixnum, r.class)
	end

	def test_pcap_snapshot
		d = Pcap.lookupdev
		o = Pcap.open_live(d, 1344, true, 1)
		r = o.snapshot
		assert_equal(1344, r)
	end

	def test_pcap_stats
		d = Pcap.lookupdev
		o = Pcap.open_live(d, 1344, true, 1)
		r = o.stats
		assert_equal(Hash, r.class)
	end

	def test_pcap_next
		d = Pcap.lookupdev
		o = Pcap.open_live(d, 1344, true, 1)

		@c = 0
		t = Thread.new { while(true); @c += 1; select(nil, nil, nil, 0.10); end; }

		require 'timeout'
		begin
		Timeout.timeout(10) do
			o.each do |pkt|
			end
		end
		rescue ::Timeout::Error
		end
		
		t.kill
		puts "Background thread ticked #{@c} times while capture was running"
		true
	end
							
end
