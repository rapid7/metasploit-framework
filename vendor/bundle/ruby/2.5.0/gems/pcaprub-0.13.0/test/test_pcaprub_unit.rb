#!/usr/bin/env ruby

base = File.symlink?(__FILE__) ? File.readlink(__FILE__) : __FILE__
$:.unshift(File.join(File.dirname(base)))


require File.expand_path '../test_helper.rb', __FILE__

#
# Simple unit test, requires r00t.
#

class Pcap::UnitTest < Test::Unit::TestCase
  def test_version
    assert_equal(String, Pcap.version.class)
    # puts "Pcaprub version: #{Pcap.version}"
  end

  def test_lookupdev
    assert_equal(String, Pcap.lookupdev.class)
    # puts "Pcaprub default device: #{Pcap.lookupdev}"
  end

  def test_lookupnet
    dev = Pcap.lookupdev
    assert_equal(Array, Pcap.lookupnet(dev).class)
    net = Pcap.lookupnet(dev)
    assert net
    # puts "Pcaprub net (#{dev}): #{net[0]} #{[net[1]].pack("N").unpack("H*")[0]}"
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

    assert_equal(e.class, PCAPRUB::PCAPRUBError)
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
    # UPDATE: TRAVIS CI is now on a new hardware platform.
    # Travis CI's virtual network interface does not support injection
    #if ENV['CI']
    #  assert_equal(-1,r)
    #else
    #  assert_equal(512, r)
    #end
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

    pkt_count = 0
    require 'timeout'
    begin
      Timeout.timeout(10) do
        o.each do |pkt|
          pkt_count += 1
        end
      end
    rescue ::Timeout::Error
    end

    t.kill
    # puts "Background thread ticked #{@c} times while capture was running"
    # puts "Captured #{pkt_count} packets"
    assert(0 < @c, "Background thread failed to tick while capture was running");
    true
  end

  def test_create_from_primitives
    d = Pcap.lookupdev
    o = Pcap.create(d).setsnaplen(65535).settimeout(100).setpromisc(true)
    assert_equal(o, o.activate)
    o.close
  end

  def test_set_datalink
    d = Pcap.lookupdev
    o = Pcap.open_live(d, 65535, true, -1)
    dls = o.listdatalinks
    begin
      assert_equal(o,o.setdatalink(dls.values.first))
    rescue PCAPRUB::LinkTypeError
      print "#{dls} - Data LinkType Binding issue in the environment (Skipping)"
      assert_equal(o,o)
    end
  end

  def test_monitor
    return if RUBY_PLATFORM =~ /mingw|win/
    d = Pcap.lookupdev
    o = Pcap.create(d)
    assert_equal(o, o.setmonitor(true))
  end

  def test_open_dead
    # No applied filters on OPEN_DEAD just compile checking
    o = Pcap.open_dead(Pcap::DLT_NULL, 65535)
    assert_nothing_raised do
      o.compile("ip host 1.2.3.4")
    end
    assert_raise PCAPRUB::BPFError do
      o.setfilter("ip host 1.2.3.5")
    end
  end

  def test_filter
    d = Pcap.lookupdev
    o = Pcap.create(d)
    o.activate
    assert_nothing_raised do
      o.compile("ip host 1.2.3.4")
    end
    assert_raise PCAPRUB::BPFError do
      o.compile("A non working filter")
    end
  end

  def test_lib_version
    v = Pcap.lib_version.split
    assert_equal "libpcap", v[0]
    assert_equal "version", v[1]
    assert_equal 3, v[2].split('.').size
  end
end
