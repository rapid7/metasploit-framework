#!/usr/bin/env ruby
require 'test/unit'
$:.unshift File.join(File.expand_path(File.dirname(__FILE__)), "..", "lib")
require 'packetfu'


class CaptureTest < Test::Unit::TestCase

  def test_cap
    assert_nothing_raised { PacketFu::Capture }
  end

  def test_whoami
    assert_nothing_raised { PacketFu::Utils.whoami?(:iface => PacketFu::Utils.default_int) }
  end
  
  def test_new
    cap = PacketFu::Capture.new
    assert_kind_of PacketFu::Capture, cap
    cap = PacketFu::Capture.new(
      :filter => 'tcp and dst host 1.2.3.4'
    )
  end
  
  def test_filter
    daddr = PacketFu::Utils.rand_routable_daddr.to_s
    cap = PacketFu::Capture.new( :filter => "icmp and dst host #{daddr}")
    cap.start
    %x{ping -c 1 #{daddr}}
    sleep 1
    cap.save
    assert cap.array.size == 1
    pkt = PacketFu::Packet.parse(cap.array.first)
    assert pkt.ip_daddr == daddr
  end
  
  def test_no_filter
    daddr = PacketFu::Utils.rand_routable_daddr.to_s
    daddr2 = PacketFu::Utils.rand_routable_daddr.to_s
    cap = PacketFu::Capture.new
    cap.start
    %x{ping -c 1 #{daddr}}
    %x{ping -c 1 #{daddr2}}
    sleep 1
    cap.save
    assert cap.array.size > 1
  end

  def test_bpf_alias
    daddr = PacketFu::Utils.rand_routable_daddr.to_s
    cap = PacketFu::Capture.new( :filter => "icmp and dst host #{daddr}")
    assert cap.filter.object_id == cap.bpf.object_id
  end

end


# vim: nowrap sw=2 sts=0 ts=2 ff=unix ft=ruby
