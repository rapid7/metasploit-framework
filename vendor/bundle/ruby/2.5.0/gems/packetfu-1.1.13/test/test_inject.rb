#!/usr/bin/env ruby
require 'test/unit'
$:.unshift File.join(File.expand_path(File.dirname(__FILE__)), "..", "lib")
require 'packetfu'


class InjectTest < Test::Unit::TestCase

  def test_cap
    assert_nothing_raised { PacketFu::Capture }
  end

  def test_whoami
    assert_nothing_raised { PacketFu::Utils.whoami?(:iface => PacketFu::Utils.default_int) }
  end

  def test_to_w
    assert_equal(Process.euid, 0, "TEST FAIL: This test must be run as root")
    conf = PacketFu::Utils.whoami?(:iface => PacketFu::Utils.default_int)
    p = PacketFu::UDPPacket.new(:config => conf)
    p.udp_dport = 12345
    p.udp_sport = 12345
    p.payload = "PacketFu test packet"
    p.recalc
    assert p.to_w
  end

end


# vim: nowrap sw=2 sts=0 ts=2 ff=unix ft=ruby
