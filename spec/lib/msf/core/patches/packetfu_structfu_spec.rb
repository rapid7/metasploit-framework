# -*- coding: binary -*-

require 'spec_helper'
require 'msf/core/patches/packetfu_structfu'

RSpec.describe 'StructFu#typecast backtrace-format shim' do
  # Field setters in PacketFu's various headers all run through
  # StructFu#typecast on their first assignment. If the shim does not match
  # the running Ruby's caller[0] format, the constructor raises before the
  # object is returned. One assertion per packet type the Capture and IPv6
  # mixins touch; a regression on any Ruby version re-breaks arp_sweep and
  # the surrounding scanner/spoof/dos families (see rapid7#21721).
  it 'constructs an ARPPacket without raising' do
    expect { PacketFu::ARPPacket.new }.not_to raise_error
  end

  it 'constructs a UDPPacket without raising' do
    expect { PacketFu::UDPPacket.new }.not_to raise_error
  end

  it 'constructs a TCPPacket without raising' do
    expect { PacketFu::TCPPacket.new }.not_to raise_error
  end

  it 'constructs an ICMPPacket without raising' do
    expect { PacketFu::ICMPPacket.new }.not_to raise_error
  end

  it 'constructs an IPv6Packet without raising' do
    expect { PacketFu::IPv6Packet.new }.not_to raise_error
  end

  it 'resolves the setter name from caller[0] regardless of backtrace format' do
    # Both Ruby 3.3- (`eth_proto=') and Ruby 3.4+ ('Klass#eth_proto=') must
    # match. Simulate the two shapes directly so this check does not depend
    # on which Ruby the suite is running under.
    old_style = "foo.rb:10:in `eth_proto='"
    new_style = "foo.rb:10:in 'PacketFu::EthHeader#eth_proto='"
    [old_style, new_style].each do |frame|
      expect(frame[/([A-Za-z0-9_]+)=['`]/, 1]).to eq('eth_proto')
    end
  end
end
