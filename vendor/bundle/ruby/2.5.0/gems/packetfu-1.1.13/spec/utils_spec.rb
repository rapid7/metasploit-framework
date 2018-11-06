# -*- coding: binary -*-
require 'spec_helper'
require 'packetfu/protos/eth'
require 'packetfu/protos/ip'
require 'packetfu/utils'

include PacketFu

describe Utils do
  context "when using ifconfig" do
    it "should prevent non-interface values" do
      expect {
        PacketFu::Utils.ifconfig("not_an_interface")
      }.to raise_error(ArgumentError, /interface does not exist$/)
    end

    it "should work on Mac OSX Yosemite" do
      stub_const("RUBY_PLATFORM", "x86_64-darwin14")
      mac_osx_reply = "ifconfig en0\n" +
                      "en0: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500\n" +
                      "ether 78:31:c1:ce:39:bc\n" +
                      "inet6 fe80::7a31:c1ff:fece:39bc%en0 prefixlen 64 scopeid 0x4\n" +
                      "inet 192.168.10.173 netmask 0xffffff00 broadcast 192.168.10.255\n" +
                      "nd6 options=1<PERFORMNUD>\n" +
                      "media: autoselect\n" +
                      "status: active\n"
      allow(PacketFu::Utils).to receive(:ifconfig_data_string).and_return(mac_osx_reply)
      util_reply = PacketFu::Utils.ifconfig("en0")

      # Ensure we got a hash back
      expect(util_reply).to be_a(::Hash)

      # Ensure all our values parse correctly
      expect(util_reply[:iface]).to eq("en0")
      expect(util_reply[:eth_saddr]).to eq("78:31:c1:ce:39:bc")
      expect(util_reply[:eth_src]).to eq("x1\xC1\xCE9\xBC")
      expect(util_reply[:ip6_saddr]).to eq("fe80::7a31:c1ff:fece:39bc")
      expect(util_reply[:ip6_obj]).to eq(IPAddr.new("fe80::7a31:c1ff:fece:39bc"))
      expect(util_reply[:ip_saddr]).to eq("192.168.10.173")
      expect(util_reply[:ip_src]).to eq("\xC0\xA8\n\xAD")
      expect(util_reply[:ip4_obj]).to eq(IPAddr.new("192.168.10.0/24"))
    end

    it "should work on Ubuntu 14.04 LTS" do
      stub_const("RUBY_PLATFORM", "x86_64-linux")
      ubuntu_reply = "eth0      Link encap:Ethernet  HWaddr 00:0c:29:2a:e3:bd\n" +
                     "inet addr:192.168.10.174  Bcast:192.168.10.255  Mask:255.255.255.0\n" +
                     "inet6 addr: fe80::20c:29ff:fe2a:e3bd/64 Scope:Link\n" +
                     "UP BROADCAST RUNNING MULTICAST  MTU:1500  Metric:1\n" +
                     "RX packets:65782 errors:0 dropped:0 overruns:0 frame:0\n" +
                     "TX packets:31354 errors:0 dropped:0 overruns:0 carrier:0\n" +
                     "collisions:0 txqueuelen:1000\n" +
                     "RX bytes:40583515 (40.5 MB)  TX bytes:3349554 (3.3 MB)"
      allow(PacketFu::Utils).to receive(:ifconfig_data_string).and_return(ubuntu_reply)
      util_reply = PacketFu::Utils.ifconfig("eth0")

      # Ensure we got a hash back
      expect(util_reply).to be_a(::Hash)

      # Ensure all our values parse correctly
      expect(util_reply[:iface]).to eq("eth0")
      expect(util_reply[:eth_saddr]).to eq("00:0c:29:2a:e3:bd")
      expect(util_reply[:eth_src]).to eq("\x00\f)*\xE3\xBD")
      expect(util_reply[:ip6_saddr]).to eq("fe80::20c:29ff:fe2a:e3bd/64")
      expect(util_reply[:ip6_obj]).to eq(IPAddr.new("fe80::20c:29ff:fe2a:e3bd/64"))
      expect(util_reply[:ip_saddr]).to eq("192.168.10.174")
      expect(util_reply[:ip_src]).to eq("\xC0\xA8\n\xAE")
      expect(util_reply[:ip4_obj]).to eq(IPAddr.new("192.168.10.0/24"))
    end

    it "should work on FreeBSD" do
      stub_const("RUBY_PLATFORM", "freebsd")
      freebsd_reply = "dc0: flags=8843<UP,BROADCAST,RUNNING,SIMPLEX,MULTICAST> metric 0 mtu 1500\n" +
                      "options=80008<VLAN_MTU,LINKSTATE>\n" +
                      "ether 00:a0:cc:da:da:da\n" +
                      "inet 192.168.1.3 netmask 0xffffff00 broadcast 192.168.1.255\n" +
                      "media: Ethernet autoselect (100baseTX <full-duplex>)\n" +
                      "status: active"
      allow(PacketFu::Utils).to receive(:ifconfig_data_string).and_return(freebsd_reply)
      util_reply = PacketFu::Utils.ifconfig("dc0")

      # Ensure we got a hash back
      expect(util_reply).to be_a(::Hash)

      # Ensure all our values parse correctly
      expect(util_reply[:iface]).to eq("dc0")
      expect(util_reply[:eth_saddr]).to eq("00:a0:cc:da:da:da")
      expect(util_reply[:eth_src]).to eq("\x00\xA0\xCC\xDA\xDA\xDA")
      expect(util_reply[:ip6_saddr]).to eq(nil)
      expect(util_reply[:ip6_obj]).to eq(nil)
      expect(util_reply[:ip_saddr]).to eq("192.168.1.3")
      expect(util_reply[:ip_src]).to eq("\xC0\xA8\x01\x03")
      expect(util_reply[:ip4_obj]).to eq(IPAddr.new("192.168.1.0/24"))
    end

    it "should work on OpenBSD" do
      stub_const("RUBY_PLATFORM", "openbsd")
      openbsd_reply = "em0: flags=8b43\\<UP,BROADCAST,RUNNING,PROMISC,ALLMULTI,SIMPLEX,MULTICAST\\> mtu 1500\n" +
                      "        lladdr 00:01:02:03:04:05\n" +
                      "        priority: 0\n" +
                      "        groups: egress\n" +
                      "        media: Ethernet autoselect (1000baseT full-duplex,rxpause,txpause)\n" +
                      "        status: active\n" +
                      "        inet 10.0.0.1 netmask 0xffffff00 broadcast 10.0.0.255"
      allow(PacketFu::Utils).to receive(:ifconfig_data_string).and_return(openbsd_reply)
      util_reply = PacketFu::Utils.ifconfig("em0")

      # Ensure we got a hash back
      expect(util_reply).to be_a(::Hash)

      # Ensure all our values parse correctly
      expect(util_reply[:iface]).to eq("em0")
      expect(util_reply[:eth_saddr]).to eq("00:01:02:03:04:05")
      expect(util_reply[:eth_src]).to eq("\x00\x01\x02\x03\x04\x05")
      expect(util_reply[:ip6_saddr]).to eq(nil)
      expect(util_reply[:ip6_obj]).to eq(nil)
      expect(util_reply[:ip_saddr]).to eq("10.0.0.1")
      expect(util_reply[:ip_src]).to eq("\n\x00\x00\x01")
      expect(util_reply[:ip4_obj]).to eq(IPAddr.new("10.0.0.0/24"))
    end

  end

  context 'when using arp' do

    before(:all) do
      @whoami = lambda { |iface| {
                           :iface => iface,
                           :eth_saddr => '00:01:02:03:dd:b3',
                           :eth_src => "\x00\x01\x02\x03\xdd\xb3",
                           :ip_saddr => '192.168.254.1',
                           :ip_src => 0xc0a8fe01,
                           :ip_src_bin => "\xc0\xa8\xfe\x01",
                           :eth_dst => "\x00\x01\x02\x03\xcc\xb2",
                           :eth_daddr => '00:01:02:03:cc:b2',
                         } }
    end

    context 'when cached' do
      it 'should work on Mac OSX Yosemite' do
        stub_const('RUBY_PLATFORM', 'macosx')
        mac_osx_reply = "? (192.168.254.57) at 64:00:00:00:cc:b2 on en0 ifscope [ethernet]\n"
        allow(PacketFu::Utils).to receive(:arp_cache_raw).and_return(mac_osx_reply)
        whoami_reply = @whoami.call('em0')
        allow(PacketFu::Utils).to receive(:whoami?).and_return(whoami_reply)
        util_reply = PacketFu::Utils.arp('192.168.254.57')

        expect(util_reply).to be_a(String)
        expect(util_reply).to eq('64:00:00:00:cc:b2')
      end

      it 'should work on Ubuntu 14.04 LTS' do
        stub_const('RUBY_PLATFORM', 'x86_64-linux')
        ubuntu_reply = "? (192.168.254.56) at 00:01:02:03:cc:b2 [ether] on eth0\n"
        allow(PacketFu::Utils).to receive(:arp_cache_raw).and_return(ubuntu_reply)
        whoami_reply = @whoami.call('eth0')
        allow(PacketFu::Utils).to receive(:whoami?).and_return(whoami_reply)
        util_reply = PacketFu::Utils.arp('192.168.254.56')

        expect(util_reply).to be_a(String)
        expect(util_reply).to eq('00:01:02:03:cc:b2')
      end

      it 'should work on FreeBSD' do
        stub_const('RUBY_PLATFORM', 'freebsd')
        freebsd_reply = "? (192.168.254.57) at 00:13:20:c3:7d:22 on em0 [ethernet]\n"
        allow(PacketFu::Utils).to receive(:arp_cache_raw).and_return(freebsd_reply)
        whoami_reply = @whoami.call('em0')
        allow(PacketFu::Utils).to receive(:whoami?).and_return(whoami_reply)
        util_reply = PacketFu::Utils.arp('192.168.254.57')

        expect(util_reply).to be_a(String)
        expect(util_reply).to eq('00:13:20:c3:7d:22')
      end
    end

  end
end
