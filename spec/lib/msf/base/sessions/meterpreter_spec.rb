require 'spec_helper'
require 'msf/base/sessions/meterpreter'
require 'rex/post/meterpreter/extensions/stdapi/net/interface'
require 'rex/post/meterpreter/extensions/stdapi/net/route'

RSpec.describe Msf::Sessions::Meterpreter do
  before do
    allow_any_instance_of(Rex::Post::Meterpreter::PacketDispatcher).to receive(:monitor_socket)
  end

  subject(:meterpreter) { described_class.new(StringIO.new(""), skip_ssl: true) }

  let(:v6_gateway) { "2607:f8b0:4004:0802::1014" }
  let(:v4_gateway) { "192.168.3.1" }

  let(:v6_linklocal) { "fe80::d6c9:efff:fe53:53ff" }

  let(:routes) do
    [
      Rex::Post::Meterpreter::Extensions::Stdapi::Net::Route.new(
        IPAddr.new("0.0.0.0").hton, # Subnet
        IPAddr.new("0.0.0.0").hton, # Netmask
        IPAddr.new("192.168.3.1").hton  # Gateway
      ),
      Rex::Post::Meterpreter::Extensions::Stdapi::Net::Route.new(
        IPAddr.new("::").hton, # Subnet
        IPAddr.new("::").hton, # Netmask
        IPAddr.new(v6_gateway).hton  # Gateway
      )
    ]
  end

  describe "#find_internet_connected_address" do

    subject(:connected_address) do
      allow_message_expectations_on_nil
      m = described_class.new(StringIO.new(""), skip_ssl: true)
      allow(m).to receive_message_chain(:private_methods, :net)
      allow(m).to receive_message_chain(:private_methods, :net, :config, :get_interfaces).and_return(interfaces)
      allow(m).to receive_message_chain(:private_methods, :net, :config, :get_routes).and_return(routes)
      m.session_host = session_host

      m.send(:find_internet_connected_address)
    end

    let(:interfaces) do
      ifaces = []
      interface_config.each_with_index { |iface_hash, idx|
        ifaces << Rex::Post::Meterpreter::Extensions::Stdapi::Net::Interface.new(
          index: idx,
          mac_addr: "00:11:22:33:44:%02x"%idx,
          mac_name: "eth0",
          mtu: 1500,
          flags: 0,
          addrs: iface_hash[:ips],
          netmasks: iface_hash[:masks],
          scopes: [ "" ]
        )
      }

      ifaces
    end

    let(:session_host) { "99.99.99.99" }

    context "with an address that matches #session_host" do
      let(:interface_config) do
        [
          { ips: [ "192.168.10.1" ], masks: [ "255.255.255.0" ], },
          { ips: [ "192.168.11.1" ], masks: [ "255.255.255.0" ], },
          { ips: [ "192.168.12.1" ], masks: [ "255.255.255.0" ], },
          { ips: [ session_host   ], masks: [ "255.255.255.0" ], },
          { ips: [ "192.168.14.1" ], masks: [ "255.255.255.0" ], },
          { ips: [ "192.168.16.1" ], masks: [ "255.255.255.0" ], },
        ]
      end
      it "returns nil" do
        expect(connected_address).to be_nil
      end
    end

    # All the rest of these assume session_host does not match any
    # interface's addresses

    context "one interface with one IPv4 address" do
      let(:interface_config) do
        [ { ips: [ "10.2.3.4" ], masks: [ "255.255.255.0" ], } ]
      end
      it "returns that address" do
        expect(connected_address).to eq("10.2.3.4")
      end
    end

    context "one interface with one IPv6 address" do
      let(:interface_config) do
        [
          { ips: [ v6_linklocal ], masks: [ "ffff:ffff:ffff:ffff::" ], },
        ]
      end
      it "returns that address" do
        expect(connected_address).to eq(v6_linklocal)
      end
    end

    context "one interface with mixed IP versions" do
      context "first is correct" do
        let(:interface_config) do
          [
            { ips: [ "192.168.3.4" ], masks: [ "255.255.255.0" ], },
            { ips: [ v6_linklocal ], masks: [ "ffff:ffff:ffff:ffff::" ], },
          ]
        end
        it "returns first address" do
          expect(connected_address).to eq("192.168.3.4")
        end
      end
      context "second address is correct" do
        let(:interface_config) do
          [
            { ips: [ v6_linklocal ], masks: [ "ffff:ffff:ffff:ffff::" ], },
            { ips: [ "192.168.3.4" ], masks: [ "255.255.255.0" ], },
          ]
        end
        it "returns second address" do
          expect(connected_address).to eq("192.168.3.4")
        end
      end
    end

    context "one interface with multiple IPv4 addresses" do
      context "first address is correct" do
        let(:interface_config) do
          [ {
            ips: ["192.168.3.4", "10.2.3.4"],
            masks: [ "255.255.255.0", "255.0.0.0"],
          } ]
        end
        it "returns first address" do
          expect(connected_address).to eq("192.168.3.4")
        end
      end
      context "second address is correct" do
        let(:interface_config) do
          [ {
            ips: [ "10.2.3.4", "192.168.3.4" ],
            masks: [ "255.0.0.0", "255.255.255.0" ],
          } ]
        end
        it "returns second address" do
          expect(connected_address).to eq("192.168.3.4")
        end
      end
    end

  end

end

