require 'spec_helper'
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

  describe '#exit' do
    it 'shuts down the session' do
      allow(subject).to receive(:core).and_return(double('core'))
      allow(subject).to receive(:console).and_return(double('console'))

      expect(subject.core).to receive(:shutdown)
      expect(subject).to receive(:shutdown_passive_dispatcher)
      expect(subject.console).to receive(:stop)
      subject.exit
    end
  end

  describe '#auto_load_extensions' do
    before { allow(subject).to receive(:platform).and_return('windows') }

    it 'parses a comma-separated string and trims blanks' do
      datastore = { 'AutoLoadExtensions' => 'stdapi, priv ,,' }
      expect(subject.auto_load_extensions(datastore)).to eq(%w[stdapi priv])
    end

    it 'de-duplicates case-variant spellings of the same extension' do
      datastore = { 'AutoLoadExtensions' => 'Stdapi,stdapi,priv' }
      expect(subject.auto_load_extensions(datastore)).to eq(%w[Stdapi priv])
    end

    it 'does not load an auto-added extension twice when supplied in a different case' do
      datastore = { 'AutoLoadExtensions' => 'Stdapi', 'AutoLoadStdapi' => true }
      # AutoLoadStdapi pushes 'stdapi' (and 'priv' on Windows); the supplied
      # 'Stdapi' must collapse with the pushed 'stdapi' so stdapi loads once.
      expect(subject.auto_load_extensions(datastore)).to eq(%w[Stdapi priv])
    end
  end

  describe '#bootstrap AutoSystemInfo collection' do
    let(:console) { double('console') }
    let(:core) { double('core') }

    before do
      allow(subject).to receive(:platform).and_return('windows')
      allow(subject).to receive(:init_ui)
      allow(subject).to receive(:user_input)
      allow(subject).to receive(:user_output)
      allow(subject).to receive(:comm_timeout).and_return(0)
      allow(subject).to receive(:session_guid).and_return('A' * 16)
      allow(subject).to receive(:commands).and_return([])
      allow(subject).to receive(:load_embedded_extensions)
      allow(subject).to receive(:console).and_return(console)
      allow(console).to receive(:disable_output).and_return(false)
      allow(console).to receive(:disable_output=)
      allow(console).to receive(:run_single)
      allow(core).to receive(:negotiate_tlv_encryption).and_return({ weak_key?: false })
      allow(core).to receive(:get_loaded_extension_commands).and_return([])
      allow(subject).to receive(:core).and_return(core)
    end

    # Regression: the dedup in #auto_load_extensions keeps the operator's
    # spelling ("Stdapi"), so the stdapi load-site check must be
    # case-insensitive or AutoSystemInfo silently stops collecting system info.
    it 'collects session info even when the surviving stdapi name is cased differently' do
      datastore = {
        'AutoLoadExtensions' => 'Stdapi',
        'AutoLoadStdapi' => true,
        'AutoSystemInfo' => true
      }

      expect(subject).to receive(:load_session_info).once
      subject.bootstrap(datastore)
    end
  end

end
