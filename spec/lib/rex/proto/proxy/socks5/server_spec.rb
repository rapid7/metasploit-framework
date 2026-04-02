# -*- coding:binary -*-

RSpec.describe Rex::Proto::Proxy::Socks5::Server do

  subject(:server) do
    Rex::Proto::Proxy::Socks5::Server.new
  end

  describe "#initialize" do
    it "defaults ServerHost to 0.0.0.0" do
      expect(server.opts['ServerHost']).to eq('0.0.0.0')
    end

    it "defaults ServerPort to 1080" do
      expect(server.opts['ServerPort']).to eq(1080)
    end

    it "accepts option overrides" do
      s = described_class.new('ServerPort' => 9090)
      expect(s.opts['ServerPort']).to eq(9090)
    end

    it "starts in a not-running state" do
      expect(server.is_running?).to be(false)
    end
  end

  describe "#is_running?" do

    it "should respond to #is_running?" do
      expect(server.is_running?).to eq(false)
    end

  end

  describe "#relay_manager" do
    it "returns a Rex::IO::RelayManager instance" do
      expect(server.relay_manager).to be_a(Rex::IO::RelayManager)
    end

    it "returns the same instance on repeated calls" do
      expect(server.relay_manager).to be(server.relay_manager)
    end
  end

  describe "#add_client" do
    let(:client) { double('ServerClient') }

    it "starts with no clients" do
      expect(server.instance_variable_get(:@clients)).to be_empty
    end

    it "adds a client" do
      server.add_client(client)
      expect(server.instance_variable_get(:@clients)).to include(client)
    end
  end

  describe "#remove_client" do
    let(:client) { double('ServerClient') }

    it "removes a client" do
      server.add_client(client)
      server.remove_client(client)
      expect(server.instance_variable_get(:@clients)).not_to include(client)
    end
  end

  describe "#stop" do
    context "when the server is not running" do
      it "returns true" do
        expect(server.stop).to be(true)
      end

      it "does not raise" do
        expect { server.stop }.not_to raise_error
      end
    end
  end
end
