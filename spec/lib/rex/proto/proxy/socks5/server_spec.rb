# -*- coding:binary -*-
require 'rex/proto/proxy/socks5'

RSpec.describe Rex::Proto::Proxy::Socks5::Server do

  subject(:server) do
    Rex::Proto::Proxy::Socks5::Server.new
  end

  describe "#is_running?" do

    it "should respond to #is_running?" do
      expect(server.is_running?).to eq(false)
    end

  end
end
