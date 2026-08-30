# -*- coding: binary -*-

require 'spec_helper'
require 'rex/proto/smb/simple_client'

RSpec.describe Rex::Proto::SMB::SimpleClient do
  let(:host) { '127.0.0.1' }
  let(:port) { 1234 }
  let(:info) { "#{host}:#{port}" }

  subject do
    socket = instance_double(Rex::Socket, peerinfo: info)
    client = described_class.new(socket)
    client
  end

  it_behaves_like 'session compatible client'
end
