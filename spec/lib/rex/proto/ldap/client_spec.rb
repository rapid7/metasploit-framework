# -*- coding: binary -*-

require 'spec_helper'
require 'rex/proto/ldap/client'

RSpec.describe Rex::Proto::LDAP::Client do
  let(:host) { '127.0.0.1' }
  let(:port) { 1234 }
  let(:info) { "#{host}:#{port}" }

  subject do
    client = described_class.new(host: host, port: port)
    client
  end

  it_behaves_like 'session compatible client'
end
