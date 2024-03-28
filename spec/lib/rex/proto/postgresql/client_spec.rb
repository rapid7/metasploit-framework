# -*- coding: binary -*-

require 'spec_helper'
require 'postgres/postgres-pr/connection'

RSpec.describe Msf::Db::PostgresPR::Connection do
  let(:host) { '127.0.0.1' }
  let(:port) { 1234 }
  let(:info) { "#{host}:#{port}" }
  let(:db_name) { 'my_db_name' }
  let(:socket) { double(Rex::Socket, peerhost: host, peerport: port) }
  let(:message) { Msf::Db::PostgresPR::ReadyForQuery.new('') }

  subject do
    allow(socket).to receive(:<<)
    allow(Msf::Db::PostgresPR::Message).to receive(:read).and_return(message)
    allow(Rex::Socket).to receive(:create).and_return(socket)
    client = described_class.new(db_name, 'username', 'password', "tcp://#{host}:#{port}")
    client
  end

  it_behaves_like 'session compatible SQL client'
end
