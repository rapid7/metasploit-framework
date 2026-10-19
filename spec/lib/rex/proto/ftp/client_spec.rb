# -*- coding: binary -*-

require 'spec_helper'
require 'rex/proto/ftp/client'

RSpec.describe Rex::Proto::Ftp::Client do
  subject(:client) { described_class.allocate }

  describe '#data_connect' do
    let(:control_socket) { double('control socket', peerhost: '192.0.2.1') }
    let(:data_socket) { double('data socket') }

    before do
      allow(client).to receive(:datasocket).and_return(nil, data_socket)
      allow(client).to receive(:datasocket=)
      allow(client).to receive(:send_cmd).with(['PASV'], true, control_socket).and_return(
        "227 Entering Passive Mode (10,0,0,50,192,0)\r\n"
      )
      allow(Rex::Socket::Tcp).to receive(:create).and_return(data_socket)
    end

    it 'uses the control connection host instead of the PASV advertised host' do
      expect(client.data_connect(nil, control_socket)).to eq(data_socket)
      expect(Rex::Socket::Tcp).to have_received(:create).with(
        'PeerHost' => '192.0.2.1',
        'PeerPort' => 49_152
      )
    end

    it 'clears an old socket and permits a retry after a malformed response' do
      old_data_socket = double('old data socket', shutdown: nil, close: nil)
      current_data_socket = old_data_socket
      allow(client).to receive(:datasocket) { current_data_socket }
      allow(client).to receive(:datasocket=) { |socket| current_data_socket = socket }
      allow(client).to receive(:send_cmd).with(['PASV'], true, control_socket).and_return(
        "227 Entering Passive Mode (invalid)\r\n",
        "227 Entering Passive Mode (192,0,2,1,192,0)\r\n"
      )

      expect(client.data_connect(nil, control_socket)).to be_nil
      expect(current_data_socket).to be_nil
      expect(client.data_connect(nil, control_socket)).to eq(data_socket)
      expect(old_data_socket).to have_received(:shutdown)
      expect(old_data_socket).to have_received(:close)
    end
  end
end
