require 'spec_helper'

require 'rex/proto/http/packet'
require 'rex/proto/http/packet/header'
require 'rex/proto/http/request'
require 'rex/proto/http/response'
require 'rex/proto/http/handler'
require 'rex/proto/http/handler/proc'
require 'rex/proto/http/server'

RSpec.describe Rex::Proto::Http::Server do
  describe '#add_response_headers' do
    it 'adds default response headers when context is nil' do
      server = described_class.new(0, '127.0.0.1', false, nil)
      request = Rex::Proto::Http::Request.new
      response = Rex::Proto::Http::Response.new

      expect { server.add_response_headers(request, response) }.not_to raise_error
      expect(response['Server']).to eq('Rex')
    end
  end

  describe '#dispatch_request' do
    it 'dispatches mounted resources when context is nil' do
      server = described_class.new(0, '127.0.0.1', false, nil)
      client = instance_double('Rex::Proto::Http::ServerClient', keepalive: false)
      request = Rex::Proto::Http::Request.new('POST', '/api')
      handled_request = nil

      allow(client).to receive(:keepalive=)
      allow(server).to receive(:close_client)

      server.add_resource('/api', {
        'Proc' => proc { |_cli, req| handled_request = req }
      })

      expect { server.send(:dispatch_request, client, request) }.not_to raise_error
      expect(handled_request).to be(request)
    end
  end
end
