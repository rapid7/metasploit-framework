require 'spec_helper'
require 'rex/socket'

unless defined?(Msf::Payload)
  module Msf
    # Minimal namespace needed by the isolated Rex spec environment.
    module Payload
    end
  end
end

require 'msf/core/payload/uuid'
require 'rex/payloads/meterpreter/uri_checksum'
require 'rex/post/meterpreter/client'

RSpec.describe Rex::Post::Meterpreter::Client do
  describe '#init_meterpreter' do
    subject(:client) do
      described_class.allocate.tap do |client|
        allow(client).to receive_messages(
          initialize_inbound_handlers: nil,
          initialize_channels: nil,
          initialize_pivots: nil,
          register_inbound_handler: nil,
          monitor_socket: nil
        )

        client.send(:init_meterpreter, double('socket'), {})
      end
    end

    it 'initializes empty microextension command and channel inventories' do
      expect(client.micro_commands).to eq([])
      expect(client.micro_channels).to eq([])
    end

    it 'removes client aliases created by a deregistered extension' do
      extension_class = Class.new do
        attr_reader :name

        def initialize(extension_client)
          @name = 'test_adapter'
          extension_client.register_extension_alias('test_api', Object.new)
        end
      end
      allow(described_class).to receive(:check_ext_hash).with('test_adapter').and_return(extension_class)

      client.add_extension('test_adapter')
      expect(client.singleton_class.instance_methods(false)).to include(:test_api)

      client.deregister_extension('test_adapter')
      expect(client.singleton_class.instance_methods(false)).not_to include(:test_api)
    end
  end
end
