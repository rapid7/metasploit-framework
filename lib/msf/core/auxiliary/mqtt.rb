# -*- coding: binary -*-

require 'msf/core/exploit'
require 'rex/proto/mqtt'

module Msf
  module Auxiliary::MQTT
      def initialize(info = {})
        super

        register_options(
          [
            Opt::RPORT(Rex::Proto::MQTT::DEFAULT_PORT)
          ]
        )

        register_advanced_options(
          [
            OptString.new('CLIENT_ID', [false, 'The client ID to send if necessary for bypassing clientid_prefixes']),
            OptInt.new('READ_TIMEOUT', [true, 'Seconds to wait while reading MQTT responses', 5])
          ]
        )

        register_autofilter_ports([Rex::Proto::MQTT::DEFAULT_PORT, Rex::Proto::MQTT::DEFAULT_SSL_PORT])
      end

      def setup
        fail_with(Failure::BadConfig, 'READ_TIMEOUT must be > 0') if read_timeout <= 0

        client_id_arg = datastore['CLIENT_ID']
        if client_id_arg && client_id_arg.blank?
          fail_with(Failure::BadConfig, 'CLIENT_ID must be a non-empty string')
        end
      end

      def read_timeout
        datastore['READ_TIMEOUT']
      end

      def client_id
        datastore['CLIENT_ID'] || 'mqtt-' + Rex::Text.rand_text_alpha(1 + rand(10))
      end

      # creates a new mqtt client for use against the connected socket
      def mqtt_client
        client_opts = {
          client_id: client_id,
          username: datastore['USERNAME'],
          password: datastore['PASSWORD'],
          read_timeout: read_timeout
        }
        Rex::Proto::MQTT::Client.new(sock, client_opts)
      end

      def mqtt_connect(client)
        client.connect
      end

      def mqtt_connect?(client)
        client.connect?
      end

      def mqtt_disconnect(client)
        client.disconnect
      end
  end
end
