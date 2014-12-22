# -*- coding: binary -*-
require 'rex/proto/kerberos'

module Msf
  module Kerberos
    module Client
      require 'msf/kerberos/client/base'
      require 'msf/kerberos/client/as_request'
      require 'msf/kerberos/client/as_response'
      require 'msf/kerberos/client/tgs_request'
      require 'msf/kerberos/client/tgs_response'
      require 'msf/kerberos/client/pac'
      require 'msf/kerberos/client/cache_credential'

      include Msf::Kerberos::Client::Base
      include Msf::Kerberos::Client::AsRequest
      include Msf::Kerberos::Client::AsResponse
      include Msf::Kerberos::Client::TgsRequest
      include Msf::Kerberos::Client::TgsResponse
      include Msf::Kerberos::Client::Pac
      include Msf::Kerberos::Client::CacheCredential

      # @!attribute client
      #   @return [Rex::Proto::Kerberos::Client] The kerberos client
      attr_accessor :client

      def initialize(info = {})
        super

        register_options(
          [
            Opt::RHOST,
            Opt::RPORT(88),
            OptInt.new('Timeout', [true, 'The TCP timeout to establish connection and read data', 10])
          ], self.class
        )
      end

      # Returns the target host
      #
      # @return [String]
      def rhost
        datastore['RHOST']
      end

      # Returns the remote port
      #
      # @return [Fixnum]
      def rport
        datastore['RPORT']
      end

      # Returns the TCP timeout
      #
      # @return [Fixnum]
      def timeout
        datastore['Timeout']
      end

      # Returns the kdc peer
      #
      # @return [String]
      def peer
        "#{rhost}:#{rport}"
      end

      # Creates a kerberos connection
      #
      # @param opts [Hash{Symbol => <String, Fixnum>}]
      # @option opts [String] :rhost
      # @option opts [<String, Fixnum>] :rport
      # @return [Rex::Proto::Kerberos::Client]
      def connect(opts={})
        kerb_client = Rex::Proto::Kerberos::Client.new(
          host: opts[:rhost] || rhost,
          port: (opts[:rport] || rport).to_i,
          timeout: (opts[:timeout] || timeout).to_i,
          context:
            {
              'Msf'        => framework,
              'MsfExploit' => self,
            },
          protocol: 'tcp'
        )

        disconnect if client
        self.client = kerb_client

        kerb_client
      end

      # Disconnects the Kerberos client
      #
      # @param kerb_client [Rex::Proto::Kerberos::Client] the client to disconnect
      def disconnect(kerb_client = client)
        kerb_client.close if kerb_client

        if kerb_client == client
          self.client = nil
        end
      end

      # Performs cleanup as necessary, disconnecting the Kerberos client
      # if it's still established.
      def cleanup
        super
        disconnect
      end

      # Sends a kerberos AS request and reads the response
      #
      # @param opts [Hash]
      # @return [Rex::Proto::Kerberos::Model::KdcResponse]
      # @see Msf::Kerberos::Client::AsRequest#build_as_request
      # @see Rex::Proto::Kerberos::Model::KdcResponse
      def send_request_as(opts = {})
        connect(opts)
        req = build_as_request(opts)
        res = client.send_recv(req)
        disconnect
        res
      end

      # Sends a kerberos AS request and reads the response
      #
      # @param opts [Hash]
      # @return [Rex::Proto::Kerberos::Model::KdcResponse]
      # @see Msf::Kerberos::Client::TgsRequest#build_tgs_request
      # @see Rex::Proto::Kerberos::Model::KdcResponse
      def send_request_tgs(opts = {})
        connect(opts)
        req = build_tgs_request(opts)
        res = client.send_recv(req)
        disconnect
        res
      end
    end
  end
end
