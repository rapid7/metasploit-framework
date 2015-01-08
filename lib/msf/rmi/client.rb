# -*- coding: binary -*-
require 'rex/proto/rmi'
require 'rex/java/serialization'
require 'stringio'

module Msf
  module Rmi
    module Client

      require 'msf/rmi/client/streams'

      include Msf::Rmi::Client::Streams
      include Exploit::Remote::Tcp

      # Returns the target host
      #
      # @return [String]
      def rhost
        datastore['RHOST']
      end

      # Returns the target port
      #
      # @return [Fixnum]
      def rport
        datastore['RPORT']
      end

      # Returns the RMI server peer
      #
      # @return [String]
      def peer
        "#{rhost}:#{rport}"
      end

      # Sends a RMI header stream and reads the Protocol Ack
      #
      # @param opts [Hash]
      # @option opts [Rex::Socket::Tcp] :sock
      # @return [Rex::Proto::Rmi::Model::ProtocolAck]
      # @raise [RuntimeError]
      # @see #build_header
      # @see Rex::Proto::Rmi::Model::ProtocolAck.decode
      def send_header(opts = {})
        nsock = opts[:sock] || sock
        stream = build_header(opts)
        nsock.put(stream.encode + "\x00\x00\x00\x00\x00\x00")
        ack = Rex::Proto::Rmi::Model::ProtocolAck.decode(nsock)

        ack
      end

      # Sends a RMI CALL stream and reads the ReturnData
      #
      # @param opts [Hash]
      # @option opts [Rex::Socket::Tcp] :sock
      # @return [Rex::Java::Serialization::Model::Stream] the call return value
      # @raise [RuntimeError] when the response can't be decoded
      # @see #build_call
      # @see Rex::Proto::Rmi::Model::ReturnData.decode
      def send_call(opts = {})
        nsock = opts[:sock] || sock
        stream = build_call(opts)
        nsock.put(stream.encode)
        return_data = Rex::Proto::Rmi::Model::ReturnData.decode(nsock)

        return_data.return_value
      end
    end
  end
end
