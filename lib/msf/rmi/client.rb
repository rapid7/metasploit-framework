# -*- coding: binary -*-
require 'rex/proto/rmi'
require 'rex/java/serialization'
require 'stringio'

module Msf
  module Rmi
    module Client

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

      # Sends a RMI Header stream and reads the Protocol Ack
      #
      # @param opts [Hash]
      # @return [Rex::Proto::Rmi::Model::ProtocolAck]
      # @raise [RuntimeError]
      def send_header(opts = {})
        nsock = opts[:sock] || sock
        stream = build_header(opts)
        nsock.put(stream.encode)
        res = nsock.get_once
        res_io = StringIO.new(res)
        ack = Rex::Proto::Rmi::Model::ProtocolAck.decode(res_io)

        ack
      end

      # Sends a RMI CALL stream and reads the ReturnData
      #
      # @param opts [Hash]
      # @return [Rex::Java::Serialization::Model::Stream]
      # @raise [RuntimeError]
      def send_call(opts = {})
        nsock = opts[:sock] || sock
        stream = build_call(opts)
        nsock.put(stream.encode)
        res = nsock.get_once
        res_io = StringIO.new(res)
        return_data = Rex::Proto::Rmi::Model::ReturnData.decode(res_io)

        return_data.return_value
      end


      def build_header(opts = {})
        signature = opts[:signature] || Rex::Proto::Rmi::Model::SIGNATURE
        version = opts[:version] || 2
        protocol = opts[:protocol] || Rex::Proto::Rmi::Model::STREAM_PROTOCOL

        header = Rex::Proto::Rmi::Model::OutputHeader.new(
          signature: signature,
          version: version,
          protocol: protocol)

        header
      end


      def build_call(opts = {})
        message_id = opts[:message_id] || Rex::Proto::Rmi::Model::CALL_MESSAGE
        call_data = opts[:call_data] || Rex::Java::Serialization::Model::Stream.new

        call = Rex::Proto::Rmi::Model::Call.new(
          message_id: message_id,
          call_data: call_data
        )

        call
      end
    end
  end
end
