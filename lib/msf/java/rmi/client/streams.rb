# -*- coding: binary -*-

require 'rex/java/serialization'

module Msf
  module Java
    module Rmi
      module Client
        module Streams

          # Builds a RMI header stream
          #
          # @param opts [Hash{Symbol => <String, Fixnum>}]
          # @option opts [String] :signature
          # @option opts [Fixnum] :version
          # @option opts [Fixnum] :protocol
          # @return [Rex::Proto::Rmi::Model::OutputHeader]
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

          # Builds a RMI call stream
          #
          # @param opts [Hash{Symbol => <Fixnum, Rex::Java::Serialization::Model::Stream>}]
          # @option opts [Fixnum] :message_id
          # @option opts [Rex::Java::Serialization::Model::Stream] :call_data
          # @return [Rex::Proto::Rmi::Model::Call]
          def build_call(opts = {})
            message_id = opts[:message_id] || Rex::Proto::Rmi::Model::CALL_MESSAGE
            call_data = opts[:call_data] || Rex::Java::Serialization::Model::Stream.new

            call = Rex::Proto::Rmi::Model::Call.new(
                message_id: message_id,
                call_data: call_data
            )

            call
          end

          # Builds a RMI dgc ack stream
          #
          # @param opts [Hash{Symbol => <Fixnum, String>}]
          # @option opts [Fixnum] :stream_id
          # @option opts [String] :unique_identifier
          # @return [Rex::Proto::Rmi::Model::DgcAck]
          def build_dgc_ack(opts = {})
            stream_id = opts[:stream_id] || Rex::Proto::Rmi::Model::DGC_ACK_MESSAGE
            unique_identifier = opts[:unique_identifier] || "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"

            dgc_ack = Rex::Proto::Rmi::Model::DgcAck.new(
                stream_id: stream_id,
                unique_identifier: unique_identifier
            )

            dgc_ack
          end
        end
      end
    end
  end
end
