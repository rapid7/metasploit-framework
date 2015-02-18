# -*- coding: binary -*-
require 'rex/proto/rmi'
require 'rex/java/serialization'
require 'stringio'

module Msf
  module Java
    module Rmi
      module Client

        require 'msf/java/rmi/client/streams'

        include Msf::Java::Rmi::Client::Streams
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

        # Sends a RMI header stream
        #
        # @param opts [Hash]
        # @option opts [Rex::Socket::Tcp] :sock
        # @return [Fixnum] the number of bytes sent
        # @see Msf::Rmi::Client::Streams#build_header
        def send_header(opts = {})
          nsock = opts[:sock] || sock
          stream = build_header(opts)
          nsock.put(stream.encode + "\x00\x00\x00\x00\x00\x00")
        end

        # Sends a RMI CALL stream
        #
        # @param opts [Hash]
        # @option opts [Rex::Socket::Tcp] :sock
        # @return [Fixnum] the number of bytes sent
        # @see Msf::Rmi::Client::Streams#build_call
        def send_call(opts = {})
          nsock = opts[:sock] || sock
          stream = build_call(opts)
          nsock.put(stream.encode)
        end

        # Sends a RMI DGCACK stream
        #
        # @param opts [Hash]
        # @option opts [Rex::Socket::Tcp] :sock
        # @return [Fixnum] the number of bytes sent
        # @see Msf::Rmi::Client::Streams#build_dgc_ack
        def send_dgc_ack(opts = {})
          nsock = opts[:sock] || sock
          stream = build_dgc_ack(opts)
          nsock.put(stream.encode)
        end

        # Reads the Protocol Ack
        #
        # @param opts [Hash]
        # @option opts [Rex::Socket::Tcp] :sock
        # @return [Rex::Proto::Rmi::Model::ProtocolAck]
        # @see Rex::Proto::Rmi::Model::ProtocolAck.decode
        def recv_protocol_ack(opts = {})
          nsock = opts[:sock] || sock
          data = safe_get_once(nsock)
          begin
            ack = Rex::Proto::Rmi::Model::ProtocolAck.decode(StringIO.new(data))
          rescue ::RuntimeError
            return nil
          end

          ack
        end

        # Reads a ReturnData message and returns the java serialized stream
        # with the return data value.
        #
        # @param opts [Hash]
        # @option opts [Rex::Socket::Tcp] :sock
        # @return [Rex::Java::Serialization::Stream]
        # @see Rex::Proto::Rmi::Model::ReturnData.decode
        def recv_return(opts = {})
          nsock = opts[:sock] || sock
          data = safe_get_once(nsock)
          begin
            return_data = Rex::Proto::Rmi::Model::ReturnData.decode(StringIO.new(data))
          rescue ::RuntimeError
            return nil
          end

          return_data.return_value
        end

        # Helper method to read fragmented data from a ```Rex::Socket::Tcp```
        #
        # @param opts [Hash]
        # @option opts [Rex::Socket::Tcp] :sock
        # @return [String]
        def safe_get_once(nsock = sock)
          data = ''
          begin
            res = nsock.get_once
          rescue ::EOFError
            res = nil
          end

          until res.nil? || res.length < 1448
            data << res
            begin
              res = nsock.get_once
            rescue ::EOFError
              res = nil
            end
          end

          data << res if res
          data
        end
      end
    end
  end
end
