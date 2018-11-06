require 'socket'
module RubySMB
  module Dispatcher
    # This class provides a wrapper around a Socket for the packet Dispatcher.
    # It allows for dependency injection of different Socket implementations.
    class Socket < RubySMB::Dispatcher::Base
      READ_TIMEOUT = 30

      # The underlying socket that we select on
      # @!attribute [rw] tcp_socket
      #   @return [IO]
      attr_accessor :tcp_socket

      # The read timeout
      # @!attribute [rw] read_timeout
      #   @return [Integer]
      attr_accessor :read_timeout

      # @param tcp_socket [IO]
      def initialize(tcp_socket, read_timeout: READ_TIMEOUT)
        @tcp_socket = tcp_socket
        @tcp_socket.setsockopt(::Socket::SOL_SOCKET, ::Socket::SO_KEEPALIVE, true) if @tcp_socket.respond_to?(:setsockopt)
        @read_timeout = read_timeout
      end

      # @param host [String] passed to TCPSocket.new
      # @param port [Fixnum] passed to TCPSocket.new
      def self.connect(host, port: 445, socket: TCPSocket.new(host, port))
        new(socket)
      end

      # @param packet [SMB2::Packet,#to_s]
      # @param nbss [Boolean] wether to include the NetBIOS Session header
      # @return [void]
      def send_packet(packet, nbss_header: true)
        data = nbss_header ? nbss(packet) : ''
        data << packet.to_binary_s
        bytes_written = 0
        begin
          while bytes_written < data.size
            retval = @tcp_socket.write(data[bytes_written..-1])

            if retval == nil
              raise RubySMB::Error::CommunicationError
            else
              bytes_written += retval
            end
          end

        rescue IOError, Errno::ECONNABORTED, Errno::ECONNRESET => e
          raise RubySMB::Error::CommunicationError, "An error occured writing to the Socket: #{e.message}"
        end
        nil
      end

      # Read a packet off the wire and parse it into a string
      #
      # @param full_response [Boolean] whether to include the NetBios Session Service header in the repsonse
      # @return [String] the raw response (including the NetBios Session Service header if full_response is true)
      # @raise [RubySMB::Error::NetBiosSessionService] if there's an error reading the first 4 bytes,
      #   which are assumed to be the NetBiosSessionService header.
      # @raise [RubySMB::Error::CommunicationError] if the read timeout expires or an error occurs when reading the socket
      def recv_packet(full_response: false)
        if IO.select([@tcp_socket], nil, nil, @read_timeout).nil?
          raise RubySMB::Error::CommunicationError, "Read timeout expired when reading from the Socket (timeout=#{@read_timeout})"
        end

        begin
          nbss_data = @tcp_socket.read(4)
          raise IOError if nbss_data.nil?
          nbss_header = RubySMB::Nbss::SessionHeader.read(nbss_data)
        rescue IOError
          raise ::RubySMB::Error::NetBiosSessionService, 'NBSS Header is missing'
        end

        length = nbss_header.packet_length
        data = full_response ? nbss_header.to_binary_s : ''
        if length > 0
          if IO.select([@tcp_socket], nil, nil, @read_timeout).nil?
            raise RubySMB::Error::CommunicationError, "Read timeout expired when reading from the Socket (timeout=#{@read_timeout})"
          end
          data << @tcp_socket.read(length)
          data << @tcp_socket.read(length - data.length) while data.length < length
        end
        data
      rescue Errno::EINVAL, Errno::ECONNABORTED, Errno::ECONNRESET, TypeError, NoMethodError => e
        raise RubySMB::Error::CommunicationError, "An error occured reading from the Socket #{e.message}"
      end
    end
  end
end
