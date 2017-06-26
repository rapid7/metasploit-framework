=begin

    This file is part of the Arachni-RPC Pure project and may be subject to
    redistribution and commercial restrictions. Please see the Arachni-RPC Pure
    web site for more information on licensing and terms of use.

=end

require 'openssl'
require 'socket'
require 'zlib'
require 'msgpack'

module Rex
module Proto
module Arachni

# Represents an RPC connection, which is basically an OpenSSL socket with
# the ability to serialize/unserialize RPC messages.
#
# @author   Tasos Laskos <tasos.laskos@arachni-scanner.com>
class Connection

    # @param    [Hash]  options
    # @option   options    [String]  :host
    #   Hostname/IP address.
    # @option   options    [Integer] :port
    #   Port number.
    # @option   options    [String]  :ssl_ca
    #   SSL CA certificate.
    # @option   options    [String]  :ssl_pkey
    #   SSL private key.
    # @option   options    [String]  :ssl_cert
    #   SSL certificate.
    def initialize( options )
        context = OpenSSL::SSL::SSLContext.new

        if options[:ssl_cert] && options[:ssl_pkey]
            context.cert =
                OpenSSL::X509::Certificate.new( File.open( options[:ssl_cert] ) )

            context.key  =
                OpenSSL::PKey::RSA.new( File.open( options[:ssl_pkey] ) )

            context.ca_file     = options[:ssl_ca]
            context.verify_mode =
                OpenSSL::SSL::VERIFY_PEER | OpenSSL::SSL::VERIFY_FAIL_IF_NO_PEER_CERT
        end

        @socket = OpenSSL::SSL::SSLSocket.new(
            TCPSocket.new( options[:host], options[:port] ),
            context
        )
        @socket.sync_close = true
        @socket.connect
    end

    # Closes the connection.
    def close
        @socket.close
    end

    # @param    [Hash]  request
    #   RPC request message data.
    def perform( request )
        send_rcv_object( request )
    end

    private

    def send_rcv_object( obj )
        send_object( obj )
        receive_object
    end

    def send_object( obj )
        serialized = serialize( obj )
        @socket.puts( [ serialized.bytesize, serialized ].pack( 'Na*' ) )
    end

    def receive_object
        while data = @socket.sysread( 99999 )
            (@buf ||= '') << data
            while @buf.size >= 4
                if @buf.size >= 4 + ( size = @buf.unpack( 'N' ).first )
                    @buf.slice!(0,4)

                    complete = @buf.slice!( 0, size )
                    @buf = ''
                    return unserialize( complete )
                else
                    break
                end
            end
        end
    end

    def serialize( object )
        MessagePack.dump object
    end

    def unserialize( object )
        MessagePack.load try_decompress( object )
    end

    # @note Will return the `string` as is if it was not compressed.
    #
    # @param    [String]    string
    #   String to decompress.
    #
    # @return   [String]
    #   Decompressed string.
    def try_decompress( string )
        # Just an ID representing a serialized, empty data structure.
        return string if string.size == 1

        begin
            Zlib::Inflate.inflate string
        rescue Zlib::DataError
            string
        end
    end

end

end
end
end
