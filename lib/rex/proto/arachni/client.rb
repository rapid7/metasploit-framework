=begin

    This file is part of the Arachni-RPC Pure project and may be subject to
    redistribution and commercial restrictions. Please see the Arachni-RPC Pure
    web site for more information on licensing and terms of use.

=end
module Rex
module Proto
module Arachni

# Very simple client, essentially establishes a {Connection} and performs
# requests.
#
# @author   Tasos Laskos <tasos.laskos@arachni-scanner.com>
class Client

    # @param    [Hash]  options
    # @option   options    [String]  :host
    #   Hostname/IP address.
    # @option   options    [Integer] :port
    #   Port number.
    # @option   options    [String]  :token
    #   Optional authentication token.
    # @option   options    [String]  :ssl_ca
    #   SSL CA certificate.
    # @option   options    [String]  :ssl_pkey
    #   SSL private key.
    # @option   options    [String]  :ssl_cert
    #   SSL certificate.
    def initialize( options )
        @options = options
    end

    # @note Will establish a connection if none is available.
    #
    # Performs an RPC request and returns a response.
    #
    # @param    [String]    msg
    #   RPC message in the form of `handler.method`.
    # @param    [Array]     args
    #   Collection of arguments to be passed to the method.
    #
    # @return   [Object]
    #   Response object.
    #
    # @raise    [RuntimeError]
    #   * If a connection error was encountered the relevant exception will be
    #        raised.
    #   * If the response object is a remote exception, one will also be raised
    #       locally.
    def call( msg, *args )
        response = with_connection { |c| c.perform( request( msg, *args ) ) }
        handle_exception( response )

        response['obj']
    end

    private

    def with_connection( &block )
        c = Connection.new( @options )

        begin
            block.call c
        ensure
            c.close
        end
    end

    def handle_exception( response )
        return if !(data = response['exception'])

        exception = RuntimeError.new( "#{data['type']}: #{data['message']}" )
        exception.set_backtrace( data['backtrace'] )

        raise exception
    end

    def request( msg, *args )
        {
            message: msg,
            args:    args,
            token:   @options[:token]
        }
    end

end

end
end
end
