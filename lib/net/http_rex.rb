require 'net/http'
require 'rex/socket'

#
# Converts Ruby STD Net::HTTP class to use Rex::Socket
# Allows pivoting, virtual sockets, etc.
# This is for development with external libraries which
# depend on net/http like open-uri or xmlrpc which are
# heavily used by other interfaces for our targets
#

class ::Net::HTTP
 def connect
      D "opening connection to #{conn_address()}..."
      # Should find a way of passing framework context here
      # Not using our SSL socket implementation for compat
      s = timeout(@open_timeout) {Rex::Socket::Tcp.create(
	'PeerHost' => conn_address,
	'PeerPort' => conn_port)}
      D "opened"
      if use_ssl?
        ssl_parameters = Hash.new
        iv_list = instance_variables
        SSL_ATTRIBUTES.each do |name|
          ivname = "@#{name}".intern
          if iv_list.include?(ivname) and
             value = instance_variable_get(ivname)
            ssl_parameters[name] = value
          end
        end
        @ssl_context = OpenSSL::SSL::SSLContext.new
        @ssl_context.set_params(ssl_parameters)
	# SSL Verification fails with the Rex Socket.
	@ssl_context.verify_mode = OpenSSL::SSL::VERIFY_NONE
        s = OpenSSL::SSL::SSLSocket.new(s, @ssl_context)
        s.sync_close = true
      end
      # Namespacing change as lookup apparears to fail on 1.9.3-p392
      @socket = Net::BufferedIO.new(s)
      @socket.read_timeout = @read_timeout
      @socket.continue_timeout = @continue_timeout
      @socket.debug_output = @debug_output
      if use_ssl?
        begin
          if proxy?
            @socket.writeline sprintf('CONNECT %s:%s HTTP/%s',
                                      @address, @port, HTTPVersion)
            @socket.writeline "Host: #{@address}:#{@port}"
            if proxy_user
              credential = ["#{proxy_user}:#{proxy_pass}"].pack('m')
              credential.delete!("\r\n")
              @socket.writeline "Proxy-Authorization: Basic #{credential}"
            end
            @socket.writeline ''
            HTTPResponse.read_new(@socket).value
          end
          # Server Name Indication (SNI) RFC 3546
          s.hostname = @address if s.respond_to? :hostname=
          timeout(@open_timeout) { s.connect }
          if @ssl_context.verify_mode != OpenSSL::SSL::VERIFY_NONE
            s.post_connection_check(@address)
          end
        rescue => exception
          D "Conn close because of connect error #{exception}"
          @socket.close if @socket and not @socket.closed?
          raise exception
        end
      end
      on_connect
    end
    private :connect
end
