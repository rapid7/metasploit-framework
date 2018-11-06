module EventMachine
  module Protocols
    # Basic SOCKS v4 client implementation
    #
    # Use as you would any regular connection:
    #
    # class MyConn < EM::P::Socks4
    #   def post_init
    #     send_data("sup")
    #   end
    #
    #   def receive_data(data)
    #     send_data("you said: #{data}")
    #   end
    # end
    #
    # EM.connect socks_host, socks_port, MyConn, host, port
    #
    class Socks4 < Connection
      def initialize(host, port)
        @host = Socket.gethostbyname(host).last
        @port = port
        @socks_error_code = nil
        @buffer = ''
        setup_methods
      end

      def setup_methods
        class << self
          def post_init; socks_post_init; end
          def receive_data(*a); socks_receive_data(*a); end
        end
      end

      def restore_methods
        class << self
          remove_method :post_init
          remove_method :receive_data
        end
      end

      def socks_post_init
        header = [4, 1, @port, @host, 0].flatten.pack("CCnA4C")
        send_data(header)
      end

      def socks_receive_data(data)
        @buffer << data
        return  if @buffer.size < 8

        header_resp = @buffer.slice! 0, 8
        _, r = header_resp.unpack("cc")
        if r != 90
          @socks_error_code = r
          close_connection
          return
        end

        restore_methods

        post_init
        receive_data(@buffer)  unless @buffer.empty?
      end
    end
  end
end
