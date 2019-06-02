require 'rex/logging'
require 'rex/socket'

module Rex
module Proto
module Proxy

  module Relay
    #
    # Relay data coming in from relay_sock to this socket.
    #
    def relay(relay_client, relay_sock, relay_name = "#{self.class.to_s.split('::')[-2..-1].join}Relay")
      @relay_client = relay_client
      @relay_sock   = relay_sock
      # start the relay thread (modified from Rex::IO::StreamAbstraction)
      @relay_thread = Rex::ThreadFactory.spawn(relay_name, false) do
        loop do
          closed = false
          buf    = nil

          begin
            s = Rex::ThreadSafe.select([@relay_sock], nil, nil, 0.2)
            next if s.nil? || s[0].nil?
          rescue
            closed = true
          end

          unless closed
            begin
              buf = @relay_sock.sysread( 32768 )
              closed = buf.nil?
            rescue
              closed = true
            end
          end

          unless closed
            total_sent   = 0
            total_length = buf.length
            while total_sent < total_length
              begin
                data = buf[total_sent, buf.length]
                sent = self.write(data)
                total_sent += sent if sent > 0
              rescue
                closed = true
                break
              end
            end
          end

          if closed
            @relay_client.stop
            ::Thread.exit
          end
        end
      end
    end
  end
end; end; end;
