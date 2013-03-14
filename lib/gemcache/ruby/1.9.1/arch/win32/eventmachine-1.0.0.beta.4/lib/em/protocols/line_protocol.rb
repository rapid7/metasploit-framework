module EventMachine
  module Protocols
    # LineProtocol will parse out newline terminated strings from a receive_data stream
    #
    #  module Server
    #    include EM::P::LineProtocol
    #
    #    def receive_line(line)
    #      send_data("you said: #{line}")
    #    end
    #  end
    #
    module LineProtocol
      # @private
      def receive_data data
        (@buf ||= '') << data

        while line = @buf.slice!(/(.*)\r?\n/)
          receive_line(line)
        end
      end

      # Invoked with lines received over the network
      def receive_line(line)
        # stub
      end
    end
  end
end
