module EventMachine
  module Protocols
    # ObjectProtocol allows for easy communication using marshaled ruby objects
    #
    #  module RubyServer
    #    include EM::P::ObjectProtocol
    #
    #    def receive_object obj
    #      send_object({'you said' => obj})
    #    end
    #  end
    #
    module ObjectProtocol
      # By default returns Marshal, override to return JSON or YAML, or any
      # other serializer/deserializer responding to #dump and #load.
      def serializer
        Marshal
      end

      # @private
      def receive_data data
        (@buf ||= '') << data

        while @buf.size >= 4
          if @buf.size >= 4+(size=@buf.unpack('N').first)
            @buf.slice!(0,4)
            receive_object serializer.load(@buf.slice!(0,size))
          else
            break
          end
        end
      end

      # Invoked with ruby objects received over the network
      def receive_object obj
        # stub
      end

      # Sends a ruby object over the network
      def send_object obj
        data = serializer.dump(obj)
        send_data [data.respond_to?(:bytesize) ? data.bytesize : data.size, data].pack('Na*')
      end
    end
  end
end
