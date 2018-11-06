module RubySMB
  module Dispatcher
    # Provides the base class for the packet dispatcher.
    class Base
      # Creates a NetBIOS Session Service (NBSS) header
      #
      # @param packet [#do_num_bytes] the packet to be sent
      # @return [String] NBSS header to go in front of `packet`
      def nbss(packet)
        nbss = RubySMB::Nbss::SessionHeader.new
        nbss.session_packet_type = RubySMB::Nbss::SESSION_MESSAGE
        nbss.packet_length       = packet.do_num_bytes
        nbss.to_binary_s
      end

      # @abstract
      def send_packet(_packet)
        raise NotImplementedError
      end

      # @abstract
      def recv_packet
        raise NotImplementedError
      end
    end
  end
end
