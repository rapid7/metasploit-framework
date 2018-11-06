module RubySMB
  # Contains all the RubySMB specific Error classes.
  module Error
    # Base class for RubySMB errors
    class RubySMBError < StandardError; end

    # Raised when there is a length or formatting issue with an ASN1-encoded string
    # @see https://en.wikipedia.org/wiki/Abstract_Syntax_Notation_One
    # @todo Find an SMB-specific link for ASN1 above
    class ASN1Encoding < RubySMBError; end

    # Raised when there is a problem with communication over NetBios Session Service
    # @see https://wiki.wireshark.org/NetBIOS/NBSS
    class NetBiosSessionService < RubySMBError; end

    # Raised when trying to parse raw binary into a Packet and the data
    # is invalid.
    class InvalidPacket < RubySMBError
      def initialize(args = nil)
        if args.nil?
          super
        elsif args.is_a? String
          super(args)
        elsif args.is_a? Hash
          expected_proto = args[:expected_proto] ? translate_protocol(args[:expected_proto]) : "???"
          expected_cmd = args[:expected_cmd] || "???"
          received_proto = args[:received_proto] ? translate_protocol(args[:received_proto]) : "???"
          received_cmd = args[:received_cmd] || "???"
          super(
            "Expecting #{expected_proto} protocol "\
            "with command=#{expected_cmd}"\
            "#{(" (" + args[:expected_custom] + ")") if args[:expected_custom]}, "\
            "got #{received_proto} protocol "\
            "with command=#{received_cmd}"\
            "#{(" (" + args[:received_custom] + ")") if args[:received_custom]}"
          )
        else
          raise ArgumentError, "InvalidPacket expects a String or a Hash, got a #{args.class}"
        end
      end

      def translate_protocol(proto)
        case proto
        when RubySMB::SMB1::SMB_PROTOCOL_ID
          'SMB1'
        when RubySMB::SMB2::SMB2_PROTOCOL_ID
          'SMB2'
        else
          raise ArgumentError, 'Unknown SMB protocol'
        end
      end
      private :translate_protocol
    end

    # Raised when a response packet has a NTStatus code that was unexpected.
    class UnexpectedStatusCode < RubySMBError; end

    # Raised when an error occurs with the underlying socket.
    class CommunicationError < RubySMBError; end

    # Raised when Protocol Negotiation fails, possibly due to an
    # unsupported protocol.
    class NegotiationFailure < RubySMBError; end

    # Raised when trying to parse raw binary into a BitField and the data
    # is invalid.
    class InvalidBitField < RubySMBError; end
  end
end
