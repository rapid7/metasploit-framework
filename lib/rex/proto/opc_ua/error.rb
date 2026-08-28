# -*- coding: binary -*-

# Errors raised by the OPC-UA library.
#
# Everything here descends from OpcUaError, so a caller that only needs to know
# that the conversation failed can rescue the family in one clause, while a
# caller that wants to report why can rescue the individual classes. This
# follows Rex::Proto::Thrift::Error and Rex::Proto::Amqp::Error, which solve the
# same problem for their transports.
#
# The distinction the classes draw is between a fault in our reading of the
# connection and a fault the server reported, because a scanner reports those
# very differently: a TimeoutError against a host that never answers is not
# worth printing, whereas a ServerError is a positive result.
module Rex::Proto::OpcUa::Error
  # Base class of OPC-UA specific errors.
  class OpcUaError < Rex::RuntimeError; end

  # Raised when a read does not complete before its deadline, either because
  # nothing arrived or because only part of a message did. Rex sockets report
  # a closed connection by raising EOFError rather than by timing out, and that
  # is left to propagate as itself.
  class TimeoutError < OpcUaError; end

  # Raised when the UA TCP framing is unusable: a message size outside the
  # permitted range, a chunk too short to hold its own headers, a message or
  # chunk type that has no meaning here, or a response that ran past the chunk
  # ceiling.
  class FramingError < OpcUaError; end

  # Raised when the server abandons a response part way through by sending a
  # chunk of type A. The response cannot be completed, but the connection
  # itself is intact and the server is behaving to specification.
  class AbortError < OpcUaError; end

  # Raised when the server answers with an ERR message. This is a report from
  # the server rather than a fault in reading it, and the StatusCode it carries
  # is the useful part, so it is kept as a field rather than only interpolated
  # into the message.
  class ServerError < OpcUaError
    # @return [Integer, nil] the StatusCode from the ERR message, or nil when
    #   the body could not be decoded.
    attr_reader :status_code

    # @return [String, nil] the Reason from the ERR message. Servers routinely
    #   leave this null.
    attr_reader :reason

    # @param status_code [Integer, nil] the StatusCode from the ERR message.
    # @param reason [String, nil] the Reason from the ERR message.
    # @param msg [String, nil] overrides the generated message.
    def initialize(status_code: nil, reason: nil, msg: nil)
      @status_code = status_code
      @reason = reason.to_s.empty? ? nil : reason.to_s

      super(msg || generate_message)
    end

    private

    # @return [String] the StatusCode by name where it is one the enumeration
    #   carries, with the Reason appended when the server supplied one.
    def generate_message
      name = status_code.nil? ? 'an undecodable status' : Rex::Proto::OpcUa::Enums.status_code_name(status_code)
      reason.nil? ? "server returned ERR: #{name}" : "server returned ERR: #{name} - #{reason}"
    end
  end
end
