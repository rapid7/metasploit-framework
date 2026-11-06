# -*- coding: binary -*-
# frozen_string_literal: true

# Errors raised by the OPC-UA library.
#
# Everything here descends from OpcUaError, so a caller that only needs to know
# that the conversation failed can rescue the family in one clause, while a
# caller that wants to report why can rescue the individual classes. This
# follows Rex::Proto::Thrift::Error and Rex::Proto::Amqp::Error, which solve the
# same problem for their transports.
#
# OpcUaError descends from Rex::RuntimeError, which means every error here is
# both a StandardError and a Rex::Exception without any of them saying so
# individually: Rex::RuntimeError includes the Rex::Exception marker module, so
# `rescue Rex::Exception` catches these alongside Rex's own.
#
# The distinction the classes draw is between a fault in our reading of the
# connection and a fault the server reported, because a scanner reports those
# very differently: a TimeoutError against a host that never answers is not
# worth printing, whereas a ServerError is a positive result.
module Rex::Proto::OpcUa::Error
  # Base class of OPC-UA specific errors.
  class OpcUaError < Rex::RuntimeError; end

  # Raised when a read does not complete before its deadline, either because
  # nothing arrived or because only part of a message did. Rex sockets report a
  # closed connection by raising EOFError rather than by timing out, and that is
  # left to propagate as itself.
  class TimeoutError < OpcUaError; end

  # Raised when the UA TCP framing is unusable: a message size outside the
  # permitted range, a chunk too short to hold its own headers, a message or
  # chunk type that has no meaning here, or a response that ran past the chunk
  # ceiling. See OPC-UA Specification Part 6, section 7.1.
  class FramingError < OpcUaError; end

  # Base of the two errors that carry a StatusCode and a Reason the server put
  # on the wire. Both bodies have the same two fields in the same order: an ERR
  # message body is Table 76 of OPC-UA Specification Part 6, section 7.1.2.5,
  # and an abort chunk body is Table 63 of section 6.7.3.
  #
  # These are reports from the server rather than faults in reading it, and the
  # StatusCode is the useful part, so it is kept as a field rather than only
  # interpolated into the message.
  class StatusReportError < OpcUaError
    # @return [Integer, nil] the StatusCode the server sent, or nil when the
    #   body could not be decoded.
    attr_reader :status_code

    # @return [String, nil] the Reason the server sent. Servers routinely leave
    #   this null.
    attr_reader :reason

    # @param status_code [Integer, nil] the StatusCode from the body.
    # @param reason [String, nil] the Reason from the body. An empty reason is
    #   stored as nil, since the two say the same thing.
    # @param msg [String, nil] overrides the generated message.
    # @return [StatusReportError]
    def initialize(status_code: nil, reason: nil, msg: nil)
      @status_code = status_code
      @reason = reason.to_s.empty? ? nil : reason.to_s

      super(msg || generate_message)
    end

    private

    # @return [String] what happened, then the StatusCode by name where it is
    #   one the enumeration carries, with the Reason appended when the server
    #   supplied one.
    def generate_message
      name = status_code.nil? ? 'an undecodable status' : Rex::Proto::OpcUa::Enums.status_code_name(status_code)
      reason.nil? ? "#{summary}: #{name}" : "#{summary}: #{name} - #{reason}"
    end

    # @return [String] the leading clause of the generated message.
    def summary
      raise ::NotImplementedError, "#{self.class} must supply a summary"
    end
  end

  # Raised when the server abandons a response part way through by sending a
  # chunk of type A, per OPC-UA Specification Part 6, section 6.7.3. The
  # response cannot be completed, but the connection itself is intact and the
  # server is behaving to specification.
  #
  # The chunk carries the same StatusCode and Reason an ERR message would;
  # Table 63 in that section gives the body as an Error UInt32 followed by a
  # Reason String. No capture under spec/file_fixtures/opc_ua contains an abort,
  # so that decode is specified rather than observed, and a body that will not
  # decode leaves both fields nil rather than failing the abort report.
  class AbortError < StatusReportError
    private

    def summary
      'server aborted the response'
    end
  end

  # Raised when the server answers with an ERR message, per OPC-UA
  # Specification Part 6, section 7.1.2.5.
  class ServerError < StatusReportError
    private

    def summary
      'server returned ERR'
    end
  end
end
