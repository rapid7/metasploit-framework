module Rex::Proto::Amqp::Error
  # Base class of AMQP-specific errors.
  class AmqpError < Rex::RuntimeError
  end

  # Raised when trying to parse a frame that is invalid.
  class InvalidFrameError < AmqpError
    def initialize(msg='Invalid AMQP frame data was received and could not be parsed.')
      super(msg)
    end
  end

  # Raised when an unexpected reply is received.
  class UnexpectedReplyError < AmqpError
    attr_reader :reply
    def initialize(reply, msg='An unexpected AMQP reply was received.')
      @reply = reply
      super(msg)
    end
  end

  # Raised when the connection can not be negotiated for some reason.
  class NegotiationError < AmqpError
    def initialize(msg='AMQP Connection negotiation failed.')
      super(msg)
    end
  end
end
