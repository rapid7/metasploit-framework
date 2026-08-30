module Rex::Proto::Thrift::Error
  # Base class of Thrift-specific errors.
  class ThriftError < Rex::RuntimeError
  end

  # Raised when trying to parse a frame that is invalid.
  class InvalidFrameError < ThriftError
    def initialize(msg='Invalid Thrift frame data was received and could not be parsed.')
      super(msg)
    end
  end

  # Raised when an unexpected reply is received.
  class UnexpectedReplyError < ThriftError
    attr_reader :reply
    def initialize(reply, msg='An unexpected Thrift reply was received.')
      @reply = reply
      super(msg)
    end
  end
end
