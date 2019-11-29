module Msf::RPC::JSON

  # JSON-RPC 2.0 Error Codes
  ## Specification errors:
  PARSE_ERROR = -32700
  INVALID_REQUEST = -32600
  METHOD_NOT_FOUND = -32601
  INVALID_PARAMS = -32602
  INTERNAL_ERROR = -32603
  ## Implementation-defined server-errors:
  SERVER_ERROR_MAX = -32000
  SERVER_ERROR_MIN = -32099
  APPLICATION_SERVER_ERROR = -32000

  # JSON-RPC 2.0 Error Messages
  ERROR_MESSAGES = {
      # Specification errors:
      PARSE_ERROR => 'Invalid JSON was received by the server. An error occurred on the server while parsing the JSON text.',
      INVALID_REQUEST => 'The JSON sent is not a valid Request object.',
      METHOD_NOT_FOUND => 'The method %<name>s does not exist.',
      INVALID_PARAMS => 'Invalid method parameter(s).',
      INTERNAL_ERROR => 'Internal JSON-RPC error',
      # Implementation-defined server-errors:
      APPLICATION_SERVER_ERROR => 'Application server error: %<msg>s',
  }

  # Base class for all Msf::RPC::JSON exceptions.
  class RpcError < StandardError
    # Code              Message           Meaning
    # -32700            Parse error       Invalid JSON was received by the server. An error
    #                                     occurred on the server while parsing the JSON text.
    # -32600            Invalid Request   The JSON sent is not a valid Request object.
    # -32601            Method not found  The method does not exist / is not available.
    # -32602            Invalid params    Invalid method parameter(s).
    # -32603            Internal error    Internal JSON-RPC error.
    # -32000 to -32099  Server error      Reserved for implementation-defined server-errors.

    attr_reader :code
    attr_reader :message
    attr_reader :data

    # Instantiate an RpcError object.
    #
    # @param code [Integer] A Number that indicates the error type that occurred.
    # @param message [String] A String providing a short description of the error.
    #   The message SHOULD be limited to a concise single sentence.
    # @param data [Object] A Primitive or Structured value that contains additional
    #   information about the error. This may be omitted. The value of this member is
    #   defined by the Server (e.g. detailed error information, nested errors etc.).
    #   The default value is nil.
    def initialize(code, message, data: nil)
      super(message)
      @code = code
      @message = message
      @data = data
    end

    def to_h
      hash = {
          code: @code,
          message: @message
      }

      # process data member
      unless @data.nil?
        if @data.is_a?(String) || @data.kind_of?(Numeric) || @data.is_a?(Array) || @data.is_a?(Hash)
          hash[:data] = @data
        elsif @data.respond_to?(:to_h)
          hash[:data] = @data.to_h
        else
          hash[:data] = @data.to_s
        end
      end

      hash
    end
  end

  class ParseError < RpcError
    def initialize(data: nil)
      super(PARSE_ERROR, ERROR_MESSAGES[PARSE_ERROR], data: data)
    end
  end

  class InvalidRequest < RpcError
    def initialize(data: nil)
      super(INVALID_REQUEST, ERROR_MESSAGES[INVALID_REQUEST], data: data)
    end
  end

  class MethodNotFound < RpcError
    def initialize(method, data: nil)
      super(METHOD_NOT_FOUND, ERROR_MESSAGES[METHOD_NOT_FOUND] % {name: method}, data: data)
    end
  end

  class InvalidParams < RpcError
    def initialize(data: nil)
      super(INVALID_PARAMS, ERROR_MESSAGES[INVALID_PARAMS], data: data)
    end
  end

  class InternalError < RpcError
    def initialize(e, data: nil)
      super(INTERNAL_ERROR, "#{ERROR_MESSAGES[INTERNAL_ERROR]}: #{e}", data: data)
    end
  end

  # Class is reserved for implementation-defined server-error exceptions.
  class ServerError < RpcError

    # Instantiate a ServerError object.
    #
    # @param code [Integer] A Number that indicates the error type that occurred.
    #   The code must be between -32000 and -32099.
    # @param message [String] A String providing a short description of the error.
    #   The message SHOULD be limited to a concise single sentence.
    # @param data [Object] A Primitive or Structured value that contains additional
    #   information about the error. This may be omitted. The value of this member is
    #   defined by the Server (e.g. detailed error information, nested errors etc.).
    #   The default value is nil.
    # @raise [ArgumentError] Module not found (either the wrong type or name).
    def initialize(code, message, data: nil)
      if code < SERVER_ERROR_MIN || code > SERVER_ERROR_MAX
        raise ArgumentError.new("invalid code #{code}, must be between #{SERVER_ERROR_MAX} and #{SERVER_ERROR_MIN}")
      end
      super(code, message, data: data)
    end
  end

  class ApplicationServerError < ServerError
    def initialize(message, data: nil)
      super(APPLICATION_SERVER_ERROR, ERROR_MESSAGES[APPLICATION_SERVER_ERROR] % {msg: message}, data: data)
    end
  end

  # Base class for all Msf::RPC::JSON client exceptions.
  class ClientError < StandardError
    attr_reader :response

    # Instantiate a ClientError object.
    #
    # @param message [String] A String providing a short description of the error.
    # @param response [Hash] A response hash. The default value is nil.
    def initialize(message = nil, response: nil)
      super(message)
      @response = response
    end
  end

  class InvalidResponse < ClientError
    # Instantiate an InvalidResponse object.
    #
    # @param message [String] A String providing a short description of the error.
    # @param response [Hash] A response hash. The default value is nil.
    def initialize(message = 'Invalid response from server', response: nil)
      super(message, response: response)
    end
  end

  class JSONParseError < ClientError
    # Instantiate an JSONParseError object.
    #
    # @param message [String] A String providing a short description of the error.
    # @param response [Hash] A response hash. The default value is nil.
    def initialize(message = 'Invalid JSON was received from the server', response: nil)
      super(message, response: response)
    end
  end

  class ErrorResponse < ClientError
    attr_reader :id
    attr_reader :code
    attr_reader :message
    attr_reader :data

    # Parse response and return a new ErrorResponse instance.
    # @param response [Hash] A response hash.
    # @param symbolize_names [Boolean] If true, symbols are used for the names (keys) when
    #   processing JSON objects; otherwise, strings are used. Default: true
    # @returns [ErrorResponse] ErrorResponse object that represents the response hash.
    def self.parse(response, symbolize_names: true)
      id_key = symbolize_names ? :id : :id.to_s
      error_key = symbolize_names ? :error : :error.to_s
      code_key = symbolize_names ? :code : :code.to_s
      message_key = symbolize_names ? :message : :message.to_s
      data_key = symbolize_names ? :data : :data.to_s

      id = response[id_key]
      error = response[error_key]

      if !error.nil?
        code = error[code_key]
        message = error[message_key]
        data = error[data_key]
      else
        code = nil
        message = nil
        data = nil
      end

      ErrorResponse.new(id: id, code: code, message: message, data: data, response: response)
    end

    # Instantiate an ErrorResponse object.
    #
    # @param id [Integer, String, NilClass] It MUST be the same as the value of the
    #   id member in the Request Object. If there was an error in detecting the id
    #   in the Request object (e.g. Parse error/Invalid Request), it MUST be Null.
    # @param code [Integer] A Number that indicates the error type that occurred.
    # @param message [String] A String providing a short description of the error.
    #   The message SHOULD be limited to a concise single sentence.
    # @param data [Object] A Primitive or Structured value that contains additional
    #   information about the error. This may be omitted. The value of this member is
    #   defined by the Server (e.g. detailed error information, nested errors etc.).
    #   The default value is nil.
    # @param response [Hash] A response hash. The default value is nil.
    def initialize(id:, code:, message:, data: nil, response: nil)
      super(message, response: response)
      @id = id
      @code = code
      @message = message
      @data = data
    end
  end
end
