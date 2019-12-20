require 'json'
require 'msf/core/rpc'

module Msf::RPC::JSON
  class Dispatcher
    JSON_RPC_VERSION = '2.0'
    JSON_RPC_REQUIRED_MEMBERS = %i(jsonrpc method)
    JSON_RPC_MEMBER_TYPES = {
        # A String specifying the version of the JSON-RPC protocol.
        jsonrpc: [String],
        # A String containing the name of the method to be invoked.
        method: [String],
        # If present, parameters for the rpc call MUST be provided as a Structured
        # value. Either by-position through an Array or by-name through an Object.
        # * by-position: params MUST be an Array, containing the values in the
        #   Server expected order.
        # * by-name: params MUST be an Object, with member names that match the
        #   Server expected parameter names. The absence of expected names MAY
        #   result in an error being generated. The names MUST match exactly,
        #   including case, to the method's expected parameters.
        params: [Array, Hash],
        # An identifier established by the Client that MUST contain a String,
        # Number, or NULL value if included. If it is not included it is assumed
        # to be a notification. The value SHOULD normally not be Null [1] and
        # Numbers SHOULD NOT contain fractional parts [2]
        id: [Integer, String, NilClass]
    }

    attr_reader :framework
    attr_reader :command

    # Instantiate a Dispatcher.
    # @param framework [Msf::Simple::Framework] Framework wrapper instance
    def initialize(framework)
      @framework = framework
      @command = nil
    end

    # Set the command.
    # @param command [RpcCommand] the command used by the Dispatcher.
    def set_command(command)
      @command = command
    end

    # Process the JSON-RPC request.
    # @param source [String] the JSON-RPC request
    # @return [String] JSON-RPC response that encapsulates the RPC result
    # if successful; otherwise, a JSON-RPC error response.
    def process(source)
      begin
        request = parse_json_request(source)
        if request.is_a?(Array)
          # If the batch rpc call itself fails to be recognized as an valid
          # JSON or as an Array with at least one value, the response from
          # the Server MUST be a single Response object.
          raise InvalidRequest.new if request.empty?
          # process batch request
          response = request.map { |r| process_request(r) }
          # A Response object SHOULD exist for each Request object, except that
          # there SHOULD NOT be any Response objects for notifications.
          # Remove nil responses from response array
          response.compact!
        else
          response = process_request(request)
        end
      rescue ParseError, InvalidRequest => e
        # If there was an error in detecting the id in the Request object
        # (e.g. Parse error/Invalid Request), then the id member MUST be
        # Null. Don't pass request obj when building the error response.
        response = self.class.create_error_response(e)
      rescue RpcError => e
        # other JSON-RPC errors should include the id from the Request object
        response = self.class.create_error_response(e, request)
      rescue => e
        response = self.class.create_error_response(ApplicationServerError.new(e), request)
      end

      # When a rpc call is made, the Server MUST reply with a Response, except
      # for in the case of Notifications. The Response is expressed as a single
      # JSON Object.
      self.class.to_json(response)
    end

    # Validate and execute the JSON-RPC request.
    # @param request [Hash] the JSON-RPC request
    # @returns [RpcCommand] an RpcCommand for the specified version
    # @raise [InvalidParams] ArgumentError occurred during execution.
    # @raise [ApplicationServerError] General server-error wrapper around an
    # Msf::RPC::Exception that occurred during execution.
    # @returns [Hash] JSON-RPC response that encapsulates the RPC result
    # if successful; otherwise, a JSON-RPC error response.
    def process_request(request)
      begin
        if !validate_rpc_request(request)
          response = self.class.create_error_response(InvalidRequest.new)
          return response
        end

        # dispatch method execution to command
        result = @command.execute(request[:method], request[:params])

        # A Notification is a Request object without an "id" member. A Request
        # object that is a Notification signifies the Client's lack of interest
        # in the corresponding Response object, and as such no Response object
        # needs to be returned to the client. The Server MUST NOT reply to a
        # Notification, including those that are within a batch request.
        if request.key?(:id)
          response = self.class.create_success_response(result, request)
        else
          response = nil
        end

        response
      rescue ArgumentError
        raise InvalidParams.new
      rescue Msf::RPC::Exception => e
        raise ApplicationServerError.new(e.message, data: { code: e.code })
      end
    end

    # Validate the JSON-RPC request.
    # @param request [Hash] the JSON-RPC request
    # @returns [Boolean] true if the JSON-RPC request is valid; otherwise, false.
    def validate_rpc_request(request)
      # validate request is an object
      return false unless request.is_a?(Hash)

      # validate request contains required members
      JSON_RPC_REQUIRED_MEMBERS.each { |member| return false unless request.key?(member) }

      return false if request[:jsonrpc] != JSON_RPC_VERSION

      # validate request members are correct types
      request.each do |member, value|
        return false if JSON_RPC_MEMBER_TYPES.key?(member) &&
            !JSON_RPC_MEMBER_TYPES[member].one? { |type| value.is_a?(type) }
      end

      true
    end

    # Parse the JSON document source into a Hash or Array with symbols for the names (keys).
    # @param source [String] the JSON source
    # @raise [ParseError] Invalid JSON was received by the server.
    # An error occurred on the server while parsing the JSON text.
    # @return [Hash or Array] Hash or Array representation of source
    def parse_json_request(source)
      begin
        JSON.parse(source, symbolize_names: true)
      rescue
        raise ParseError.new
      end
    end

    # Serialize data as JSON string.
    # @param data [Hash] data
    # @return [String] data serialized JSON string if data not nil; otherwise, nil.
    def self.to_json(data)
      return nil if data.nil?

      json = data.to_json
      return json.to_s
    end

    # Create a JSON-RPC success response.
    # @param result [Object] the RPC method's return value
    # @param request [Hash] the JSON-RPC request
    # @returns [Hash] JSON-RPC success response.
    def self.create_success_response(result, request = nil)
      response = {
          # A String specifying the version of the JSON-RPC protocol.
          jsonrpc: JSON_RPC_VERSION,

          # This member is REQUIRED on success.
          # This member MUST NOT exist if there was an error invoking the method.
          # The value of this member is determined by the method invoked on the Server.
          result: result
      }

      self.add_response_id_member(response, request)

      response
    end

    # Create a JSON-RPC error response.
    # @param error [RpcError] a RpcError instance
    # @param request [Hash] the JSON-RPC request
    # @returns [Hash] JSON-RPC error response.
    def self.create_error_response(error, request = nil)
      response = {
          # A String specifying the version of the JSON-RPC protocol.
          jsonrpc: JSON_RPC_VERSION,

          # This member is REQUIRED on error.
          # This member MUST NOT exist if there was no error triggered during invocation.
          # The value for this member MUST be an Object as defined in section 5.1.
          error: error.to_h
      }

      self.add_response_id_member(response, request)

      response
    end

    # Adds response id based on request id.
    # @param response [Hash] the JSON-RPC response
    # @param request [Hash] the JSON-RPC request
    def self.add_response_id_member(response, request)
      if !request.nil? && request.key?(:id)
        response[:id] = request[:id]
      else
        response[:id] = nil
      end
    end
  end
end