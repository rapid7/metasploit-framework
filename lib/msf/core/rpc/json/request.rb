require 'em-http-request'
require 'json'

require 'msf/core/rpc'

module Msf::RPC::JSON

  # Represents a JSON-RPC request. This is an EM::Deferrable class and instances
  # respond to #callback and #errback to store callback actions.
  class Request
    include EM::Deferrable

    JSON_MEDIA_TYPE = 'application/json'
    JSON_RPC_VERSION = '2.0'
    JSON_RPC_RESPONSE_REQUIRED_MEMBERS = %i(jsonrpc id)
    JSON_RPC_RESPONSE_MEMBER_TYPES = {
        # A String specifying the version of the JSON-RPC protocol.
        jsonrpc: [String],
        # An identifier established by the Client that MUST contain a String,
        # Number, or NULL value if included. If it is not included it is assumed
        # to be a notification. The value SHOULD normally not be Null [1] and
        # Numbers SHOULD NOT contain fractional parts [2]
        id: [Integer, String, NilClass],
    }
    JSON_RPC_ERROR_RESPONSE_REQUIRED_MEMBERS = %i(code message)
    JSON_RPC_ERROR_RESPONSE_MEMBER_TYPES = {
        # A Number that indicates the error type that occurred.
        # This MUST be an integer.
        code: [Integer],
        # A String providing a short description of the error.
        # The message SHOULD be limited to a concise single sentence.
        message: [String]
    }

    # Instantiate a Request.
    # @param uri [URI::HTTP] the JSON-RPC service URI
    # @param api_token [String] the API token. Default: nil
    # @param method [String] the JSON-RPC method name.
    # @param params [Array, Hash] the JSON-RPC method parameters. Default: nil
    # @param namespace [String] the namespace for the JSON-RPC method. The namespace will
    #   be prepended to the method name with a period separator. Default: nil
    # @param symbolize_names [Boolean] If true, symbols are used for the names (keys) when
    #   processing JSON objects; otherwise, strings are used. Default: true
    # @param is_notification [Boolean] If true, the request is created as a notification;
    #   otherwise, a standard request. Default: false
    # @param private_key_file [String] the SSL private key file used for the HTTPS request. Default: nil
    # @param cert_chain_file [String] the SSL cert chain file used for the HTTPS request. Default: nil
    # @param verify_peer [Boolean] indicates whether a server should request a certificate
    #   from a peer, to be verified by user code. Default: nil
    def initialize(uri, api_token: nil, method:, params: nil, namespace: nil,
                   symbolize_names: true, is_notification: false,
                   private_key_file: nil, cert_chain_file: nil, verify_peer: nil)
      @uri = uri
      @api_token = api_token
      @namespace = namespace
      @symbolize_names = symbolize_names
      @is_notification = is_notification
      @headers = {
          'Accept': JSON_MEDIA_TYPE,
          'Content-Type': JSON_MEDIA_TYPE,
          'Authorization': "Bearer #{@api_token}"
      }

      absolute_method_name = @namespace.nil? ? method : "#{@namespace}.#{method}"
      request_msg = {
          jsonrpc: JSON_RPC_VERSION,
          method: absolute_method_name
      }
      request_msg[:id] = Request.generate_id unless is_notification
      request_msg[:params] = params unless params.nil?

      @request_options = {
          head: @headers,
          body: request_msg.to_json
      }

      # add SSL options if specified
      if !private_key_file.nil? || !cert_chain_file.nil? || verify_peer.is_a?(TrueClass) ||
          verify_peer.is_a?(FalseClass)
        ssl_options = {}
        ssl_options[:private_key_file] = private_key_file unless private_key_file.nil?
        ssl_options[:cert_chain_file] = cert_chain_file unless cert_chain_file.nil?
        ssl_options[:verify_peer] = verify_peer if verify_peer.is_a?(TrueClass) || verify_peer.is_a?(FalseClass)
        @request_options[:ssl] = ssl_options
      end
    end

    # Sends the JSON-RPC request using an EM::HttpRequest object, then validates and processes
    # the JSON-RPC response.
    def send
      http = EM::HttpRequest.new(@uri).post(@request_options)

      http.callback do
        process(http.response)
      end

      http.errback do
        fail(http.error)
      end
    end

    private

    # Process the JSON-RPC response.
    # @param source [String] the JSON-RPC response
    def process(source)
      begin
        response = JSON.parse(source, symbolize_names: @symbolize_names)
        if response.is_a?(Array)
          # process batch response
          # TODO: implement batch response processing
          fail("#{self.class.name}##{__method__} is not implemented for batch response")
        else
          process_response(response)
        end
      rescue JSON::ParserError
        fail(JSONParseError.new(response: source))
      end
    end


    # Validate and process the JSON-RPC response.
    # @param response [Hash] the JSON-RPC response
    def process_response(response)
      if !valid_rpc_response?(response)
        fail(InvalidResponse.new(response: response))
        return
      end

      error_key = @symbolize_names ? :error : :error.to_s
      if response.key?(error_key)
        # process error response
        fail(ErrorResponse.parse(response, symbolize_names: @symbolize_names))
      else
        # process successful response
        succeed(Response.parse(response, symbolize_names: @symbolize_names))
      end
    end

    # Validate the JSON-RPC response.
    # @param response [Hash] the JSON-RPC response
    # @returns [Boolean] true if the JSON-RPC response is valid; otherwise, false.
    def valid_rpc_response?(response)
      # validate response is an object
      return false unless response.is_a?(Hash)

      JSON_RPC_RESPONSE_REQUIRED_MEMBERS.each do |member|
        tmp_member = @symbolize_names ? member : member.to_s
        return false unless response.key?(tmp_member)
      end

      # validate response members are correct types
      response.each do |member, value|
        tmp_member = @symbolize_names ? member : member.to_sym
        return false if JSON_RPC_RESPONSE_MEMBER_TYPES.key?(tmp_member) &&
            !JSON_RPC_RESPONSE_MEMBER_TYPES[tmp_member].one? { |type| value.is_a?(type) }
      end

      return false if response[:jsonrpc] != JSON_RPC_VERSION

      result_key = @symbolize_names ? :result : :result.to_s
      error_key = @symbolize_names ? :error : :error.to_s

      return false if response.key?(result_key) && response.key?(error_key)

      if response.key?(error_key)
        error_response = response[error_key]
        # validate error response is an object
        return false unless error_response.is_a?(Hash)

        JSON_RPC_ERROR_RESPONSE_REQUIRED_MEMBERS.each do |member|
          tmp_member = @symbolize_names ? member : member.to_s
          return false unless error_response.key?(tmp_member)
        end

        # validate error response members are correct types
        error_response.each do |member, value|
          tmp_member = @symbolize_names ? member : member.to_sym
          return false if JSON_RPC_ERROR_RESPONSE_MEMBER_TYPES.key?(tmp_member) &&
              !JSON_RPC_ERROR_RESPONSE_MEMBER_TYPES[tmp_member].one? { |type| value.is_a?(type) }
        end
      end

      true
    end

    # Generates a random id.
    # @param n [Integer] Upper boundary for the random id.
    # @return [Integer] A random id. If a positive integer is given for n,
    #   returns an integer: 0 <= id < n.
    def self.generate_id(n = (2**(0.size * 8 - 1))-1)
      SecureRandom.random_number(n)
    end
  end

  # Represents a JSON-RPC Notification. This is an EM::Deferrable class and
  # instances respond to #callback and #errback to store callback actions.
  class Notification < Request
    # Instantiate a Notification.
    # @param uri [URI::HTTP] the JSON-RPC service URI
    # @param api_token [String] the API token. Default: nil
    # @param method [String] the JSON-RPC method name.
    # @param params [Array, Hash] the JSON-RPC method parameters. Default: nil
    # @param namespace [String] the namespace for the JSON-RPC method. The namespace will
    #   be prepended to the method name with a period separator. Default: nil
    # @param symbolize_names [Boolean] If true, symbols are used for the names (keys) when
    #   processing JSON objects; otherwise, strings are used. Default: true
    # @param private_key_file [String] the SSL private key file used for the HTTPS request. Default: nil
    # @param cert_chain_file [String] the SSL cert chain file used for the HTTPS request. Default: nil
    # @param verify_peer [Boolean] indicates whether a server should request a certificate
    #   from a peer, to be verified by user code. Default: nil
    def initialize(uri, api_token: nil, method:, params: nil, namespace: nil,
                   symbolize_names: true, private_key_file: nil,
                   cert_chain_file: nil, verify_peer: nil)
      super(uri,
            api_token: api_token,
            method: method,
            params: params,
            namespace: namespace,
            symbolize_names: symbolize_names,
            is_notification: true,
            private_key_file: private_key_file,
            cert_chain_file: cert_chain_file,
            verify_peer: verify_peer)
    end
  end
end