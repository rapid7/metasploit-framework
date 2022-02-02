module Msf::RPC::JSON

  # Represents a JSON-RPC response.
  class Response
    attr_reader :response
    attr_reader :id
    attr_reader :result

    # Parse response and return a new Response instance.
    # @param response [Hash] A response hash.
    # @param symbolize_names [Boolean] If true, symbols are used for the names (keys) when
    #   processing JSON objects; otherwise, strings are used. Default: true
    # @returns [Response] Response object that represents the response hash.
    def self.parse(response, symbolize_names: true)
      id_key = symbolize_names ? :id : :id.to_s
      result_key = symbolize_names ? :result : :result.to_s

      id = response[id_key]
      result = response[result_key]

      Response.new(id: id, result: result, response: response)
    end

    # Instantiate a Response object.
    #
    # @param id [Integer, String, NilClass] It MUST be the same as the value of the
    #   id member in the Request Object. If there was an error in detecting the id
    #   in the Request object (e.g. Parse error/Invalid Request), it MUST be Null.
    # @param result [Integer, String, Array, Hash, NilClass] Result of the method.
    # @param response [Hash] A response hash. The default value is nil.
    def initialize(id:, result:, response: nil)
      @id = id
      @result = result
      @response = response
    end
  end
end