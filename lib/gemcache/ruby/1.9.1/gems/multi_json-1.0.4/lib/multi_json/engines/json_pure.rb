require 'json/pure' unless defined?(::JSON)
require 'multi_json/engines/json_common'

module MultiJson
  module Engines
    # Use JSON pure to encode/decode.
    class JsonPure
      ParseError = ::JSON::ParserError
      extend JsonCommon
    end
  end
end
