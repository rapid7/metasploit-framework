require 'oj' unless defined?(::Oj)

::Oj.default_options = {:mode => :compat}

module MultiJson
  module Engines
    # Use the Oj library to encode/decode.
    class Oj
      ParseError = SyntaxError

      def self.decode(string, options = {}) #:nodoc:
        opts = {}
        opts[:symbol_keys] = options[:symbolize_keys]
        ::Oj.load(string, opts)
      end

      def self.encode(object, options = {}) #:nodoc:
        ::Oj.dump(object, options)
      end
    end
  end
end
