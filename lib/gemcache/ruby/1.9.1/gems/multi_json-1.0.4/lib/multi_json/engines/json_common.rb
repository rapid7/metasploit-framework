module MultiJson
  module Engines
    module JsonCommon

      def decode(string, options = {})
        opts = {}
        opts[:symbolize_names] = options[:symbolize_keys]
        string = string.read if string.respond_to?(:read)
        ::JSON.parse(string, opts)
      end

      def encode(object, options = {})
        object.to_json(process_options(options))
      end

      protected

        def process_options(options={})
          return options if options.empty?
          opts = {}
          opts.merge!(JSON::PRETTY_STATE_PROTOTYPE.to_h) if options.delete(:pretty)
          opts.merge! options
        end

    end
  end
end