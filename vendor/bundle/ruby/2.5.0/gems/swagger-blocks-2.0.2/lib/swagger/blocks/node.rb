module Swagger
  module Blocks
    # Base node for representing every object in the Swagger DSL.
    class Node
      attr_accessor :name
      attr_writer :version

      def self.call(options = {}, &block)
        # Create a new instance and evaluate the block into it.
        instance = new
        instance.name = options[:name] if options[:name]
        instance.version = options[:version]
        instance.keys options[:inline_keys]
        instance.instance_eval(&block) if block
        instance
      end

      def as_json
        result = {}

        self.data.each do |key, value|
          if value.is_a?(Node)
            result[key] = value.as_json
          elsif value.is_a?(Array)
            result[key] = []
            value.each { |v| result[key] << (v.respond_to?(:as_json) ? v.as_json : v) }
          elsif is_swagger_2_0? && value.is_a?(Hash)
            result[key] = {}
            value.each_pair {|k, v| result[key][k] = (v.respond_to?(:as_json) ? v.as_json : v) }
          elsif is_swagger_2_0? && key.to_s.eql?('$ref') && (value.to_s !~ %r{^#/|https?://})
            result[key] = "#/definitions/#{value}"
          else
            result[key] = value
          end
        end
        return result if !name
        # If 'name' is given to this node, wrap the data with a root element with the given name.
        {name => result}
      end

      def data
        @data ||= {}
      end

      def keys(data)
        self.data.merge!(data) if data
      end

      def key(key, value)
        self.data[key] = value
      end

      def version
        return @version if instance_variable_defined?('@version') && @version
        return '2.0' if data.has_key?(:swagger) && data[:swagger] == '2.0'
        raise DeclarationError, "You must specify swagger '2.0'"
      end

      def is_swagger_2_0?
        version == '2.0'
      end
    end
  end
end
