module Swagger
  module Blocks
    module Nodes
      class AllOfNode < Node
        def as_json
          result = []

          self.data.each do |value|
            if value.is_a?(Node)
              result << value.as_json
            elsif value.is_a?(Array)
              r = []
              value.each { |v| r << (v.respond_to?(:as_json) ? v.as_json : v) }
              result << r
            elsif is_swagger_2_0? && value.is_a?(Hash)
              r = {}
              value.each_pair {|k, v| r[k] = (v.respond_to?(:as_json) ? v.as_json : v) }
              result << r
            else
              result = value
            end
          end
          return result if !name
          # If 'name' is given to this node, wrap the data with a root element with the given name.
          {name => result}
        end

        def data
          @data ||= []
        end

        def key(key, value)
          raise NotSupportedError
        end

        def schema(inline_keys = nil, &block)
          data << Swagger::Blocks::Nodes::SchemaNode.call(version: version, inline_keys: inline_keys, &block)
        end
      end
    end
  end
end
