module Swagger
  module Blocks
    module Nodes
      # v2.0: https://github.com/swagger-api/swagger-spec/blob/master/versions/2.0.md#path-item-object
      class PathNode < Node
        OPERATION_TYPES = [:get, :put, :post, :delete, :options, :head, :patch].freeze

        # TODO support ^x- Vendor Extensions
        def operation(op, inline_keys = nil, &block)
          op = op.to_sym
          raise ArgumentError.new("#{name} not in #{OPERATION_TYPES}") if !OPERATION_TYPES.include?(op)
          self.data[op] = Swagger::Blocks::Nodes::OperationNode.call(version: version, inline_keys: inline_keys, &block)
        end

        def parameter(inline_keys = nil, &block)
          inline_keys = {'$ref' => "#/parameters/#{inline_keys}"} if inline_keys.is_a?(Symbol)

          self.data[:parameters] ||= []
          self.data[:parameters] << Swagger::Blocks::Nodes::ParameterNode.call(version: version, inline_keys: inline_keys, &block)
        end
      end
    end
  end
end
