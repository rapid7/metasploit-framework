module Swagger
  module Blocks
    module Nodes
      # v2.0: https://github.com/swagger-api/swagger-spec/blob/master/versions/2.0.md#responseObject
      class ResponseNode < Node
        def schema(inline_keys = nil, &block)
          self.data[:schema] = Swagger::Blocks::Nodes::SchemaNode.call(version: version, inline_keys: inline_keys, &block)
        end

        def header(head, inline_keys = nil, &block)
          # TODO validate 'head' is as per spec
          self.data[:headers] ||= {}
          self.data[:headers][head] = Swagger::Blocks::Nodes::HeaderNode.call(version: version, inline_keys: inline_keys, &block)
        end

        def example(exam, inline_keys = nil, &block)
          # TODO validate 'exam' is as per spec
          self.data[:examples] ||= {}
          self.data[:examples][exam] = Swagger::Blocks::Nodes::ExampleNode.call(version: version, inline_keys: inline_keys, &block)
        end
      end
    end
  end
end
