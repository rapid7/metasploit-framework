module Swagger
  module Blocks
    module Nodes
      # v2.0: https://github.com/swagger-api/swagger-spec/blob/master/versions/2.0.md#security-scheme-object
      class SecuritySchemeNode < Node
        # TODO support ^x- Vendor Extensions

        def scopes(inline_keys = nil, &block)
          self.data[:scopes] = Swagger::Blocks::Nodes::ScopesNode.call(version: version, inline_keys: inline_keys, &block)
        end
      end
    end
  end
end
