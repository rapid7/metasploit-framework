module Swagger
  module Blocks
    module Nodes
      # v2.0: https://github.com/swagger-api/swagger-spec/blob/master/versions/2.0.md#tag-object
      class TagNode < Node

        # TODO support ^x- Vendor Extensions

        def externalDocs(inline_keys = nil, &block)
          self.data[:externalDocs] = Swagger::Blocks::Nodes::ExternalDocsNode.call(version: version, inline_keys: inline_keys, &block)
        end
      end
    end
  end
end
