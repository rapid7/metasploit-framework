module Swagger
  module Blocks
    module Nodes
      # v2.0: https://github.com/swagger-api/swagger-spec/blob/master/versions/2.0.md#infoObject
      class InfoNode < Node
        def contact(inline_keys = nil, &block)
          self.data[:contact] = Swagger::Blocks::Nodes::ContactNode.call(version: version, inline_keys: inline_keys, &block)
        end

        def license(inline_keys = nil, &block)
          self.data[:license] = Swagger::Blocks::Nodes::LicenseNode.call(version: version, inline_keys: inline_keys, &block)
        end
      end
    end
  end
end
