module Swagger
  module Blocks
    module Nodes
      # v2.0:
      class ItemsNode < Node
        def property(name, inline_keys = nil, &block)
          self.data[:properties] ||= Swagger::Blocks::Nodes::PropertiesNode.new
          self.data[:properties].version = version
          self.data[:properties].property(name, inline_keys, &block)
        end
        
        def items(inline_keys = nil, &block)
          self.data[:items] = Swagger::Blocks::Nodes::ItemsNode.call(version: version, inline_keys: inline_keys, &block)
        end
      end
    end
  end
end
