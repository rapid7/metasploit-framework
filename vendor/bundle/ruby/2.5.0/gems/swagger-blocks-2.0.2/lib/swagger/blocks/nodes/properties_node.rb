module Swagger
  module Blocks
    module Nodes
      class PropertiesNode < Node
        def property(name, inline_keys = nil, &block)
          self.data[name] = Swagger::Blocks::Nodes::PropertyNode.call(version: version, inline_keys: inline_keys, &block)
        end
      end
    end
  end
end
