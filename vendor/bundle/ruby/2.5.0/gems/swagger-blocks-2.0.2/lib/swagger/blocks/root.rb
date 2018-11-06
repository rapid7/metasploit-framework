require 'json'
require 'swagger/blocks/version'

module Swagger
  module Blocks

    # Inject the swagger_root, swagger_api_root, and swagger_model class methods.
    def self.included(base)
      base.extend(ClassMethods)
    end

    def self.build_root_json(swaggered_classes)
      data = Swagger::Blocks::InternalHelpers.parse_swaggered_classes(swaggered_classes)

      if data[:root_node].is_swagger_2_0?
        data[:root_node].key(:paths, data[:path_nodes]) # Required, so no empty check.
        if data[:schema_nodes] && !data[:schema_nodes].empty?
          data[:root_node].key(:definitions, data[:schema_nodes])
        end
      end

      data[:root_node].as_json
    end
  end
end
