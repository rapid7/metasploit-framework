require 'swagger/blocks/root'
require 'swagger/blocks/internal_helpers'
require 'swagger/blocks/class_methods'
require 'swagger/blocks/errors'

module Swagger
  module Blocks
    autoload :Node, 'swagger/blocks/node'

    module Nodes
      autoload :AllOfNode, 'swagger/blocks/nodes/all_of_node'
      autoload :ContactNode, 'swagger/blocks/nodes/contact_node'
      autoload :ExampleNode, 'swagger/blocks/nodes/example_node'
      autoload :ExternalDocsNode, 'swagger/blocks/nodes/external_docs_node'
      autoload :HeaderNode, 'swagger/blocks/nodes/header_node'
      autoload :InfoNode, 'swagger/blocks/nodes/info_node'
      autoload :ItemsNode, 'swagger/blocks/nodes/items_node'
      autoload :LicenseNode, 'swagger/blocks/nodes/license_node'
      autoload :OperationNode, 'swagger/blocks/nodes/operation_node'
      autoload :ParameterNode, 'swagger/blocks/nodes/parameter_node'
      autoload :PathNode, 'swagger/blocks/nodes/path_node'
      autoload :PropertiesNode, 'swagger/blocks/nodes/properties_node'
      autoload :PropertyNode, 'swagger/blocks/nodes/property_node'
      autoload :ResponseNode, 'swagger/blocks/nodes/response_node'
      autoload :RootNode, 'swagger/blocks/nodes/root_node'
      autoload :SchemaNode, 'swagger/blocks/nodes/schema_node'
      autoload :ScopesNode, 'swagger/blocks/nodes/scopes_node'
      autoload :SecurityRequirementNode, 'swagger/blocks/nodes/security_requirement_node'
      autoload :SecuritySchemeNode, 'swagger/blocks/nodes/security_scheme_node'
      autoload :TagNode, 'swagger/blocks/nodes/tag_node'
      autoload :XmlNode, 'swagger/blocks/nodes/xml_node'
    end
  end
end
