module Swagger
  module Blocks
    module Nodes
      class RootNode < Node

        def info(inline_keys = nil, &block)
          self.data[:info] = Swagger::Blocks::Nodes::InfoNode.call(version: version, inline_keys: inline_keys, &block)
        end

        def parameter(param, inline_keys = nil, &block)
          raise NotSupportedError unless is_swagger_2_0?

          # TODO validate 'param' is as per spec
          self.data[:parameters] ||= {}
          self.data[:parameters][param] = Swagger::Blocks::Nodes::ParameterNode.call(version: version, inline_keys: inline_keys, &block)
        end

        def response(resp, inline_keys = nil, &block)
          raise NotSupportedError unless is_swagger_2_0?

          # TODO validate 'resp' is as per spec
          self.data[:responses] ||= {}
          self.data[:responses][resp] = Swagger::Blocks::Nodes::ResponseNode.call(version: version, inline_keys: inline_keys, &block)
        end

        def security_definition(name, inline_keys = nil, &block)
          raise NotSupportedError unless is_swagger_2_0?

          self.data[:securityDefinitions] ||= {}
          self.data[:securityDefinitions][name] = Swagger::Blocks::Nodes::SecuritySchemeNode.call(version: version, inline_keys: inline_keys, &block)
        end

        def security(inline_keys = nil, &block)
          raise NotSupportedError unless is_swagger_2_0?

          self.data[:security] ||= []
          self.data[:security] << Swagger::Blocks::Nodes::SecurityRequirementNode.call(version: version, inline_keys: inline_keys, &block)
        end

        def externalDocs(inline_keys = nil, &block)
          self.data[:externalDocs] = Swagger::Blocks::Nodes::ExternalDocsNode.call(version: version, inline_keys: inline_keys, &block)
        end

        def tag(inline_keys = nil, &block)
          raise NotSupportedError unless is_swagger_2_0?

          self.data[:tags] ||= []
          self.data[:tags] << Swagger::Blocks::Nodes::TagNode.call(version: version, inline_keys: inline_keys, &block)
        end

        # Use 'tag' instead.
        # @deprecated
        alias_method :tags, :tag
      end
    end
  end
end
