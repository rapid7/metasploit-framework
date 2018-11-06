# frozen_string_literal: true
module YARD
  module Templates::Helpers
    # Helpers for various object types
    module FilterHelper
      # @return [Boolean] whether an object is a method
      def is_method?(object)
        object.type == :method
      end

      # @return [Boolean] whether an object is a namespace
      def is_namespace?(object)
        object.is_a?(CodeObjects::NamespaceObject)
      end

      # @return [Boolean] whether an object is a class
      def is_class?(object)
        object.is_a?(CodeObjects::ClassObject)
      end

      # @return [Boolean] whether an object is a module
      def is_module?(object)
        object.is_a?(CodeObjects::ModuleObject)
      end
    end
  end
end
