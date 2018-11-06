# frozen_string_literal: true
module YARD
  module Handlers
    module Ruby
      # Sets visibility of a constant (class, module, const)
      class PrivateConstantHandler < YARD::Handlers::Ruby::Base
        handles method_call(:private_constant)
        namespace_only

        process do
          errors = []
          statement.parameters.each do |param|
            next unless AstNode === param
            begin
              privatize_constant(param)
            rescue UndocumentableError => err
              errors << err.message
            end
          end
          unless errors.empty?
            msg = errors.size == 1 ? ": #{errors[0]}" : "s: #{errors.join(", ")}"
            raise UndocumentableError, "private constant#{msg} for #{namespace.path}"
          end
        end

        private

        def privatize_constant(node)
          if node.literal? || (node.type == :var_ref && node[0].type == :const)
            node = node.jump(:tstring_content, :const)
            const = Proxy.new(namespace, node[0])
            ensure_loaded!(const)
            const.visibility = :private
          else
            raise UndocumentableError, "invalid argument to private_constant: #{node.source}"
          end
        rescue NamespaceMissingError
          raise UndocumentableError, "private visibility set on unrecognized constant: #{node[0]}"
        end
      end
    end
  end
end
