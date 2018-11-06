# frozen_string_literal: true
# Handles module_function calls to turn methods into public class methods.
# Also creates a private instance copy of the method.
class YARD::Handlers::Ruby::ModuleFunctionHandler < YARD::Handlers::Ruby::Base
  handles method_call(:module_function)
  namespace_only

  process do
    return if statement.jump(:ident) == statement
    case statement.type
    when :var_ref, :vcall
      self.scope = :module
    when :fcall, :command
      statement[1].traverse do |node|
        case node.type
        when :symbol; name = node.first.source
        when :string_content; name = node.source
        else next
        end
        instance_method = MethodObject.new(namespace, name)
        class_method = MethodObject.new(namespace, name, :module)
        instance_method.copy_to(class_method)
        class_method.visibility = :public
      end
    end
  end
end
