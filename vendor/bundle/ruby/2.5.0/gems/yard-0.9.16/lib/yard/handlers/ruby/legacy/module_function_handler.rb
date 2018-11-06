# frozen_string_literal: true
# (see Ruby::ModuleFunctionHandler)
class YARD::Handlers::Ruby::Legacy::ModuleFunctionHandler < YARD::Handlers::Ruby::Legacy::Base
  handles(/\A(module_function)(\s|\(|$)/)
  namespace_only

  process do
    if statement.tokens.size == 1
      self.scope = :module
    else
      tokval_list(statement.tokens[2..-1], :attr).each do |name|
        instance_method = MethodObject.new(namespace, name)
        class_method = MethodObject.new(namespace, name, :module)
        instance_method.copy_to(class_method)
        class_method.visibility = :public
      end
    end
  end
end
