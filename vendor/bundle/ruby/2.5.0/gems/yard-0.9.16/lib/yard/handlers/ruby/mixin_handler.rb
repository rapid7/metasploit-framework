# frozen_string_literal: true
# Handles the 'include' statement to mixin a module in the instance scope
class YARD::Handlers::Ruby::MixinHandler < YARD::Handlers::Ruby::Base
  handles method_call(:include)
  namespace_only

  process do
    errors = []
    statement.parameters(false).reverse.each do |mixin|
      begin
        process_mixin(mixin)
      rescue YARD::Parser::UndocumentableError => err
        errors << err.message
      end
    end
    unless errors.empty?
      msg = errors.size == 1 ? ": #{errors[0]}" : "s: #{errors.join(", ")}"
      raise YARD::Parser::UndocumentableError, "mixin#{msg} for class #{namespace.path}"
    end
  end

  protected

  def process_mixin(mixin)
    raise YARD::Parser::UndocumentableError unless mixin.ref?
    raise YARD::Parser::UndocumentableError if mixin.first.type == :ident

    case obj = Proxy.new(namespace, mixin.source)
    when ConstantObject # If a constant is included, use its value as the real object
      obj = Proxy.new(namespace, obj.value, :module)
    else
      obj = Proxy.new(namespace, mixin.source, :module)
    end

    namespace.mixins(scope).unshift(obj) unless namespace.mixins(scope).include?(obj)
  end
end
