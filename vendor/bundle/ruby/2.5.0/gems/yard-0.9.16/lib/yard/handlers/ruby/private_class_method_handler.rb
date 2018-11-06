# frozen_string_literal: true
# Sets visibility of a class method to private.
class YARD::Handlers::Ruby::PrivateClassMethodHandler < YARD::Handlers::Ruby::Base
  include YARD::Handlers::Ruby::DecoratorHandlerMethods

  handles method_call(:private_class_method)
  namespace_only

  process do
    process_decorator :scope => :class do |method|
      method.visibility = :private if method.respond_to? :visibility=
    end
  end
end
