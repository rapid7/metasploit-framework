# frozen_string_literal: true
# Sets visibility of a class method to public.
class YARD::Handlers::Ruby::PublicClassMethodHandler < YARD::Handlers::Ruby::Base
  include YARD::Handlers::Ruby::DecoratorHandlerMethods

  handles method_call(:public_class_method)
  namespace_only

  process do
    process_decorator :scope => :class do |method|
      method.visibility = :public if method.respond_to? :visibility
    end
  end
end
