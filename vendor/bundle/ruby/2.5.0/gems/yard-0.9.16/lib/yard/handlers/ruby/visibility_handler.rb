# frozen_string_literal: true
# Handles 'private', 'protected', and 'public' calls.
class YARD::Handlers::Ruby::VisibilityHandler < YARD::Handlers::Ruby::Base
  include YARD::Handlers::Ruby::DecoratorHandlerMethods

  handles method_call(:private)
  handles method_call(:protected)
  handles method_call(:public)
  namespace_only

  process do
    return if (ident = statement.jump(:ident)) == statement
    case statement.type
    when :var_ref, :vcall
      self.visibility = ident.first.to_sym
    when :fcall, :command
      process_decorator do |method|
        method.visibility = ident.first if method.respond_to? :visibility=
      end
    end
  end
end
