# frozen_string_literal: true
# Handles 'raise' calls inside methods
class YARD::Handlers::Ruby::ExceptionHandler < YARD::Handlers::Ruby::Base
  handles method_call(:raise)

  process do
    return unless owner.is_a?(MethodObject) # Only methods yield
    return if [:command_call, :call].include? statement.type
    return if owner.has_tag?(:raise)

    klass = nil
    if statement.call?
      params = statement.parameters(false)
      if params.size == 1
        if params.first.ref? && params.first.first.type != :ident
          klass = params.first.source
        elsif params.first.call? && params.first.method_name(true) == :new
          klass = params.first.namespace.source
        end
      elsif params.size > 1
        klass = params.first.source
      end
    end

    owner.add_tag YARD::Tags::Tag.new(:raise, '', klass) if klass
  end
end
