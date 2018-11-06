# frozen_string_literal: true
module YARD::CodeObjects
  register_separator NSEP, :constant

  # A +ConstantObject+ represents a Ruby constant (not a module or class).
  # To access the constant's (source code) value, use {#value}.
  class ConstantObject < Base
    # The source code representing the constant's value
    # @return [String] the value the constant is set to
    attr_reader :value

    def value=(value)
      @value = format_source(value)
    end
  end
end
