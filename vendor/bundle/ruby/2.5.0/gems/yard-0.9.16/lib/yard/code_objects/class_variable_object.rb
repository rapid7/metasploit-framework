# frozen_string_literal: true
module YARD::CodeObjects
  register_separator NSEP, :class_variable

  # Represents a class variable inside a namespace. The path is expressed
  # in the form "A::B::@@classvariable"
  class ClassVariableObject < Base
    # @return [String] the class variable's value
    attr_accessor :value
  end
end
