# frozen_string_literal: true
module YARD::CodeObjects
  # Represents an instance method of a module that was mixed into the class
  # scope of another namespace.
  #
  # @see MethodObject
  class ExtendedMethodObject
    instance_methods.each {|m| undef_method(m) unless m =~ /^__/ || m.to_sym == :object_id }

    # @return [Symbol] always +:class+
    def scope; :class end

    # Sets up a delegate for {MethodObject} obj.
    #
    # @param [MethodObject] obj the instance method to treat as a mixed in
    #   class method on another namespace.
    def initialize(obj) @del = obj end

    # Sends all methods to the {MethodObject} assigned in {#initialize}
    # @see #initialize
    # @see MethodObject
    def method_missing(sym, *args, &block) @del.__send__(sym, *args, &block) end
  end
end
