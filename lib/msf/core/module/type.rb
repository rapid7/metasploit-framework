# Methods dealing with the type of the module.
module Msf::Module::Type
  extend ActiveSupport::Concern

  module ClassMethods
    # The type of this metasploit `Class`.
    #
    # @return [ActiveSupport::StringInquirer] if {#module_type=} called.
    # @return [nil] if {#module_type=} not called in this class or any ancestor.
    def module_type
      nil
    end

    # Sets {#module_type} for this class and all subclasses that don't set their own {#module_type}.
    #
    # @see Class#class_attribute
    # @see https://github.com/rails/rails/blob/7ed5bdc834479c39e3b0ad5a38bcffe27983c10d/activesupport/lib/active_support/core_ext/class/attribute.rb#L78-L93
    def module_type=(module_type)
      module_type_string_inquirer = ActiveSupport::StringInquirer.new(module_type)

      singleton_class.class_eval do
        remove_possible_method(:module_type)

        define_method(:module_type) do
          module_type_string_inquirer
        end
      end

      module_type_string_inquirer
    end

    # @deprecated Use {#module_type} instead
    # @return (see module_type)
    def type
      ActiveSupport::Deprecation.warn "#{self}.#{__method__} is deprecated. Use #{self}.module_type instead", caller
      module_type
    end
  end

  # @return (see module_type)
  # @see https://github.com/rails/rails/blob/7ed5bdc834479c39e3b0ad5a38bcffe27983c10d/activesupport/lib/active_support/core_ext/class/attribute.rb#L97-L99
  def module_type
    self.class.module_type
  end

  # @deprecated Use {#module_type} instead
  # @return (see #module_type)
  def type
    ActiveSupport::Deprecation.warn "#{self}##{__method__} is deprecated. Use #{self}#module_type instead", caller
    module_type
  end

  # @!method auxiliary?
  #   Whether {#module_type} is auxiliary.
  #
  #   @return [true] if {#module_type} is auxiliary.
  #   @return [false] otherwise
  #
  # @!method encoder?
  #   Whether {#module_type} is encoder.
  #
  #   @return [true] if {#module_type} is encoder.
  #   @return [false] otherwise
  #
  # @!method exploit?
  #   Whether {#module_type} is exploit.
  #
  #   @return [true] if {#module_type} is exploit.
  #   @return [false] otherwise
  #
  # @!method nop?
  #   Whether {#module_type} is nop.
  #
  #   @return [true] if {#module_type} is nop.
  #   @return [false] otherwise
  #
  # @!method payload?
  #   Whether {#module_type} is payload.
  #
  #   @return [true] if {#module_type} is payload.
  #   @return [false] otherwise
  #
  # @!method post?
  #   Whether {#module_type} is post.
  #
  #   @return [true] if {#module_type} is post.
  #   @return [false] otherwise
  delegate :auxiliary?,
           :encoder?,
           :exploit?,
           :nop?,
           :post?,
           :payload?,
           to: :module_type
end