# -*- coding: binary -*-

module Msf::Module::Deprecated

  # Additional class methods for deprecated modules
  module ClassMethods
    # Mark this module as deprecated
    #
    # Any time this module is run it will print warnings to that effect.
    #
    # @param deprecation_date [Date,#to_s] The date on which this module will
    #   be removed
    # @param replacement_module [String] The name of a module that users
    #   should be using instead of this deprecated one
    # @return [void]
    def deprecated(deprecation_date=nil, replacement_module=nil)
      # Yes, class instance variables.
      @replacement_module = replacement_module
      @deprecation_date = deprecation_date
    end

    # The name of a module that users should be using instead of this
    # deprecated one
    #
    # @return [String,nil]
    # @see ClassMethods#deprecated
    def replacement_module; @replacement_module; end

    # The date on which this module will be removed
    #
    # @return [Date,nil]
    # @see ClassMethods#deprecated
    def deprecation_date; @deprecation_date; end
  end

  # (see ClassMethods#replacement_module)
  def replacement_module
    if self.class.instance_variable_defined?(:@replacement_module)
      return self.class.replacement_module
    elsif self.class.const_defined?(:DEPRECATION_REPLACEMENT)
      return self.class.const_get(:DEPRECATION_REPLACEMENT)
    end
  end

  # (see ClassMethods#deprecation_date)
  def deprecation_date
    if self.class.instance_variable_defined?(:@deprecation_date)
      return self.class.deprecation_date
    elsif self.class.const_defined?(:DEPRECATION_DATE)
      return self.class.const_get(:DEPRECATION_DATE)
    end
  end

  # Extends with {ClassMethods}
  def self.included(base)
    base.extend(ClassMethods)
  end

  # Print the module deprecation information
  #
  # @return [void]
  def print_deprecation_warning
    print_warning("*"*90)
    print_warning("*%red"+"The module #{fullname} is deprecated!".center(88)+"%clr*")
    if deprecation_date
      print_warning("*"+"It will be removed on or about #{deprecation_date}".center(88)+"*")
    end
    if replacement_module
      print_warning("*"+"Use #{replacement_module} instead".center(88)+"*")
    end
    print_warning("*"*90)
  end

  def init_ui(input = nil, output = nil)
    super(input, output)
    print_deprecation_warning
    @you_have_been_warned = true
  end

  def generate
    print_deprecation_warning
    super
  end

  def setup
    print_deprecation_warning unless @you_have_been_warned
    super
  end

end
