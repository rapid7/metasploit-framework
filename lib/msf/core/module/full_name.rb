# @note {Msf::Module::ModuleInfo#name} is unrelated to {#fullname} and should instead be thought of as the title or
#   summary of the module.
#
# Names related to {#fullname}, such as {#fullname}, {#refname}, and {#shortname}.
module Msf::Module::FullName
  extend ActiveSupport::Concern

  module ClassMethods
    #
    # Attributes
    #


    # @attribute refname
    #   The module's name that is assigned to it by the framework
    #   or derived from the path that the module is loaded from.
    attr_accessor :refname

    #
    # Class Methods
    #

    def fullname
      "#{type}/#{refname}"
    end

    def promptname
      refname
    end

    def shortname
      refname.split('/').last
    end

    #
    # Returns a list of alternate names the module might go by.
    #
    def aliases
      const_defined?(:Aliases) ? const_get(:Aliases) : []
    end
  end

  #
  # Instance Methods
  #

  #
  # Returns the module's framework full reference name.  This is the
  # short name that end-users work with (refname) plus the type
  # of module prepended.  Ex:
  #
  # payloads/windows/shell/reverse_tcp
  #
  def fullname
    self.class.fullname
  end

  #
  # Returns the module's framework reference name.  This is the
  # short name that end-users work with.  Ex:
  #
  # windows/shell/reverse_tcp
  #
  def refname
    self.class.refname
  end

  #
  # Returns the module's framework prompt-friendly name.
  #
  # reverse_tcp
  #
  def promptname
    self.class.promptname
  end

  #
  # Returns the module's framework short name.
  #
  # reverse_tcp
  #
  def shortname
    self.class.shortname
  end

  def aliases
    self.class.aliases
  end
end
