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

    #
    # Classes themselves are never aliased (at the moment, anyway), but this is
    # always just the {#fullname}.
    #
    def realname
      fullname
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

  attr_accessor :aliased_as

  #
  # Returns the module's framework full reference name.  This is the
  # short name that end-users work with (refname) plus the type
  # of module prepended.  Ex:
  #
  # payloads/windows/shell/reverse_tcp
  #
  def fullname
    aliased_as || self.class.fullname
  end

  #
  # Always return the module's framework full reference name, even when the
  # module is aliased.
  #
  def realname
    self.class.fullname
  end

  #
  # Returns the module's framework reference name.  This is the
  # short name that end-users work with.  Ex:
  #
  # windows/shell/reverse_tcp
  #
  def refname
    fullname.delete_prefix("#{type}/")
  end

  #
  # Returns the module's framework prompt-friendly name.
  #
  # windows/shell/reverse_tcp
  #
  def promptname
    refname
  end

  #
  # Returns the module's framework short name.
  #
  # reverse_tcp
  #
  def shortname
    refname.split('/').last
  end

  def aliases
    self.class.aliases
  end
end
