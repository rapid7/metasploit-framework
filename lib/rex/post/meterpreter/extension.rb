# -*- coding: binary -*-

module Rex
module Post
module Meterpreter

#
# An error that is raised when a particular Meterpreter extension can not be
# loaded for any reason.
#
# @attr_reader [String] name The name of the extension that could not be loaded.
class ExtensionLoadError < RuntimeError
  attr_reader :name

  # @param [String] name The name of the extension that could not be loaded.
  def initialize(name:)
    @name = name
    super
  end
end

###
#
# Base class for all extensions that holds a reference to the
# client context that they are part of.  Each extension also has a defined
# name through which it is referenced.
#
###
class Extension

  #
  # Initializes the client and name attributes.
  #
  def initialize(client, name)
    self.client = client
    self.name   = name
  end

  #
  # The name of the extension.
  #
  attr_accessor :name
protected
  attr_accessor :client # :nodoc:
end

end; end; end
