# -*- coding: binary -*-

module Rex
module Post
module HWBridge

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
