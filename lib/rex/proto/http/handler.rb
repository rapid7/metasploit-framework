# -*- coding: binary -*-
module Rex
module Proto
module Http

###
#
# This class acts as the base class for all handlers.
#
###
class Handler

  require 'rex/proto/http/handler/erb'
  require 'rex/proto/http/handler/proc'

  #
  # Initializes the handler instance as being associated with the supplied
  # server.
  #
  def initialize(server)
    self.server = server
  end

  #
  # By default, handlers do not require a relative resource.
  #
  def self.relative_resource_required?
    false
  end

  #
  # Calls the class method.
  #
  def relative_resource_required?
    self.class.relative_resource_required?
  end

protected

  attr_accessor :server # :nodoc:

end


end
end
end
