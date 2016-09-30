# -*- coding: binary -*-
require 'rex'
require 'rex/proto'

module Rex

###
#
# The service module is used to extend classes that are passed into the
# service manager start routine.  It provides extra methods, such as reference
# counting, that are used to track the service instances more uniformly.
#
###
module Service
  include Ref

  require 'rex/services/local_relay'

  #
  # Returns the hardcore, as in porno, alias for this service.  This is used
  # by the service manager to manage singleton services.
  #
  def self.hardcore_alias(*args)
    return "__#{args}"
  end

  def deref
    rv = super

    # If there's only one reference, then it's the service managers.
    if @_references == 1
      Rex::ServiceManager.stop_service(self)
    end

    rv
  end

  #
  # Calls stop on the service once the ref count drops.
  #
  def cleanup
    stop
  end

  attr_accessor :alias

end

end
