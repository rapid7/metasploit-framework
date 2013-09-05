# -*- coding: binary -*-
require 'singleton'
require 'rex'
require 'rex/service'

module Rex

###
#
# This class manages service allocation and interaction.  This class can be
# used to start HTTP servers and manage them and all that stuff.  Yup.
#
###
class ServiceManager < Hash

  #
  # This class is a singleton.
  #
  include Singleton

  #
  # Calls the instance method to start a service.
  #
  def self.start(klass, *args)
    self.instance.start(klass, *args)
  end

  #
  # Calls the instance method to stop a service.
  #
  def self.stop(klass, *args)
    self.instance.stop(klass, *args)
  end

  #
  # Stop a service using the alias that's associated with it.
  #
  def self.stop_by_alias(als)
    self.instance.stop_by_alias(als)
  end

  #
  # Stop the supplied service instance.
  #
  def self.stop_service(service)
    self.instance.stop_service(service)
  end

  #
  # Starts a service and assigns it a unique name in the service hash.
  #
  def start(klass, *args)
    # Get the hardcore alias.
    hals = "#{klass}" + klass.hardcore_alias(*args)

    # Has a service already been constructed for this guy?  If so, increment
    # its reference count like it aint no thang.
    if (inst = self[hals])
      inst.ref
      return inst
    end

    inst = klass.new(*args)
    als  = inst.alias

    # Find an alias that isn't taken.
    if (self[als])
      cnt  = 1
      cnt += 1 while (self[als + " #{cnt}"])
      als  = inst.alias + " #{cnt}"
    end

    # Extend the instance as a service.
    inst.extend(Rex::Service)

    # Re-aliases the instance.
    inst.alias = als

    # Fire up the engines.  If an error occurs an exception will be
    # raised.
    inst.start

    # Alias associate and initialize reference counting
    self[als] = self[hals] = inst.refinit

    # Pass the caller a reference
    inst.ref

    inst
  end

  #
  # Stop a service using a given klass and arguments.  These should mirror
  # what was originally passed to start exactly.  If the reference count of
  # the service drops to zero the service will be destroyed.
  #
  def stop(klass, *args)
    stop_service(hals[hardcore_alias(klass, *args)])
  end

  #
  # Stops a service using the provided alias.
  #
  def stop_by_alias(als)
    stop_service(self[als])
  end

  #
  # Stops a service instance.
  #
  def stop_service(inst)
    # Stop the service and be done wif it, but only if the number of
    # references has dropped to zero
    if (inst)
      # Since the instance may have multiple aliases, scan through
      # all the pairs for matching stuff.
      self.each_pair { |cals, cinst|
        self.delete(cals) if (inst == cinst)
      }

      # Lose the list-held reference to the instance
      inst.deref

      return true
    end

    # Return false if the service isn't there
    return false
  end

  #
  # Overrides the builtin 'each' operator to avoid the following exception on Ruby 1.9.2+
  #    "can't add a new key into hash during iteration"
  #
  def each(&block)
    list = []
    self.keys.sort.each do |sidx|
      list << [sidx, self[sidx]]
    end
    list.each(&block)
  end

protected

  #
  # Returns the alias for a given service instance.
  #
  def hardcore_alias(klass, *args)
    "__#{klass.name}#{args}"
  end

end

end
