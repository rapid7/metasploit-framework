# -*- coding: binary -*-
require 'msf/core/plugin'

module Msf

###
#
# This class manages the loading and unloading plugins.  All plugins must
# implement the Plugin base class interface.
#
###
class PluginManager < Array

  include Framework::Offspring

  #
  # The hash of path names to classes that is used during load.
  #
  @@path_hash = {}

  #
  # Check the hash using the supplied path name to see if there is already a
  # class association.
  #
  def self.check_path_hash(path)
    @@path_hash[path]
  end

  #
  # Set the class that's associated with the supplied hash.
  #
  def self.set_path_hash(path, klass)
    @@path_hash[path] = klass
  end

  #
  # Initializes the plugin manager.
  #
  def initialize(framework)
    self.framework = framework
  end

  #
  # Loads a plugin from the supplied path and returns the instance that is
  # created as a result.
  #
  def load(path, opts = {})
    # Check to see if a plugin from this path has already been loaded
    # before.
    if ((klass = self.class.check_path_hash(path)) == nil)
      old = Msf::Plugin.constants
      require(path)
      new = Msf::Plugin.constants

      # No new classes added?
      if ((diff = new - old).empty?)
        raise RuntimeError, "No classes were loaded from #{path} in the Msf::Plugin namespace."
      end

      # Grab the class
      klass = Msf::Plugin.const_get(diff[0])

      # Cache the path to class association for future reference
      self.class.set_path_hash(path, klass)
    # If it's already been loaded, go ahead and try to re-load it in case
    # the contents have changed.
    else
      Kernel.load(path + ".rb")
    end

    # Create an instance of the plugin and let it initialize
    instance = klass.create(framework, opts)

    # Add it to the list of plugins
    if (self.member?(instance) == false)
      self.unshift(instance)
    end

    # Return the instance to the caller
    instance
  end

  #
  # Unloads a plugin using the instance that was returned from a previous
  # call to load.
  #
  def unload(inst)
    # If the reference count drops to zero, remove it from the list of
    # loaded plugins.  This will indirectly call the cleanup method on the
    # plugin.
    if (inst.deref == true)
      delete(inst)
    end
  end

end

end
