# -*- coding: binary -*-

require 'rex/post/meterpreter/extensions/stdapi/constants'
require 'rex/post/meterpreter/extensions/stdapi/sys/registry'

module Rex
module Post
module Meterpreter
module Extensions
module Stdapi
module Sys
module RegistrySubsystem

###
#
# Class wrapper around a remote registry key on the remote side
#
###
class RemoteRegistryKey


  #
  # Initializes an instance of a registry key using the supplied properties
  # and HKEY handle from the server.
  #
  def initialize(client, target_host, root_key, hkey)
    self.client   = client
    self.root_key = root_key
    self.target_host = target_host
    self.hkey     = hkey

    ObjectSpace.define_finalizer( self, self.class.finalize(self.client, self.hkey) )
  end

  def self.finalize(client,hkey)
    proc { self.close(client,hkey) }
  end

  ##
  #
  # Enumerators
  #
  ##

  #
  # Enumerates all of the child keys within this registry key.
  #
  def each_key(&block)
    return enum_key.each(&block)
  end

  #
  # Enumerates all of the child values within this registry key.
  #
  def each_value(&block)
    return enum_value.each(&block)
  end

  #
  # Retrieves all of the registry keys that are direct descendents of
  # the class' registry key.
  #
  def enum_key()
    return self.client.sys.registry.enum_key(self.hkey)
  end

  #
  # Retrieves all of the registry values that exist within the opened
  # registry key.
  #
  def enum_value()
    return self.client.sys.registry.enum_value(self.hkey)
  end


  ##
  #
  # Registry key interaction
  #
  ##

  #
  # Checks to see if a registry key exists
  #
  def check_key_exists(base_key)
    return self.client.sys.registry.check_key_exists(self.hkey, base_key)
  end

  #
  # Opens a registry key that is relative to this registry key.
  #
  def open_key(base_key, perm = KEY_READ)
    return self.client.sys.registry.open_key(self.hkey, base_key, perm)
  end

  #
  # Creates a registry key that is relative to this registry key.
  #
  def create_key(base_key, perm = KEY_READ)
    return self.client.sys.registry.create_key(self.hkey, base_key, perm)
  end

  #
  # Deletes a registry key that is relative to this registry key.
  #
  def delete_key(base_key, recursive = true)
    return self.client.sys.registry.delete_key(self.hkey, base_key, recursive)
  end

  #
  # Closes the open key.  This must be called if the registry
  # key was opened.
  #
  def self.close(client, hkey)
    if hkey != nil
      return client.sys.registry.close_key(hkey)
    end

    return false
  end

  # Instance method for the same
  def close()
    self.class.close(self.client, self.hkey)
  end

  ##
  #
  # Registry value interaction
  #
  ##

  #
  # Sets a value relative to the opened registry key.
  #
  def set_value(name, type, data)
    return self.client.sys.registry.set_value(self.hkey, name, type, data)
  end

  #
  # Queries the attributes of the supplied registry value relative to
  # the opened registry key.
  #
  def query_value(name)
    return self.client.sys.registry.query_value(self.hkey, name)
  end

  #
  # Queries the class of the specified key
  #
  def query_class
    return self.client.sys.registry.query_class(self.hkey)
  end

  #
  # Delete the supplied registry value.
  #
  def delete_value(name)
    return self.client.sys.registry.delete_value(self.hkey, name)
  end

  ##
  #
  # Serializers
  #
  ##

  #
  # Returns the path to the key.
  #
  def to_s
    return "\\\\" + self.target_host + "\\" + self.root_key.to_s + "\\"
  end

  #
  # The open handle to the key on the server.
  #
  attr_reader   :hkey
  #
  # The root key name, such as HKEY_LOCAL_MACHINE.
  #
  attr_reader   :root_key
  #
  # The remote machine name, such as PDC01
  #
  attr_reader   :target_host

protected

  attr_accessor :client # :nodoc:
  attr_writer   :hkey, :root_key, :target_host # :nodoc:
end

end; end; end; end; end; end; end

