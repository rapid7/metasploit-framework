# -*- coding: binary -*-
module Msf

# This class provides a generalized interface to persisting information,
# either in whole or in part, about the state of the framework.  This can
# be used to store data that can later be reinitialized in a new instance
# of the framework or to provide a simple mechanism for generating reports
# of some form.
# @abstract
class PersistentStorage

  #@private
  @@storage_classes = {}

  # Creates an instance of the storage class with the supplied name.  The
  # array supplied as an argument is passed to the constructor of the
  # associated class as a means of generic initialization.
  # @param [String] name the name of the storage class.
  # @param [Object] params the parameters to give the new class.
  # @return [PersistentStorage, void] the newly created class or nil.
  def self.create(name, *params)
    if (klass = @@storage_classes[name])
      klass.new(*params)
    else
      nil
    end
  end

  # Stub initialization routine that takes the params passed to create.
  # @param [Object] params the parameters to initialize with.
  def initialize(*params)
  end

  # This methods stores all or part of the current state of the supplied
  # framework instance to whatever medium the derived class implements.
  # If the derived class does not implement this method, the
  # NotImplementedError is raised.
  # @raise [NotImpementedError] raised if not implemented.
  # @param [Msf::Framework] framework framework state to store.
  # @return [void] no implementation.
  def store(framework)
    raise NotImplementedError
  end

  # This method initializes the supplied framework instance with the state
  # that is stored in the persisted backing that the derived class
  # implements.  If the derived class does not implement this method, the
  # NotImplementedError is raised.
  # @raise [NotImplementedError] raised if not implemented.
  # @param [Msf::Framework] framework framework to restore state to.
  # @return [void] no implementation.
  def fetch(framework)
    raise NotImplementedError
  end

  # This method adds a new storage class to the hash of storage classes that
  # can be created through create.
  # @param [String] name the name of the storage class.
  # @param [PersistentStorage] klass the storage class to add.
  # @return [void]
  def self.add_storage_class(name, klass)
    @@storage_classes[name] = klass
  end

protected

end

end

require 'msf/base/persistent_storage/flatfile'
