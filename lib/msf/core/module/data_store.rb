module Msf::Module::DataStore
  #
  # Attributes
  #

  # @attribute [r] datastore
  #   The module-specific datastore instance.
  #
  #   @return [Hash{String => String}]
  attr_reader   :datastore

  #
  # Imports default options into the module's datastore, optionally clearing
  # all of the values currently set in the datastore.
  #
  def import_defaults(clear_datastore = true)
    # Clear the datastore if the caller asked us to
    self.datastore.clear if clear_datastore

    self.datastore.import_options(self.options, 'self', true)

    # If there are default options, import their values into the datastore
    if (module_info['DefaultOptions'])
      self.datastore.import_options_from_hash(module_info['DefaultOptions'], true, 'self')
    end
  end

  #
  # Import the target's DefaultOptions hash into the datastore.
  #
  def import_target_defaults
    return unless target && target.default_options

    datastore.import_options_from_hash(target.default_options, true, 'self')
  end

  #
  # Overrides the class' own datastore with the one supplied.  This is used
  # to allow modules to share datastores, such as a payload sharing an
  # exploit module's datastore.
  #
  def share_datastore(ds)
    self.datastore = ds
    self.datastore.import_options(self.options)
  end

  protected

  attr_writer :datastore
end
