module Msf::Module::DataStore
  #
  # Attributes
  #

  # @attribute [r] datastore
  #   The module-specific datastore instance.
  #
  #   @return [Msf::DataStore]
  attr_reader   :datastore

  #
  # Imports default options into the module's datastore, optionally clearing
  # all of the values currently set in the datastore.
  #
  def import_defaults(clear_datastore = true)
    # Clear the datastore if the caller asked us to
    # TODO: Is this a hack?
    self.datastore.clear if clear_datastore

    # TODO: Confirm why we need this. Is this a hack?
    # XXX: Above: We need this as every call to register_options calls `import_defaults`, which is potentially weird - instead of the new `import_options`
    # $stderr.puts "importing defaults from options"
    # self.datastore.import_defaults_from_options(self.options, imported_by: 'self')
    self.datastore.import_options(options)

    # If there are default options, import their values into the datastore
    if (module_info['DefaultOptions'])
      self.datastore.import_defaults_from_hash(module_info['DefaultOptions'], imported_by: 'self')
    end

    # Preference the defaults for the currently sets target
    import_target_defaults
  end

  #
  # Import the target's DefaultOptions hash into the datastore.
  #
  def import_target_defaults
    return unless defined?(targets) && targets && target && target.default_options

    datastore.import_defaults_from_hash(target.default_options, imported_by: 'self')
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
