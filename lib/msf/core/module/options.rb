# Register, deregister, and validate {#options}.
module Msf::Module::Options
  #
  # Attributes
  #

  # @attribute [r] options
  #   The module-specific options.
  attr_reader   :options

  #
  # Instance Methods
  #

  #
  # This method ensures that the options associated with this module all
  # have valid values according to each required option in the option
  # container.
  #
  def validate
    self.options.validate(self.datastore)
  end

  protected

  #
  # Removes the supplied options from the module's option container
  # and data store.
  #
  def deregister_options(*names)
    names.each { |name|
      real_name = self.datastore.find_key_case(name)
      self.datastore.delete(name)
      self.options.remove_option(name)
      if real_name != name
        self.options.remove_option(real_name)
      end
    }
  end

  attr_writer :options

  #
  # Register advanced options with a specific owning class.
  #
  def register_advanced_options(options, owner = self.class)
    self.options.add_advanced_options(options, owner)
    self.datastore.import_options(self.options, 'self', true)
    import_defaults(false)
  end

  #
  # Register evasion options with a specific owning class.
  #
  def register_evasion_options(options, owner = self.class)
    self.options.add_evasion_options(options, owner)
    self.datastore.import_options(self.options, 'self', true)
    import_defaults(false)
  end

  #
  # Register options with a specific owning class.
  #
  def register_options(options, owner = self.class)
    self.options.add_options(options, owner)
    self.datastore.import_options(self.options, 'self', true)
    import_defaults(false)
  end
end
