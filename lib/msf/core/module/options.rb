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
      if self.datastore.is_a?(Msf::DataStore)
        self.datastore.remove_option(name)
      else
        self.datastore.delete(name)
      end
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
    import_defaults(false)
  end

  #
  # Register evasion options with a specific owning class.
  #
  def register_evasion_options(options, owner = self.class)
    self.options.add_evasion_options(options, owner)
    import_defaults(false)
  end

  #
  # Register options with a specific owning class.
  #
  def register_options(options, owner = self.class)
    self.options.add_options(options, owner)
    import_defaults(false)
  end

  # Registers a new option group, merging options by default
  #
  # @param name [String] Name for the group
  # @param description [String] Description of the group
  # @param option_names [Array<String>] List of datastore option names
  # @param required_options [Array<String>] List of required datastore option names
  # @param merge [Boolean] whether to merge or overwrite the groups option names
  def register_option_group(name:, description:, option_names: [], required_options: [], merge: true)
    existing_group = options.groups[name]
    if merge && existing_group
      existing_group.description = description
      existing_group.add_options(option_names)
    else
      option_group = Msf::OptionGroup.new(name: name,
                                          description: description,
                                          option_names: option_names,
                                          required_options: required_options)
      options.add_group(option_group)
    end
  end

  # De-registers an option group by name
  #
  # @param name [String] Name for the group
  def deregister_option_group(name:)
    options.remove_group(name)
  end
end
