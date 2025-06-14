# -*- coding: binary -*-

module Msf
module Simple

###
#
# Simple module wrapper that provides some common methods for dealing with
# modules, such as importing options and other such things.
#
###
module Module

  #
  # Imports extra options from the supplied hash either as a string or as a
  # hash.
  #
  def _import_extra_options(opts)
    # If options were supplied, import them into the payload's
    # datastore
    if (value = opts['Options'])
      if value.is_a?(String)
        self.datastore.import_options_from_s(value)
      else
        self.datastore.import_options_from_hash(value)
      end
    elsif (value = opts['OptionStr'])
      self.datastore.import_options_from_s(value)
    end
  end

  def inspect
    "#<Module:#{self.fullname} datastore=[#{self.datastore.inspect}]>"
  end

  #
  # Initializes the simplified interface.
  #
  def init_simplified(load_saved_config=true)
    load_config if load_saved_config
  end

  #
  # Populates the datastore from the config file.
  #
  def load_config
    self.datastore.from_file(Msf::Config.config_file, self.refname)
  end

  #
  # Saves the module's datastore to the file.
  #
  def save_config
    self.datastore.to_file(Msf::Config.config_file, self.refname)
  end

end

end
end
