# -*- coding: binary -*-

require 'set'

module Msf

###
#
# The data store is just a bitbucket that holds keyed values.  It is used
# by various classes to hold option values and other state information.
#
###
class DataStore < Hash

  #
  # Initializes the data store's internal state.
  #
  def initialize()
    @options       = Hash.new
    @imported      = Hash.new
    @imported_by   = Hash.new
    @original_keys = Set.new
  end

  #
  # Clears the imported flag for the supplied key since it's being set
  # directly.
  #
  def []=(k, v)
    add_key(k)
    k = k.downcase
    @imported[k] = false
    @imported_by[k] = nil

    opt = @options[k]
    unless opt.nil?
      if opt.validate_on_assignment?
        unless opt.valid?(v, check_empty: false)
          raise OptionValidateError.new(["Value '#{v}' is not valid for option '#{k}'"])
        end
        v = opt.normalize(v)
      end
    end

    super(k,v)
  end

  #
  # Case-insensitive wrapper around hash lookup
  #
  def [](k)
    super(k.downcase)
  end

  #
  # Case-insensitive wrapper around store
  #
  def store(k,v)
    add_key(k)
    super(k.downcase, v)
  end

  #
  # Case-insensitive wrapper around delete
  #
  def delete(k)
    super(k.downcase)
  end

  # Override Hash's to_h method so we can include the original case of each key
  # (failing to do this breaks a number of places in framework and pro that use
  # serialized datastores)
  def to_h
    @original_keys.reduce({}) do |acc, key|
      acc[key] = self[key]
      acc
    end
  end

  #
  # This method is a helper method that imports the default value for
  # all of the supplied options
  #
  def import_options(options, imported_by = nil, overwrite = false)
    options.each_option do |name, opt|
      if self[name].nil? || overwrite
        import_option(name, opt.default, true, imported_by, opt)
      end
    end
  end

  #
  # Imports option values from a whitespace separated string in
  # VAR=VAL format.
  #
  def import_options_from_s(option_str, delim = nil)
    hash = {}

    # Figure out the delimeter, default to space.
    if (delim.nil?)
      delim = /\s/

      if (option_str.split('=').length <= 2 or option_str.index(',') != nil)
        delim = ','
      end
    end

    # Split on the delimeter
    option_str.split(delim).each { |opt|
      var, val = opt.split('=')

      next if (var =~ /^\s+$/)


      # Invalid parse?  Raise an exception and let those bastards know.
      if (var == nil or val == nil)
        var = "unknown" if (!var)

        raise Rex::ArgumentParseError, "Invalid option specified: #{var}",
          caller
      end

      # Remove trailing whitespaces from the value
      val.gsub!(/\s+$/, '')

      # Store the value
      hash[var] = val
    }

    import_options_from_hash(hash)
  end

  #
  # Imports options from a hash and stores them in the datastore.
  #
  def import_options_from_hash(option_hash, imported = true, imported_by = nil)
    option_hash.each_pair do |key, val|
      import_option(key, val, imported, imported_by)
    end
  end

  def import_option(key, val, imported=true, imported_by=nil, option=nil)
    self.store(key, val)

    key = key.downcase
    @options[key]     = option
    @imported[key]    = imported
    @imported_by[key] = imported_by
  end

  #
  # Serializes the options in the datastore to a string.
  #
  def to_s(delim = ' ')
    @original_keys.reduce('') do |acc, key|
      acc << "#{key}=#{self[key]}#{delim}"
    end
  end

  #
  # Persists the contents of the data store to a file
  #
  def to_file(path, name = 'global')
    ini = Rex::Parser::Ini.new(path)

    ini.add_group(name)

    # Save all user-defined options to the file.
    user_defined.each_pair { |k, v|
      ini[name][k] = v
    }

    ini.to_file(path)
  end

  #
  # Imports datastore values from the specified file path using the supplied
  # name
  #
  def from_file(path, name = 'global')
    begin
      ini = Rex::Parser::Ini.from_file(path)
    rescue
      return
    end

    if (ini.group?(name))
      import_options_from_hash(ini[name], false)
    end
  end

  #
  # Returns a hash of user-defined datastore values.  The returned hash does
  # not include default option values.
  #
  def user_defined
    @original_keys.reduce({}) do |acc, k|
      acc[k] = self[k] unless @imported[k.downcase]
      acc
    end
  end

  #
  # Remove all imported options from the data store.
  #
  def clear_non_user_defined
    @imported.delete_if { |k, v|
      if (v and @imported_by[k] != 'self')
        self.delete(k)
        @imported_by.delete(k)
      end

      v
    }
  end

  #
  # Completely clear all values in the hash
  #
  def clear
    @options.clear
    @imported.clear
    @imported_by.clear
    @original_keys.clear
    super
  end

  # Yield the original-cased key
  def each(&block)
    @original_keys.each do |key|
      block.call(key, self[key])
    end
  end

  protected

  # Keep track of the original, case-sensitive key
  def add_key(k)
    @original_keys.add(k) unless include? k.downcase
  end
end

###
#
# DataStore wrapper for modules that will attempt to back values against the
# framework's datastore if they aren't found in the module's datastore.  This
# is done to simulate global data store values.
#
###
class ModuleDataStore < DataStore

  def initialize(m)
    super()

    @_module = m
  end

  #
  # Fetch the key from the local hash first, or from the framework datastore
  # if we can't directly find it
  #
  def fetch(key)
    key = key.downcase
    val = nil
    val = super if(@imported_by[key] != 'self')
    if (val.nil? and @_module and @_module.framework)
      val = @_module.framework.datastore[key]
    end
    val = super if val.nil?
    val
  end

  #
  # Same as fetch
  #
  def [](key)
    key = key.downcase
    val = nil
    val = super if(@imported_by[key] != 'self')
    if (val.nil? and @_module and @_module.framework)
      val = @_module.framework.datastore[key]
    end
    val = super if val.nil?
    val
  end

  #
  # Was this entry actually set or just using its default
  #
  def default?(key)
    (@imported_by[key] == 'self')
  end

  #
  # Return a deep copy of this datastore.
  #
  def copy
    clone = self.class.new(@_module)
    self.keys.each do |k|
      clone.import_option(k, self[k].kind_of?(String) ? self[k].dup : self[k], @imported[k.downcase], @imported_by[k.downcase])
    end
    clone
  end
end

end
