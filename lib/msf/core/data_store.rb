# -*- coding: binary -*-
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
    @options     = Hash.new
    @aliases     = Hash.new
    @imported    = Hash.new
    @imported_by = Hash.new
  end

  attr_accessor :options
  attr_accessor :aliases
  attr_accessor :imported
  attr_accessor :imported_by

  #
  # Clears the imported flag for the supplied key since it's being set
  # directly.
  #
  def []=(k, v)
    k = find_key_case(k)
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
    super(find_key_case(k))
  end

  #
  # Case-insensitive wrapper around store
  #
  def store(k,v)
    super(find_key_case(k), v)
  end

  #
  # Case-insensitive wrapper around delete
  #
  def delete(k)
    @aliases.delete_if { |_, v| v.casecmp(k) == 0 }
    super(find_key_case(k))
  end


  #
  # Updates a value in the datastore with the specified name, k, to the
  # specified value, v.  This update does not alter the imported status of
  # the value.
  #
  def update_value(k, v)
    self.store(k, v)
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
    option_hash.each_pair { |key, val|
      import_option(key, val, imported, imported_by)
    }
  end

  def import_option(key, val, imported = true, imported_by = nil, option = nil)
    self.store(key, val)

    if option
      option.aliases.each do |a|
        @aliases[a.downcase] = key.downcase
      end
    end
    @options[key] = option
    @imported[key] = imported
    @imported_by[key] = imported_by
  end

  #
  # Serializes the options in the datastore to a string.
  #
  def to_s(delim = ' ')
    str = ''

    keys.sort.each { |key|
      str << "#{key}=#{self[key]}" + ((str.length) ? delim : '')
    }

    return str
  end

  def to_h
    datastore_hash = {}
    self.keys.each do |k|
      datastore_hash[k.to_s] = self[k].to_s
    end
    datastore_hash
  end

  # Hack on a hack for the external modules
  def to_nested_values
    datastore_hash = {}

    array_nester = ->(arr) do
      if arr.first.is_a? Array
        arr.map &array_nester
      else
        arr.map &:to_s
      end
    end

    self.keys.each do |k|
      # TODO arbitrary depth
      if self[k].is_a? Array
        datastore_hash[k.to_s] = array_nester.call(self[k])
      else
        datastore_hash[k.to_s] = self[k].to_s
      end
    end
    datastore_hash
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
  # Return a deep copy of this datastore.
  #
  def copy
    ds = self.class.new
    self.keys.each do |k|
      ds.import_option(k, self[k].kind_of?(String) ? self[k].dup : self[k], @imported[k], @imported_by[k])
    end
    ds.aliases = self.aliases.dup
    ds
  end

  #
  # Override merge! so that we merge the aliases and imported hashes
  #
  def merge!(other)
    if other.is_a? DataStore
      self.aliases.merge!(other.aliases)
      self.imported.merge!(other.imported)
      self.imported_by.merge!(other.imported_by)
    end
    # call super last so that we return a reference to ourselves
    super
  end

  #
  # Override merge to ensure we merge the aliases and imported hashes
  #
  def merge(other)
    ds = self.copy
    ds.merge!(other)
  end

  #
  # Returns a hash of user-defined datastore values.  The returned hash does
  # not include default option values.
  #
  def user_defined
    reject { |k, v|
      @imported[k] == true
    }
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
    self.keys.each {|k| self.delete(k) }
    self
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

  #
  # Case-insensitive key lookup
  #
  def find_key_case(k)

    # Scan each alias looking for a key
    search_k = k.downcase
    if self.aliases.has_key?(search_k)
      search_k = self.aliases[search_k]
    end

    # Scan each key looking for a match
    self.each_key do |rk|
      if rk.casecmp(search_k) == 0
        return rk
      end
    end

    # Fall through to the non-existent value
    return k
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
    key = find_key_case(key)
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
    key = find_key_case(key)
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
    ds = self.class.new(@_module)
    self.keys.each do |k|
      ds.import_option(k, self[k].kind_of?(String) ? self[k].dup : self[k], @imported[k], @imported_by[k])
    end
    ds.aliases = self.aliases.dup
    ds
  end
end

end

