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
    @imported    = Hash.new
    @imported_by = Hash.new
  end

  #
  # Clears the imported flag for the supplied key since it's being set
  # directly.
  #
  def []=(k, v)
    k = find_key_case(k)
    @imported[k] = false
    @imported_by[k] = nil

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
    options.each_option { |name, opt|
      # If there's already a value defined for this option, then skip it
      # and don't import it.
      next if self.has_key?(name) and overwrite == false

      # If the option has a default value, import it, but only if the
      # datastore doesn't already have a value set for it.
      if ((opt.default != nil) and (overwrite or self[name] == nil))
        import_option(name, opt.default.to_s, true, imported_by)
      end
    }
  end

  #
  # Imports option values from a whitespace separated string in
  # VAR=VAL format.
  #
  def import_options_from_s(option_str, delim = nil)
    hash = {}

    # Figure out the deliminter, default to space.
    if (delim.nil?)
      delim = /\s/

      if (option_str.split('=').length <= 2 or option_str.index(',') != nil)
        delim = ','
      end
    end

    # Split on the deliminter
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
      import_option(key, val.to_s, imported, imported_by)
    }
  end

  def import_option(key, val, imported=true, imported_by=nil)
    self.store(key, val)

    @imported[key]    = imported
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

protected

  #
  # Case-insensitive key lookup
  #
  def find_key_case(k)

    # Scan each key looking for a match
    self.each_key do |rk|
      if (rk.downcase == k.downcase)
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
    clone = self.class.new(@_module)
    self.keys.each do |k|
      clone.import_option(k, self[k].kind_of?(String) ? self[k].dup : self[k], @imported[k], @imported_by[k])
    end
    clone
  end
end

end

