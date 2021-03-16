# -*- coding: binary -*-
module Msf

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
