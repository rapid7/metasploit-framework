# -*- coding: binary -*-
module Msf

  ###
  #
  # DataStore wrapper for modules that will attempt to back values against the
  # framework's datastore if they aren't found in the module's datastore.  This
  # is done to simulate global data store values.
  #
  ###
  class ModuleDataStoreWithFallbacks < DataStoreWithFallbacks

    # @param [Msf::Module] m
    def initialize(m)
      super()

      @_module = m
    end

    #
    # Return a copy of this datastore. Only string values will be duplicated, other values
    # will share the same reference
    # @return [Msf::DataStore] a new datastore instance
    def copy
      new_instance = self.class.new(@_module)
      new_instance.copy_state(self)
      new_instance
    end

    # Search for a value within the current datastore, taking into consideration any registered aliases, fallbacks, etc.
    # If a value is not present in the current datastore, the global parent store will be referenced instead
    #
    # @param [String] key The key to search for
    # @return [DataStoreSearchResult]
    def search_for(key)
      k = find_key_case(key)
      return search_result(:user_defined, @user_defined[k]) if @user_defined.key?(k)

      # Preference globally set values over a module's option default
      framework_datastore_search = search_framework_datastore(key)
      return framework_datastore_search if framework_datastore_search.found? && !framework_datastore_search.default?

      option = @options.fetch(k) { @options.find { |option_name, _option| option_name.casecmp?(k) }&.last }
      if option
        # If the key isn't present - check any additional fallbacks that have been registered with the option.
        # i.e. handling the scenario of SMBUser not being explicitly set, but the option has registered a more
        # generic 'Username' fallback
        option.fallbacks.each do |fallback|
          fallback_search = search_for(fallback)
          if fallback_search.found?
            return search_result(:option_fallback, fallback_search.value, fallback_key: fallback)
          end
        end
      end

      # Checking for imported default values, ignoring case again TODO: add Alias test for this
      imported_default_match = @defaults.find { |default_key, _default_value| default_key.casecmp?(k) }
      return search_result(:imported_default, imported_default_match.last) if imported_default_match
      return search_result(:option_default, option.default) if option

      search_framework_datastore(k)
    end

    protected

    # Search the framework datastore
    #
    # @param [String] key The key to search for
    # @return [DataStoreSearchResult]
    def search_framework_datastore(key)
      return search_result(:not_found, nil) if @_module&.framework.nil?

      @_module.framework.datastore.search_for(key)
    end

    def search_result(result, value, fallback_key: nil)
      DataStoreSearchResult.new(result, value, namespace: :module_data_store, fallback_key: fallback_key)
    end
  end
end
