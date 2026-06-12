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

    # @param [Msf::Module] m
    def initialize(m)
      super()

      @_module = m
      @deregistered_keys = []
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

  # Grab any available deregistered_keys, otherwise return a blank array
  #
  # @param [Msf::DataStore] other The other datastore to copy state from
  # @return [Msf::DataStore] the current datastore instance
    def copy_state(other)
      super
      incoming = other.respond_to?(:deregistered_keys, true) ? other.deregistered_keys : []
      incoming.each do |key|
        @deregistered_keys << key unless @deregistered_keys.any? { |k| k.casecmp?(key) }
      end

      # Strip any deregistered keys that may have been written into @user_defined
      # by the parent's copy_state (e.g. during reverse_merge! which calls
      # copy_state with a plain DataStore result that contains all merged values).
      @deregistered_keys.each do |key|
        k = find_key_case(key)
        @user_defined.delete(k)
      end

      # Need self here to return datastore instance from parent
      self
    end

    # Track deregistered keys
    #
    # @param [String] name
    # @return [nil]
    def remove_option(name)
      super
      # Resolve to the canonical cased key that the datastore actually uses so
      # that filtering later works correctly regardless of what case or alias the
      # caller passed to deregister_options.
      canonical = find_key_case(name)
      @deregistered_keys << canonical unless @deregistered_keys.any? { |k| k.casecmp?(canonical) }

      # Need nil here to return original nil value from parent
      nil
    end

    # Imports options and clears any matching keys from the deregistered list.
    # This allows a module to call deregister_options followed by register_options
    # for the same key and ensure we remove the re-registered option from the
    # tracked @deregistered_keys
    #
    # @param [Msf::OptionContainer] options
    # @param [String, nil] imported_by
    # @param [Boolean] overwrite
    def import_options(options, imported_by = nil, overwrite = true)
      options.each_option do |name, _option|
        @deregistered_keys.delete_if { |k| k.casecmp?(name) }
      end
      super
    end

    # Search for a value within the current datastore, taking into consideration any registered aliases, fallbacks, etc.
    # If a value is not present in the current datastore, the global parent store will be referenced instead
    #
    # @param [String] key The key to search for
    # @return [DataStoreSearchResult]
    def search_for(key)
      k = find_key_case(key)
      return search_result(:user_defined, @user_defined[k]) if @user_defined.key?(k)

      # If the module has not registered the key then return early as it has been deregistered
      return search_result(:not_found, nil) if should_filter_key?(key)

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

    # Override the write path so that keys which were explicitly deregistered on
    # the owning module are dropped.
    #
    # Compatible and functions as normal when:
    #   - the key has never been deregistered via deregister_options
    #   - there is no associated module (@_module is nil)
    #
    # @param [String] key
    # @param [Object] value
    def []=(key, value)
      return if should_filter_key?(key)

      super
    end

    # Override merge! so that when merging a DataStore (which writes directly to
    # @user_defined, bypassing []=), any deregistered keys are stripped out
    # afterward. This prevents a caller from injecting a deregistered option's
    # value by merging a datastore that contains it.
    #
    # When merging a plain Hash the parent's merge! already routes through []=,
    # so deregistered keys are filtered at that point and no extra work is needed.
    #
    # @param [Msf::DataStore, Hash] other
    # @return [Msf::ModuleDataStore]
    def merge!(other)
      super
      if other.is_a?(DataStore)
        @deregistered_keys.each do |key|
          k = find_key_case(key)
          @user_defined.delete(k)
          @options.delete_if { |opt_name, _| opt_name.casecmp?(k) }
          @aliases.delete_if { |_, v| v.casecmp?(k) }
        end
      end
      self
    end

    protected

    attr_reader :deregistered_keys

    # Returns true when the write should be silently dropped because the key
    # was explicitly deregistered via deregister_options.
    # Normalises the incoming key via find_key_case so that differently-cased
    # references to the same key are correctly matched against @deregistered_keys.
    #
    # @param [String] key
    # @return [Boolean]
    def should_filter_key?(key)
      canonical = find_key_case(key)
      @deregistered_keys.any? { |deregistered| deregistered.casecmp?(canonical) }
    end

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
