# -*- coding: binary -*-
module Msf

###
#
# The data store is just a bitbucket that holds keyed values. It is used
# by various classes to hold option values and other state information.
#
###
class DataStoreWithFallbacks

  # The global framework datastore doesn't currently import options
  # For now, store an ad-hoc list of keys that the shell handles
  #
  # This list could be removed if framework's bootup sequence registers
  # these as datastore options
  GLOBAL_KEYS = %w[
    ConsoleLogging
    LogLevel
    MinimumRank
    SessionLogging
    TimestampOutput
    Prompt
    PromptChar
    PromptTimeFormat
    MeterpreterPrompt
    SessionTlvLogging
  ]

  #
  # Initializes the data store's internal state.
  #
  def initialize
    @options     = Hash.new
    @aliases     = Hash.new

    # default values which will be referenced when not defined by the user
    @defaults = Hash.new

    # values explicitly defined, which take precedence over default values
    @user_defined = Hash.new
  end

  # @return [Hash{String => Msf::OptBase}] The options associated with this datastore. Used for validating values/defaults/etc
  attr_accessor :options

  #
  # Returns a hash of user-defined datastore values. The returned hash does
  # not include default option values.
  #
  # @return [Hash<String, Object>] values explicitly defined on the data store which will override any default datastore values
  attr_accessor :user_defined

  #
  # Was this entry actually set or just using its default
  #
  # @return [TrueClass, FalseClass]
  def default?(key)
    search_for(key).default?
  end

  #
  # Clears the imported flag for the supplied key since it's being set
  # directly.
  #
  def []=(k, v)
    k = find_key_case(k)

    opt = @options[k]
    unless opt.nil?
      if opt.validate_on_assignment?
        unless opt.valid?(v, check_empty: false)
          raise Msf::OptionValidateError.new(["Value '#{v}' is not valid for option '#{k}'"])
        end
        v = opt.normalize(v)
      end
    end

    @user_defined[k] = v
  end

  #
  # Case-insensitive wrapper around hash lookup
  #
  def [](k)
    search_result = search_for(k)

    search_result.value
  end

  #
  # Case-insensitive wrapper around store; Skips option validation entirely
  #
  def store(k,v)
    @user_defined[find_key_case(k)] = v
  end

  #
  # Updates a value in the datastore with the specified name, k, to the
  # specified value, v. Skips option validation entirely.
  #
  def update_value(k, v)
    store(k, v)
  end

  #
  # unset the current key from the datastore
  # @param [String] key The key to search for
  def unset(key)
    k = find_key_case(key)
    search_result = search_for(k)
    @user_defined.delete(k)

    search_result.value
  end

  # @deprecated use #{unset} instead, or set the value explicitly to nil
  # @param [String] key The key to search for
  def delete(key)
    unset(key)
  end

  #
  # Removes an option and any associated value
  #
  # @param [String] name the option name
  # @return [nil]
  def remove_option(name)
    k = find_key_case(name)
    @user_defined.delete(k)
    @aliases.delete_if { |_, v| v.casecmp?(k) }
    @options.delete_if { |option_name, _v| option_name.casecmp?(k) || option_name.casecmp?(name) }

    nil
  end

  #
  # This method is a helper method that imports the default value for
  # all of the supplied options
  #
  def import_options(options, imported_by = nil, overwrite = true)
    options.each_option do |name, option|
      if self.options[name].nil? || overwrite
        key = name
        option.aliases.each do |a|
          @aliases[a.downcase] = key.downcase
        end
        @options[key] = option
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
      var, val = opt.split('=', 2)

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

    merge!(hash)
  end

  #
  # Imports values from a hash and stores them in the datastore.
  #
  # @deprecated use {#merge!} instead
  # @return [nil]
  def import_options_from_hash(option_hash, imported = true, imported_by = nil)
    merge!(option_hash)
  end

  # Update defaults from a hash. These merged values are not validated by default.
  #
  # @param [Hash<String, Object>] hash The default values that should be used by the datastore
  # @param [Object] imported_by Who imported the defaults, not currently used
  # @return [nil]
  def import_defaults_from_hash(hash, imported_by:)
    @defaults.merge!(hash)
  end

  # TODO: Doesn't normalize data in the same vein as:
  # https://github.com/rapid7/metasploit-framework/pull/6644
  # @deprecated Use {#import_options}
  def import_option(key, val, imported = true, imported_by = nil, option = nil)
    store(key, val)

    if option
      option.aliases.each do |a|
        @aliases[a.downcase] = key.downcase
      end
    end
    @options[key] = option
  end

  # @return [Array<String>] The array of user defined datastore values, and registered option names
  def keys
    (@user_defined.keys + @options.keys).uniq(&:downcase)
  end

  # @return [Integer] The length of the registered keys
  def length
    keys.length
  end

  alias count length
  alias size length

  # @param [String] key
  # @return [TrueClass, FalseClass] True if the key is present in the user defined values, or within registered options. False otherwise.
  def key?(key)
    matching_key = find_key_case(key)
    keys.include?(matching_key)
  end

  alias has_key? key?
  alias include? key?
  alias member? key?

  #
  # Serializes the options in the datastore to a string.
  #
  def to_s(delim = ' ')
    str = ''

    keys.sort.each { |key|
      str << "#{key}=#{self[key]}" + ((str.length) ? delim : '')
    }

    str
  end

  # Override Hash's to_h method so we can include the original case of each key
  # (failing to do this breaks a number of places in framework and pro that use
  # serialized datastores)
  def to_h
    datastore_hash = {}
    self.keys.each do |k|
      datastore_hash[k.to_s] = self[k].to_s
    end
    datastore_hash
  end

  # Hack on a hack for the external modules
  def to_external_message_h
    datastore_hash = {}

    array_nester = ->(arr) do
      if arr.first.is_a? Array
        arr.map &array_nester
      else
        arr.map { |item| item.to_s.dup.force_encoding('UTF-8') }
      end
    end

    self.keys.each do |k|
      # TODO arbitrary depth
      if self[k].is_a? Array
        datastore_hash[k.to_s.dup.force_encoding('UTF-8')] = array_nester.call(self[k])
      else
        datastore_hash[k.to_s.dup.force_encoding('UTF-8')] = self[k].to_s.dup.force_encoding('UTF-8')
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
    @user_defined.each_pair { |k, v|
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

    if ini.group?(name)
      merge!(ini[name])
    end
  end

  #
  # Return a copy of this datastore. Only string values will be duplicated, other values
  # will share the same reference
  # @return [Msf::DataStore] a new datastore instance
  def copy
    new_instance = self.class.new
    new_instance.copy_state(self)
    new_instance
  end

  #
  # Merge the other object into the current datastore's aliases and imported hashes
  #
  # @param [Msf::Datastore, Hash] other
  def merge!(other)
    if other.is_a?(DataStoreWithFallbacks)
      self.aliases.merge!(other.aliases)
      self.options.merge!(other.options)
      self.defaults.merge!(other.defaults)
      other.user_defined.each do |k, v|
        @user_defined[find_key_case(k)] = v
      end
    else
      other.each do |k, v|
        self.store(k, v)
      end
    end

    self
  end

  alias update merge!

  #
  # Reverse Merge the other object into the current datastore's aliases and imported hashes
  # Equivalent to ActiveSupport's reverse_merge! functionality.
  #
  # @param [Msf::Datastore] other
  def reverse_merge!(other)
    raise ArgumentError, "invalid error type #{other.class}, expected ::Msf::DataStore" unless other.is_a?(Msf::DataStoreWithFallbacks)

    copy_state(other.merge(self))
  end

  #
  # Override merge to ensure we merge the aliases and imported hashes
  #
  # @param [Msf::Datastore,Hash] other
  def merge(other)
    ds = self.copy
    ds.merge!(other)
  end

  #
  # Completely clear all values in the data store
  #
  def clear
    self.options.clear
    self.aliases.clear
    self.defaults.clear
    self.user_defined.clear

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

  alias each_pair each

  def each_key(&block)
    self.keys.each(&block)
  end

  #
  # Case-insensitive key lookup
  #
  # @return [String]
  def find_key_case(k)
    # Scan each alias looking for a key
    search_k = k.downcase
    if self.aliases.has_key?(search_k)
      search_k = self.aliases[search_k]
    end

    # Check to see if we have an exact key match - otherwise we'll have to search manually to check case sensitivity
    if @user_defined.key?(search_k) || options.key?(search_k)
      return search_k
    end

    # Scan each key looking for a match
    each_key do |rk|
      if rk.casecmp(search_k) == 0
        return rk
      end
    end

    # Fall through to the non-existent value
    k
  end

  # Search for a value within the current datastore, taking into consideration any registered aliases, fallbacks, etc.
  #
  # @param [String] key The key to search for
  # @return [DataStoreSearchResult]
  def search_for(key)
    k = find_key_case(key)
    return search_result(:user_defined, @user_defined[k]) if @user_defined.key?(k)

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

    # Checking for imported default values, ignoring case again
    imported_default_match = @defaults.find { |default_key, _default_value| default_key.casecmp?(k) }
    return search_result(:imported_default, imported_default_match.last) if imported_default_match
    return search_result(:option_default, option.default) if option

    search_result(:not_found, nil)
  end

  protected

  # These defaults will be used if the user has not explicitly defined a specific datastore value.
  # These will be checked as a priority to any options that also provide defaults.
  #
  # @return [Hash{String => Msf::OptBase}] The hash of default values
  attr_accessor :defaults

  # @return [Hash{String => String}] The key is the old option name, the value is the new option name
  attr_accessor :aliases

  #
  # Copy the state from the other Msf::DataStore. The state will be coped in a shallow fashion, other than
  # imported and user_defined strings.
  #
  # @param [Msf::DataStore] other The other datastore to copy state from
  # @return [Msf::DataStore] the current datastore instance
  def copy_state(other)
    self.options = other.options.dup
    self.aliases = other.aliases.dup
    self.defaults = other.defaults.transform_values { |value| value.kind_of?(String) ? value.dup : value }
    self.user_defined = other.user_defined.transform_values { |value| value.kind_of?(String) ? value.dup : value }

    self
  end

  # Raised when the specified key is not found
  # @param [string] key
  def key_error_for(key)
    ::KeyError.new "key not found: #{key.inspect}"
  end

  #
  # Simple dataclass for storing the result of a datastore search
  #
  class DataStoreSearchResult
    # @return [String, nil] the key associated with the fallback value
    attr_reader :fallback_key

    # @return [object, nil] The value if found
    attr_reader :value

    def initialize(result, value, namespace: nil, fallback_key: nil)
      @namespace = namespace
      @result = result
      @value = value
      @fallback_key = fallback_key
    end

    def default?
      result == :imported_default || result == :option_default || !found?
    end

    def found?
      result != :not_found
    end

    def fallback?
      result == :option_fallback
    end

    def global?
      namespace == :global_data_store && found?
    end

  protected

    # @return [Symbol] namespace Where the search result was found, i.e. a module datastore or global datastore
    attr_reader :namespace

    # @return [Symbol] result is one of `user_defined`, `not_found`, `option_fallback`, `option_default`, `imported_default`
    attr_reader :result
  end

  def search_result(result, value, fallback_key: nil)
    DataStoreSearchResult.new(result, value, namespace: :global_data_store, fallback_key: fallback_key)
  end
end

end
