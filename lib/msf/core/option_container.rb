# -*- coding: binary -*-

module Msf

  autoload :Opt, 'msf/core/opt'

  autoload :OptBase, 'msf/core/opt_base'

  autoload :OptAddress, 'msf/core/opt_address'
  autoload :OptAddressLocal, 'msf/core/opt_address_local'
  autoload :OptAddressRange, 'msf/core/opt_address_range'
  autoload :OptAddressRoot, 'msf/core/opt_address_routable'
  autoload :OptBool, 'msf/core/opt_bool'
  autoload :OptEnum, 'msf/core/opt_enum'
  autoload :OptInt, 'msf/core/opt_int'
  autoload :OptIntRange, 'msf/core/opt_int_range'
  autoload :OptFloat, 'msf/core/opt_float'
  autoload :OptPath, 'msf/core/opt_path'
  autoload :OptPort, 'msf/core/opt_port'
  autoload :OptRaw, 'msf/core/opt_raw'
  autoload :OptRegexp, 'msf/core/opt_regexp'
  autoload :OptString, 'msf/core/opt_string'

  #
  # The options purpose in life is to associate named options with arbitrary
  # values at the most simplistic level. Each {Msf::Module} contains an
  # OptionContainer that is used to hold the various options that the module
  # depends on. Example of options that are stored in the OptionContainer are
  # rhost and rport for payloads or exploits that need to connect to a host
  # and port, for instance.
  #
  # The core supported option types are:
  #
  # * {OptString}  - Multi-byte character string
  # * {OptRaw}     - Multi-byte raw string
  # * {OptBool}    - Boolean true or false indication
  # * {OptPort}    - TCP/UDP service port
  # * {OptAddress} - IP address or hostname
  # * {OptPath}    - Path name on disk or an Object ID
  # * {OptInt}     - An integer value
  # * {OptFloat}   - A float value
  # * {OptEnum}    - Select from a set of valid values
  # * {OptAddressRange} - A subnet or range of addresses
  # * {OptRegexp}  - Valid Ruby regular expression
  #
  class OptionContainer < Hash

    #
    # Merges in the supplied options and converts them to a OptBase
    # as necessary.
    #
    def initialize(opts = {})
      self.groups = {}

      add_options(opts)
    end

    #
    # Return the sorted array of options.
    #
    def sorted
      self.sort
    end

    #
    # Return the value associated with the supplied name.
    #
    def [](name)
      return get(name)
    end

    #
    # Return the option associated with the supplied name.
    #
    def get(name)
      begin
        return fetch(name)
      rescue
      end
    end

    #
    # Returns whether or not the container has any options,
    # excluding advanced (and evasions).
    #
    def has_options?
      each_option { |name, opt|
        return true if (opt.advanced? == false)

      }

      return false
    end

    #
    # Returns whether or not the container has any advanced
    # options.
    #
    def has_advanced_options?
      each_option { |name, opt|
        return true if (opt.advanced? == true)
      }

      return false
    end

    #
    # Returns whether or not the container has any evasion
    # options.
    #
    def has_evasion_options?
      each_option { |name, opt|
        return true if (opt.evasion? == true)
      }

      return false
    end

    #
    # Removes an option.
    #
    # @param [String] name the option name
    def remove_option(name)
      delete(name)
    end

    #
    # Adds one or more options.
    #
    def add_options(opts, owner = nil, advanced = false, evasion = false)
      return false if (opts == nil)

      if opts.kind_of?(Array)
        add_options_array(opts, owner, advanced, evasion)
      else
        add_options_hash(opts, owner, advanced, evasion)
      end
    end

    #
    # Add options from a hash of names.
    #
    def add_options_hash(opts, owner = nil, advanced = false, evasion = false)
      opts.each_pair { |name, opt|
        add_option(opt, name, owner, advanced, evasion)
      }
    end

    #
    # Add options from an array of option instances or arrays.
    #
    def add_options_array(opts, owner = nil, advanced = false, evasion = false)
      opts.each { |opt|
        add_option(opt, nil, owner, advanced, evasion)
      }
    end

    #
    # Adds an option.
    #
    def add_option(option, name = nil, owner = nil, advanced = false, evasion = false)
      if option.kind_of?(Array)
        option = option.shift.new(name, option)
      elsif !option.kind_of?(OptBase)
        raise ArgumentError,
          "The option named #{name} did not come in a compatible format.",
          caller
      end

      option.advanced = advanced
      option.evasion  = evasion
      option.owner    = owner

      self.store(option.name, option)
    end

    #
    # Alias to add advanced options that sets the proper state flag.
    #
    def add_advanced_options(opts, owner = nil)
      return false if (opts == nil)

      add_options(opts, owner, true)
    end

    #
    # Alias to add evasion options that sets the proper state flag.
    #
    def add_evasion_options(opts, owner = nil)
      return false if (opts == nil)

      add_options(opts, owner, false, true)
    end

    #
    # Make sures that each of the options has a value of a compatible
    # format and that all the required options are set.
    def validate(datastore)
      # First mutate the datastore and normalize all valid values before validating permutations of RHOST/etc.
      each_pair do |name, option|
        if option.valid?(datastore[name], datastore: datastore) && (val = option.normalize(datastore[name])) != nil
          # This *will* result in a module that previously used the
          # global datastore to have its local datastore set, which
          # means that changing the global datastore and re-running
          # the same module will now use the newly-normalized local
          # datastore value instead. This is mostly mitigated by
          # forcing a clone through mod.replicant, but can break
          # things in corner cases.
          datastore[name] = val
        end
      end

      # Validate all permutations of rhost combinations
      if include?('RHOSTS') && !(datastore['RHOSTS'].blank? && !self['RHOSTS'].required)
        error_options = Set.new
        error_reasons = Hash.new do |hash, key|
          hash[key] = []
        end
        rhosts_walker = Msf::RhostsWalker.new(datastore['RHOSTS'], datastore)
        rhosts_count = rhosts_walker.count
        unless rhosts_walker.valid?
          errors = rhosts_walker.to_enum(:errors).to_a
          grouped = errors.group_by { |err| err.cause.nil? ? nil : (err.cause.class.const_defined?(:MESSAGE) ? err.cause.class::MESSAGE : nil) }
          error_options << 'RHOSTS'
          if grouped.any?
            grouped.each do | message, error_subset |
              invalid_values = error_subset.map(&:value).take(5)
              message = 'Unexpected values' if message.nil?
              error_reasons['RHOSTS'] << "#{message}: #{invalid_values.join(', ')}"
            end
          end
        end

        rhosts_walker.each do |datastore|
          each_pair do |name, option|
            unless option.valid?(datastore[name], datastore: datastore)
              error_options << name
              if rhosts_count > 1
                error_reasons[name] << "for rhosts value #{datastore['UNPARSED_RHOSTS']}"
              end
            end
          end
        end

        unless error_options.empty?
          raise Msf::OptionValidateError.new(error_options.to_a, reasons: error_reasons),
                "One or more options failed to validate: #{error_options.to_a.join(', ')}."
        end
      else
        error_options = []
        each_pair do |name, option|
          unless option.valid?(datastore[name], datastore: datastore)
            error_options << name
          end
        end

        unless error_options.empty?
          raise Msf::OptionValidateError.new(error_options),
                "One or more options failed to validate: #{error_options.join(', ')}."
        end
      end

      true
    end

    #
    # Creates string of options that were used from the datastore in VAR=VAL
    # format separated by commas.
    #
    def options_used_to_s(datastore)
      used = ''

      each_pair { |name, option|
        next if (datastore[name] == nil)

        used += ", " if (used.length > 0)
        used += "#{name}=#{datastore[name]}"
      }

      return used
    end

    #
    # Enumerates each option name
    #
    def each_option(&block)
      each_pair(&block)
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
    # Merges the options in this container with another option container and
    # returns the sorted results.
    #
    def merge_sort(other_container)
      result = self.dup

      other_container.each { |name, opt|
        if (result.get(name) == nil)
          result[name] = opt
        end
      }

      result.sort
    end

    # Adds an option group to the container
    #
    # @param option_group [Msf::OptionGroup]
    def add_group(option_group)
      groups[option_group.name] = option_group
    end

    # Removes an option group from the container by name
    #
    # @param group_name [String]
    def remove_group(group_name)
      groups.delete(group_name)
    end

    # @return [Hash<String, Msf::OptionGroup>]
    attr_reader :groups

    protected

    attr_writer :groups
  end

end
