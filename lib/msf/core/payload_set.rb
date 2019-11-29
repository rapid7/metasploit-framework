# -*- coding: binary -*-
require 'msf/core'
require 'msf/core/module_manager'

module Msf

###
#
# This class is a special case of the generic module set class because
# payloads are generated in terms of combinations between various
# components, such as a stager and a stage.  As such, the payload set
# needs to be built on the fly and cannot be simply matched one-to-one
# with a payload module.  Yeah, the term module is kind of overloaded
# here, but eat it!
#
###
class PayloadSet < ModuleSet

  #
  # Creates an instance of a payload set which is just a specialized module
  # set class that has custom handling for payloads.
  #
  def initialize
    super(Msf::MODULE_PAYLOAD)

    # A hash of each of the payload types that holds an array
    # for all of the associated modules
    self.payload_type_modules = {}

    # Initialize the hash entry for each type to an empty list
    [
      Payload::Type::Single,
      Payload::Type::Stager,
      Payload::Type::Stage
    ].each { |type|
      self.payload_type_modules[type] = {}
    }

    # Initialize hashes for each of the stages and singles.  Stagers
    # never exist independent.  The stages hash will have entries that
    # point to another hash that point to the per-stager implementation
    # payload class.  For instance:
    #
    # ['windows/shell']['reverse_tcp']
    #
    # Singles will simply point to the single payload class.
    self.stages  = {}
    self.singles = {}

    # Hash that caches the sizes of payloads
    self.sizes   = {}

    # Single instance cache of modules for use with doing quick referencing
    # of attributes that would require an instance.
    self._instances = {}

    # Initializes an empty blob cache
    @blob_cache = {}
  end

  #
  # Performs custom filtering during each_module enumeration.  This allows us
  # to filter out certain stagers as necessary.
  #
  def each_module_filter(opts, name, mod)
    return false
  end

  #
  # This method builds the hash of alias names based on all the permutations
  # of singles, stagers, and stages.
  #
  def recalculate
    old_keys = self.keys
    new_keys = []

    # Recalculate single payloads
    _singles.each_pair { |name, op|
      mod, handler = op

      # if the payload has a dependency, check
      # if it is supported on the system
      payload_dependencies = op[4].dependencies
      unless payload_dependencies.empty?
        supported = payload_dependencies.all?(&:available?)
        elog("Dependency for #{name} is not supported") unless supported
        next unless supported
      end

      # Build the payload dupe using the determined handler
      # and module
      p = build_payload(handler, mod)

      # Add it to the set
      add_single(p, name, op[5])
      new_keys.push name

      # Cache the payload's size
      begin
        sizes[name] = p.cached_size || p.new.size
      # Don't cache generic payload sizes.
      rescue NoCompatiblePayloadError
      rescue StandardError => e
        elog("Unable to build payload #{name} due to #{e}.")
      end
    }

    # Recalculate staged payloads
    _stagers.each_pair { |stager_name, op|
      stager_mod, handler, stager_platform, stager_arch, stager_inst = op

      # Pass if the stager has a dependency
      # and doesn't have the dependency installed
      stager_dependencies = stager_inst.dependencies
      unless stager_dependencies.empty?
        supported = stager_dependencies.all?(&:available?)
        elog("Dependency for #{stager_name} is not supported") unless supported
        next unless supported
      end

      # Walk the array of stages
      _stages.each_pair { |stage_name, ip|
        stage_mod, _, stage_platform, stage_arch, stage_inst = ip

        #
        # if the stager or stage has a dependency, check
        # if they are compatible
        #
        unless stager_dependencies.empty? && stage_inst.dependencies.empty?
          next unless stager_dependencies == stage_inst.dependencies
        end

        # No intersection between platforms on the payloads?
        if ((stager_platform) and
            (stage_platform) and
            (stager_platform & stage_platform).empty?)
          dlog("Stager #{stager_name} and stage #{stage_name} have incompatible platforms: #{stager_platform.names} - #{stage_platform.names}", 'core', LEV_2)
          next
        end

        # No intersection between architectures on the payloads?
        if ((stager_arch) and
            (stage_arch) and
            ((stager_arch & stage_arch).empty?))
          dlog("Stager #{stager_name} and stage #{stage_name} have incompatible architectures: #{stager_arch.join} - #{stage_arch.join}", 'core', LEV_2)
          next
        end

        # If the stage has a convention, make sure it's compatible with
        # the stager's
        if ((stage_inst) and (stage_inst.compatible?(stager_inst) == false))
          dlog("Stager #{stager_name} and stage #{stage_name} are incompatible.", 'core', LEV_2)
          next
        end

        # Build the payload dupe using the handler, stager,
        # and stage
        p = build_payload(handler, stager_mod, stage_mod)

        # If the stager has an alias for the handler type (such as is the
        # case for ordinal based stagers), use it in preference of the
        # handler's actual type.
        if (stager_mod.respond_to?('handler_type_alias') == true)
          handler_type = stager_mod.handler_type_alias
        else
          handler_type = handler.handler_type
        end

        # Associate the name as a combination of the stager and stage
        combined  = stage_name

        # If a valid handler exists for this stager, then combine it
        combined += '/' + handler_type

        # Sets the modules derived name
        p.refname = combined

        # Add the stage
        add_stage(p, combined, stage_name, handler_type, {
          'files' => op[5]['files'] + ip[5]['files'],
          'paths' => op[5]['paths'] + ip[5]['paths'],
          'type'  => op[5]['type']})
        new_keys.push combined

        # Cache the payload's size
        sizes[combined] = p.cached_size || p.new.size
      }
    }

    # Blow away anything that was cached but didn't exist during the
    # recalculation
    self.delete_if do |k, v|
      next if v == SymbolicModule
      !!(old_keys.include?(k) and not new_keys.include?(k))
    end

    flush_blob_cache
  end

  # This method is called when a new payload module class is loaded up.  For
  # the payload set we simply create an instance of the class and do some
  # magic to figure out if it's a single, stager, or stage.  Depending on
  # which it is, we add it to the appropriate list.
  #
  # @param payload_module [::Module] The module name.
  # @param reference_name [String] The module reference name.
  # @param modinfo [Hash{String => Array}] additional information about the
  #   module.
  # @option modinfo [Array<String>] 'files' List of paths to the ruby source
  #   files where +class_or_module+ is defined.
  # @option modinfo [Array<String>] 'paths' List of module reference names.
  # @option modinfo [String] 'type' The module type, should match positional
  #   +type+ argument.
  # @return [void]
  def add_module(payload_module, reference_name, modinfo={})

    if (md = reference_name.match(/^(singles|stagers|stages)#{File::SEPARATOR}(.*)$/))
      ptype = md[1]
      reference_name  = md[2]
    end

    # Duplicate the Payload base class and extend it with the module
    # class that is passed in.  This allows us to inspect the actual
    # module to see what type it is, and to grab other information for
    # our own evil purposes.
    instance = build_payload(payload_module).new

    # Create an array of information about this payload module
    pinfo =
      [
        payload_module,
        instance.handler_klass,
        instance.platform,
        instance.arch,
        instance,
        modinfo
      ]

    # Use the module's preferred alias if it has one
    reference_name = instance.alias if (instance.alias)

    # Store the module and alias name for this payload.  We
    # also convey other information about the module, such as
    # the platforms and architectures it supports
    payload_type_modules[instance.payload_type][reference_name] = pinfo
  end

  #
  # Looks for a payload that matches the specified requirements and
  # returns an instance of that payload.
  #
  def find_payload(platform, arch, handler, session, payload_type)
    # Pre-filter based on platform and architecture.
    each_module(
      'Platform' => platform,
      'Arch'     => arch) { |name, mod|

      p = mod.new

      # We can't substitute one generic with another one.
      next if (p.kind_of?(Msf::Payload::Generic))

      # Check to see if the handler classes match.
      next if (handler and not p.handler_klass.ancestors.include?(handler))

      # Check to see if the session classes match.
      next if (session and p.session and not p.session.ancestors.include?(session))

      # Check for matching payload types
      next if (payload_type and p.payload_type != payload_type)

      return p
    }

    return nil
  end

  #
  # Looks for a payload from a given set that matches the specified requirements and
  # returns an instance of that payload.
  #
  def find_payload_from_set(set, platform, arch, handler, session, payload_type)
    set.each do |name, mod|
      p = mod.new

      # We can't substitute one generic with another one.
      next if (p.kind_of?(Msf::Payload::Generic))

      # Check to see if the handler classes match.
      next if (handler and p.handler_klass != handler)

      # Check to see if the session classes match.
      next if (session and p.session != session)

      # Check for matching payload types
      next if (payload_type and p.payload_type != payload_type)

      return p
    end
    return nil
  end

  #
  # This method adds a single payload to the set and adds it to the singles
  # hash.
  #
  def add_single(p, name, modinfo)
    p.framework = framework
    p.refname = name
    p.file_path = modinfo['files'][0]

    # Associate this class with the single payload's name
    self[name] = p

    # Add the singles hash
    singles[name] = p

    dlog("Built single payload #{name}.", 'core', LEV_2)
  end

  #
  # This method adds a stage payload to the set and adds it to the stages
  # hash using the supplied handler type.
  #
  def add_stage(p, full_name, stage_name, handler_type, modinfo)
    p.framework = framework
    p.refname = full_name
    p.file_path = modinfo['files'][0]

    # Associate this stage's full name with the payload class in the set
    self[full_name] = p

    # Create the hash entry for this stage and then create
    # the associated entry for the handler type
    stages[stage_name] = {} if (!stages[stage_name])

    # Add it to this stage's stager hash
    stages[stage_name][handler_type] = p

    dlog("Built staged payload #{full_name}.", 'core', LEV_2)
  end

  #
  # Returns a single read-only instance of the supplied payload name such
  # that specific attributes, like compatibility, can be evaluated.  The
  # payload instance returned should NOT be used for anything other than
  # reading.
  #
  def instance(name)
    if (self._instances[name] == nil)
      self._instances[name] = create(name)
    end

    self._instances[name]
  end

  #
  # Returns the hash of payload stagers that have been loaded.
  #
  def stagers
    _stagers
  end

  #
  # When a payload module is reloaded, the blob cache entry associated with
  # it must be removed (if one exists)
  #
  def on_module_reload(mod)
    @blob_cache.each_key do |key|
      if key.start_with? mod.refname
        @blob_cache.delete(key)
      end
    end
  end

  #
  # Adds a blob to the blob cache so that the payload does not have to be
  # recompiled in the future
  #
  def add_blob_cache(key, blob, offsets)
    @blob_cache[key] = [ blob, offsets ]
  end

  #
  # Checks to see if a payload has a blob cache entry.  If it does, the blob
  # is returned to the caller.
  #
  def check_blob_cache(key)
    @blob_cache[key]
  end

  #
  # Flushes all entries from the blob cache
  #
  def flush_blob_cache
    @blob_cache.clear
  end

  #
  # The list of stages that have been loaded.
  #
  attr_reader :stages
  #
  # The list of singles that have been loaded.
  #
  attr_reader :singles
  #
  # The sizes of all the built payloads thus far.
  #
  attr_reader :sizes

protected

  #
  # Return the hash of single payloads
  #
  def _singles
    return payload_type_modules[Payload::Type::Single] || {}
  end

  #
  # Return the hash of stager payloads
  #
  def _stagers
    return payload_type_modules[Payload::Type::Stager] || {}
  end

  #
  # Return the hash of stage payloads
  #
  def _stages
    return payload_type_modules[Payload::Type::Stage] || {}
  end

  #
  # Builds a duplicate, extended version of the Payload base
  # class using the supplied modules.
  #
  def build_payload(*modules)
    klass = Class.new(Payload)

    # Remove nil modules
    modules.compact!

    # Include the modules supplied to us with the mad skillz
    # spoonfu style
    klass.include(*modules.reverse)

    return klass
  end

  attr_accessor :payload_type_modules # :nodoc:
  attr_writer   :stages, :singles, :sizes # :nodoc:
  attr_accessor :_instances # :nodoc:

end

end

