#
# Project
#
require 'msf/core/modules/loader'
require 'msf/core/modules/namespace'
require 'msf/core/modules/metasploit_class_compatibility_error'
require 'msf/core/modules/version_compatibility_error'

# Responsible for loading modules for {Msf::ModuleManager}.
#
# @abstract Subclass and override {#each_module_reference_name}, {#loadable?}, {#module_path}, and
#   {#read_module_content}.
class Msf::Modules::Loader::Base
  #
  # CONSTANTS
  #

  # This must calculate the first line of the NAMESPACE_MODULE_CONTENT string so that errors are reported correctly
  NAMESPACE_MODULE_LINE = __LINE__ + 4
  # By calling module_eval from inside the module definition, the lexical scope is captured and available to the code in
  # module_content.
  NAMESPACE_MODULE_CONTENT = <<-EOS
    # ensure the namespace module can respond to checks during loading
    extend Msf::Modules::Namespace

    class << self
      # The loader that originally loaded this module
      #
      # @return [Msf::Modules::Loader::Base] the loader that loaded this namespace module and can reload it.
      attr_accessor :loader

      # @return [String] The path under which the module of the given type was found.
      attr_accessor :parent_path
    end

    # Calls module_eval on the module_content, but the lexical scope of the namespace_module is passed through
    # module_eval, so that module_content can act like it was written inline in the namespace_module.
    #
    # @param [String] module_content The content of the {Msf::Module}.
    # @param [String] module_path The path to the module, so that error messages in evaluating the module_content can
    #   be reported correctly.
    def self.module_eval_with_lexical_scope(module_content, module_path)
      # By calling module_eval from inside the module definition, the lexical scope is captured and available to the
      # code in module_content.
      module_eval(module_content, module_path)
    end
  EOS
  # The extension for metasploit modules.
  MODULE_EXTENSION = '.rb'
  # String used to separate module names in a qualified module name.
  MODULE_SEPARATOR = '::'
  # The base namespace name under which {#create_namespace_module
  # namespace modules are created}.
  NAMESPACE_MODULE_NAMES = ['Msf', 'Modules']
  # Regex that can distinguish regular ruby source from unit test source.
  UNIT_TEST_REGEX = /rb\.(ut|ts)\.rb$/

  # @param [Msf::ModuleManager] module_manager The module manager that
  #   caches the loaded modules.
  def initialize(module_manager)
    @module_manager = module_manager
  end

  # Returns whether the path can be loaded this module loader.
  #
  # @abstract Override and determine from properties of the path or the
  #   file to which the path points whether it is loadable using
  #   {#load_modules} for the subclass.
  #
  # @param path (see #load_modules)
  # @return [Boolean]
  def loadable?(path)
    raise ::NotImplementedError
  end

  # Loads a module from the supplied path and module_reference_name.
  #
  # @param [String] parent_path The path under which the module exists.
  #   This is not necessarily the same path as passed to
  #   {#load_modules}: it may just be derived from that path.
  # @param [String] type The type of module.
  # @param [String] module_reference_name The canonical name for
  #   referring to the module.
  # @param [Hash] options Options used to force loading and track
  #   statistics
  # @option options [Hash{String => Integer}] :count_by_type Maps the
  #   module type to the number of module loaded
  # @option options [Boolean] :force (false) whether to force loading of
  #   the module even if the module has not changed.
  # @option options [Hash{String => Boolean}] :recalculate_by_type Maps
  #   type to whether its {Msf::ModuleManager::ModuleSets#module_set}
  #   needs to be recalculated.
  # @option options [Boolean] :reload (false) whether this is a reload.
  #
  # @return [false] if :force is false and parent_path has not changed.
  # @return [false] if exception encountered while parsing module
  #   content
  # @return [false] if the module is incompatible with the Core or API
  #   version.
  # @return [false] if the module does not implement a Metasploit(\d+)
  #   class.
  # @return [false] if the module's is_usable method returns false.
  # @return [true] if all those condition pass and the module is
  #   successfully loaded.
  #
  # @see #read_module_content
  # @see Msf::ModuleManager::Loading#file_changed?
  def load_module(parent_path, type, module_reference_name, options={})
    options.assert_valid_keys(:count_by_type, :force, :recalculate_by_type, :reload)
    force = options[:force] || false
    reload = options[:reload] || false

    module_path = self.module_path(parent_path, type, module_reference_name)
    file_changed = module_manager.file_changed?(module_path)

    unless force or file_changed
      dlog("Cached module from #{module_path} has not changed.", 'core', LEV_2)

      return false
    end

    reload ||= force || file_changed

    metasploit_class = nil

    module_content = read_module_content(parent_path, type, module_reference_name)

    if module_content.empty?
      # read_module_content is responsible for calling {#load_error}, so just return here.
      return false
    end

    try_eval_module = lambda { |namespace_module|
      # set the parent_path so that the module can be reloaded with #load_module
      namespace_module.parent_path = parent_path

      begin
        namespace_module.module_eval_with_lexical_scope(module_content, module_path)
      # handle interrupts as pass-throughs unlike other Exceptions so users can bail with Ctrl+C
      rescue ::Interrupt
        raise
      rescue ::Exception => error
        # Hide eval errors when the module version is not compatible
        begin
          namespace_module.version_compatible!(module_path, module_reference_name)
        rescue Msf::Modules::VersionCompatibilityError => version_compatibility_error
          load_error(module_path, version_compatibility_error)
        else
          load_error(module_path, error)
        end

        return false
      end

      begin
        namespace_module.version_compatible!(module_path, module_reference_name)
      rescue Msf::Modules::VersionCompatibilityError => version_compatibility_error
        load_error(module_path, version_compatibility_error)

        return false
      end

      begin
        metasploit_class = namespace_module.metasploit_class!(module_path, module_reference_name)
      rescue Msf::Modules::MetasploitClassCompatibilityError => error
        load_error(module_path, error)

        return false
      end

      unless usable?(metasploit_class)
        ilog(
            "Skipping module (#{module_reference_name} from #{module_path}) because is_usable returned false.",
            'core',
            LEV_1
        )

        return false
      end

      if reload
        ilog("Reloading #{type} module #{module_reference_name}. Ambiguous module warnings are safe to ignore", 'core', LEV_2)
      else
        ilog("Loaded #{type} module #{module_reference_name} under #{parent_path}", 'core', LEV_2)
      end

      module_manager.module_load_error_by_path.delete(module_path)

      true
    }

    loaded = namespace_module_transaction(type + "/" + module_reference_name, :reload => reload, &try_eval_module)
    unless loaded
      return false
    end

    # Do some processing on the loaded module to get it into the right associations
    module_manager.on_module_load(
        metasploit_class,
        type,
        module_reference_name,
        {
            # files[0] is stored in the {Msf::Module#file_path} and is used to reload the module, so it needs to be a
            # full path
            'files' => [
                module_path
            ],
            'paths' => [
                module_reference_name
            ],
            'type' => type
        }
    )

    # Set this module type as needing recalculation
    recalculate_by_type = options[:recalculate_by_type]

    if recalculate_by_type
      recalculate_by_type[type] = true
    end

    # The number of loaded modules this round
    count_by_type = options[:count_by_type]

    if count_by_type
      count_by_type[type] ||= 0
      count_by_type[type] += 1
    end

    return true
  end

  # Loads all of the modules from the supplied path.
  #
  # @note Only paths where {#loadable?} returns true should be passed to
  #   this method.
  #
  # @param [String] path Path under which there are modules
  # @param [Hash] options
  # @option options [Boolean] force (false) Whether to force loading of
  #   the module even if the module has not changed.
  # @option options [Array] whitelist An array of regex patterns to search for specific modules
  # @return [Hash{String => Integer}] Maps module type to number of
  #   modules loaded
  def load_modules(path, options={})
    options.assert_valid_keys(:force, :whitelist)

    force = options[:force]
    count_by_type = {}
    recalculate_by_type = {}

    # This is used to avoid loading the same thing twice
    loaded_items = []

    each_module_reference_name(path, options) do |parent_path, type, module_reference_name|
      # In msfcli mode, if a module is already loaded, avoid loading it again
      next if loaded_items.include?(module_reference_name) and options[:whitelist]

      # Keep track of loaded modules in msfcli mode
      loaded_items << module_reference_name if options[:whitelist]
      load_module(
          parent_path,
          type,
          module_reference_name,
          :recalculate_by_type => recalculate_by_type,
          :count_by_type => count_by_type,
          :force => force
      )
    end

    recalculate_by_type.each do |type, recalculate|
      if recalculate
        module_set = module_manager.module_set(type)
        module_set.recalculate
      end
    end

    count_by_type
  end

  # Reloads the specified module.
  #
  # @param [Class, Msf::Module] original_metasploit_class_or_instance either an instance of a module or a module class.
  #   If an instance is given, then the datastore will be copied to the new instance returned by this method.
  # @return [Class, Msf::Module] original_metasploit_class_or_instance if an instance of the reloaded module cannot be
  #   created.
  # @return [Msf::Module] new instance of original_metasploit_class with datastore copied from
  #   original_metasploit_instance.
  def reload_module(original_metasploit_class_or_instance)
    if original_metasploit_class_or_instance.is_a? Msf::Module
      original_metasploit_instance = original_metasploit_class_or_instance
      original_metasploit_class = original_metasploit_class_or_instance.class
    else
      original_metasploit_instance = nil
      original_metasploit_class = original_metasploit_class_or_instance
    end

    namespace_module = original_metasploit_class.parent
    parent_path = namespace_module.parent_path

    type = original_metasploit_class_or_instance.type
    module_reference_name = original_metasploit_class_or_instance.refname

    dlog("Reloading module #{module_reference_name}...", 'core')

    if load_module(parent_path, type, module_reference_name, :force => true, :reload => true)
      # Create a new instance of the module
      reloaded_module_instance = module_manager.create(module_reference_name)

      if reloaded_module_instance
        if original_metasploit_instance
          # copy over datastore
          reloaded_module_instance.datastore.update(original_metasploit_instance.datastore)
        end
      else
        elog("Failed to create instance of #{original_metasploit_class_or_instance.refname} after reload.", 'core')

        # Return the old module instance to avoid an strace trace
        return original_metasploit_class_or_instance
      end
    else
      elog("Failed to reload #{module_reference_name}")

      return nil
    end

    # Let the specific module sets have an opportunity to handle the fact
    # that this module was reloaded.
    module_set = module_manager.module_set(type)
    module_set.on_module_reload(reloaded_module_instance)

    # Rebuild the cache for just this module
    module_manager.refresh_cache_from_module_files(reloaded_module_instance)

    reloaded_module_instance
  end

  protected

  # Returns a nested module to wrap the Metasploit(1|2|3) class so that it doesn't overwrite other (metasploit)
  # module's classes.  The wrapper module must be named so that active_support's autoloading code doesn't break when
  # searching constants from inside the Metasploit(1|2|3) class.
  #
  # @param namespace_module_names [Array<String>]
  #   {NAMESPACE_MODULE_NAMES} + <derived-constant-safe names>
  # @return [Module] module that can wrap the module content from {#read_module_content} using
  #   module_eval_with_lexical_scope.
  #
  # @see NAMESPACE_MODULE_CONTENT
  def create_namespace_module(namespace_module_names)
    # In order to have constants defined in Msf resolve without the Msf qualifier in the module_content, the
    # Module.nesting must resolve for the entire nesting.  Module.nesting is strictly lexical, and can't be faked with
    # module_eval(&block). (There's actually code in ruby's implementation to stop module_eval from being added to
    # Module.nesting when using the block syntax.) All this means is the modules have to be declared as a string that
    # gets module_eval'd.

    nested_module_names = namespace_module_names.reverse

    namespace_module_content = nested_module_names.inject(NAMESPACE_MODULE_CONTENT) { |wrapped_content, module_name|
      lines = []
      lines << "module #{module_name}"
      lines << wrapped_content
      lines << "end"

      lines.join("\n")
    }

    # - because the added wrap lines have to act like they were written before NAMESPACE_MODULE_CONTENT
    line_with_wrapping = NAMESPACE_MODULE_LINE - nested_module_names.length
    Object.module_eval(namespace_module_content, __FILE__, line_with_wrapping)

    # The namespace_module exists now, so no need to use constantize to do const_missing
    namespace_module = current_module(namespace_module_names)
    # record the loader, so that the namespace module and its metasploit_class can be reloaded
    namespace_module.loader = self

    namespace_module
  end

  # Returns the module with `module_names` if it exists.
  #
  # @param [Array<String>] module_names a list of module names to resolve from Object downward.
  # @return [Module] module that wraps the previously loaded content from {#read_module_content}.
  # @return [nil] if any module name along the chain does not exist.
  def current_module(module_names)
    # Don't want to trigger ActiveSupport's const_missing, so can't use constantize.
    named_module = module_names.inject(Object) { |parent, module_name|
      # Since we're searching parent namespaces first anyway, this is
      # semantically equivalent to providing false for the 1.9-only
      # "inherit" parameter to const_defined?. If we ever drop 1.8
      # support, we can save a few cycles here by adding it back.
      if parent.const_defined?(module_name)
        parent.const_get(module_name)
      else
        break
      end
    }

    named_module
  end

  # Yields module reference names under path.
  #
  # @abstract Override and search the path for modules.
  #
  # @param path (see #load_modules)
  # @yield [parent_path, type, module_reference_name] Gives the path and the module_reference_name of the module found
  #   under the path.
  # @yieldparam parent_path [String] the path under which the module of the given type was found.
  # @yieldparam type [String] the type of the module.
  # @yieldparam module_reference_name [String] The canonical name for referencing the module.
  # @return [void]
  def each_module_reference_name(path)
    raise ::NotImplementedError
  end

  # Records the load error to {Msf::ModuleManager::Loading#module_load_error_by_path} and the log.
  #
  # @param [String] module_path Path to the module as returned by {#module_path}.
  # @param [Exception, #class, #to_s, #backtrace] error the error that cause the module not to load.
  # @return [void]
  #
  # @see #module_path
  def load_error(module_path, error)
    # module_load_error_by_path does not get the backtrace because the value is echoed to the msfconsole where
    # backtraces should not appear.
    module_manager.module_load_error_by_path[module_path] = "#{error.class} #{error}"

    log_lines = []
    log_lines << "#{module_path} failed to load due to the following error:"
    log_lines << error.class.to_s
    log_lines << error.to_s
    log_lines << "Call stack:"
    log_lines += error.backtrace

    log_message = log_lines.join("\n")
    elog(log_message)
  end

  # @return [Msf::ModuleManager] The module manager for which this loader is loading modules.
  attr_reader :module_manager

  # Returns path to module that can be used for reporting errors in evaluating the
  # {#read_module_content module_content}.
  #
  # @abstract Override to return the path to the module on the file system so that errors can be reported correctly.
  #
  # @param path (see #load_module)
  # @param type (see #load_module)
  # @param module_reference_name (see #load_module)
  # @return [String] The path to module.
  def module_path(parent_path, type, module_reference_name)
    raise ::NotImplementedError
  end

  # Returns whether the path could refer to a module.  The path would still need to be loaded in order to check if it
  # actually is a valid module.
  #
  # @param [String] path to module without the type directory.
  # @return [true] if the extname is {MODULE_EXTENSION} AND
  #                   the path does not match {UNIT_TEST_REGEX} AND
  #                   the path is not hidden (starts with '.')
  # @return [false] otherwise
  def module_path?(path)
    module_path = false

    extension = File.extname(path)

    unless (path[0,1] == "." or
            extension != MODULE_EXTENSION or
            path =~ UNIT_TEST_REGEX)
      module_path = true
    end

    module_path
  end

  # Changes a file name path to a canonical module reference name.
  #
  # @param [String] path Relative path to module.
  # @return [String] {MODULE_EXTENSION} removed from path.
  def module_reference_name_from_path(path)
    path.gsub(/#{MODULE_EXTENSION}$/, '')
  end

  # Returns the fully-qualified name to the {#create_namespace_module} that wraps the module with the given module
  # reference name.
  #
  # @param [String] module_full_name The canonical name for referring to the
  #   module.
  # @return [String] name of module.
  #
  # @see MODULE_SEPARATOR
  # @see #namespace_module_names
  def namespace_module_name(module_full_name)
    namespace_module_names = self.namespace_module_names(module_full_name)
    namespace_module_name = namespace_module_names.join(MODULE_SEPARATOR)

    namespace_module_name
  end

  # Returns an Array of names to make a fully qualified module name to
  # wrap the Metasploit(1|2|3) class so that it doesn't overwrite other
  # (metasploit) module's classes.  Invalid module name characters are
  # escaped by using 'H*' unpacking and prefixing each code with X so
  # the code remains a valid module name when it starts with a digit.
  #
  # @param [String] module_full_name The unique canonical name
  #   for the module including type.
  # @return [Array<String>] {NAMESPACE_MODULE_NAMES} + <derived-constant-safe names>
  #
  # @see namespace_module
  def namespace_module_names(module_full_name)
    NAMESPACE_MODULE_NAMES + [ "Mod" + module_full_name.unpack("H*").first.downcase ]
  end

  def namespace_module_transaction(module_full_name, options={}, &block)
    options.assert_valid_keys(:reload)

    reload = options[:reload] || false
    namespace_module_names = self.namespace_module_names(module_full_name)

    previous_namespace_module = current_module(namespace_module_names)

    if previous_namespace_module and not reload
      elog("Reloading namespace_module #{previous_namespace_module} when :reload => false")
    end

    relative_name = namespace_module_names.last

    if previous_namespace_module
      parent_module = previous_namespace_module.parent
      # remove_const is private, so use send to bypass
      parent_module.send(:remove_const, relative_name)
    end

    namespace_module = create_namespace_module(namespace_module_names)
    # Get the parent module from the created module so that
    # restore_namespace_module can remove namespace_module's constant if
    # needed.
    parent_module = namespace_module.parent

    begin
      loaded = block.call(namespace_module)
    rescue Exception
      restore_namespace_module(parent_module, relative_name, previous_namespace_module)

      # re-raise the original exception in the original context
      raise
    else
      unless loaded
        restore_namespace_module(parent_module, relative_name, previous_namespace_module)
      end

      loaded
    end
  end

  # Read the content of the module from under path.
  #
  # @abstract Override to read the module content based on the method of the loader subclass and return a string.
  #
  # @param parent_path (see #load_module)
  # @param type (see #load_module)
  # @param module_reference_name (see #load_module)
  # @return [String] module content that can be module_evaled into the {#create_namespace_module}
  def read_module_content(parent_path, type, module_reference_name)
    raise ::NotImplementedError
  end

  # Restores the namespace module to it's original name under it's original parent Module if there was a previous
  # namespace module.
  #
  # @param [Module] parent_module The .parent of namespace_module before it was removed from the constant tree.
  # @param [String] relative_name The name of the constant under parent_module where namespace_module was attached.
  # @param [Module, nil] namespace_module The previous namespace module containing the old module content.  If `nil`,
  #   then the relative_name constant is removed from parent_module, but nothing is set as the new constant.
  # @return [void]
  def restore_namespace_module(parent_module, relative_name, namespace_module)
    if parent_module
      # If there is a current module with relative_name
      if parent_module.const_defined?(relative_name)
        # if the current value isn't the value to be restored.
        if parent_module.const_get(relative_name) != namespace_module
          # remove_const is private, so use send to bypass
          parent_module.send(:remove_const, relative_name)

          # if there was a previous module, not set it to the name
          if namespace_module
            parent_module.const_set(relative_name, namespace_module)
          end
        end
      else
        # if there was a previous module, but there isn't a current module, then restore the previous module
        if namespace_module
          parent_module.const_set(relative_name, namespace_module)
        end
      end
    end
  end

  # The path to the module qualified by the type directory.
  #
  # @param [String] type The type of the module.
  # @param [String] module_reference_name The canonical name for the module.
  # @return [String] path to the module starting with the type directory.
  #
  # @see Metasploit::Model::Module::Ancesotr::DIRECTORY_BY_MODULE_TYPE
  def self.typed_path(type, module_reference_name)
    file_name = module_reference_name + MODULE_EXTENSION
    type_directory = Metasploit::Model::Module::Ancestor::DIRECTORY_BY_MODULE_TYPE[type]
    typed_path = File.join(type_directory, file_name)

    typed_path
  end

  # The path to the module qualified by the type directory.
  #
  # @note To get the full path to the module, use {#module_path}.
  #
  # @param (see typed_path)
  # @return (see typed_path)
  def typed_path(type, module_reference_name)
    self.class.typed_path(type, module_reference_name)
  end

  # Returns whether the metasploit_class is usable on the current system.  Defer's to metasploit_class's #is_usable if
  # it is defined.
  #
  # @param [Msf::Module] metasploit_class As returned by {Msf::Modules::Namespace#metasploit_class}
  # @return [false] if metasploit_class.is_usable returns false.
  # @return [true] if metasploit_class does not respond to is_usable.
  # @return [true] if metasploit_class.is_usable returns true.
  def usable?(metasploit_class)
    # If the module indicates that it is not usable on this system, then we
    # will not try to use it.
    usable = false

    if metasploit_class.respond_to? :is_usable
      begin
        usable = metasploit_class.is_usable
      rescue => error
        elog("Exception caught during is_usable check: #{error}")
      end
    else
      usable = true
    end

    usable
  end
end
