class Metasploit::Framework::Module::Cache < Metasploit::Model::Base
  #
  # CONSTANTS
  #

  # Can be actual class references and not Class#names since there is no problem with circular loading.
  MODULE_CLASS_LOAD_CLASS_BY_PAYLOAD_TYPE_BY_MODULE_TYPE = {
      Metasploit::Model::Module::Type::AUX => {
          nil => Metasploit::Framework::Module::Class::Load::NonPayload
      },
      Metasploit::Model::Module::Type::ENCODER => {
          nil => Metasploit::Framework::Module::Class::Load::NonPayload
      },
      Metasploit::Model::Module::Type::EXPLOIT => {
          nil => Metasploit::Framework::Module::Class::Load::NonPayload
      },
      Metasploit::Model::Module::Type::NOP => {
          nil => Metasploit::Framework::Module::Class::Load::NonPayload
      },
      Metasploit::Model::Module::Type::PAYLOAD => {
          'single' => Metasploit::Framework::Module::Class::Load::Payload::Single,
          'staged' => Metasploit::Framework::Module::Class::Load::Payload::Staged
      },
      Metasploit::Model::Module::Type::POST => {
          nil => Metasploit::Framework::Module::Class::Load::NonPayload
      }
  }

  #
  # Attributes
  #

  # @!attribute [rw] module_manager
  #   The module manager using this cache.
  #
  #   @return [Msf::ModuleManager]
  attr_accessor :module_manager

  #
  # Validations
  #

  validates :module_manager,
            :presence => true

  #
  # Methods
  #

  delegate :framework,
           :module_type_enabled?,
           to: :module_manager

  # Either finds in-memory or loads into memory ruby `Class` described by `module_class`.
  #
  # @param module_class [Metasploit::Model::Module::Class] metadata about ruby `Class` to return
  # @return [Class]
  # @return [nil] if Class could not be loaded into memory.
  def metasploit_class(module_class)
    metasploit_class = nil

    module_class_load_class_by_payload_type = MODULE_CLASS_LOAD_CLASS_BY_PAYLOAD_TYPE_BY_MODULE_TYPE[module_class.module_type]

    if module_class_load_class_by_payload_type
      module_class_load_class = module_class_load_class_by_payload_type[module_class.payload_type]

      if module_class_load_class
        module_class_load = module_class_load_class.new(cache: self, module_class: module_class)

        if module_class_load.valid?
          metasploit_class = module_class_load.metasploit_class
        end
      end
    end

    metasploit_class
  end

  # Set of paths this cache using to load `Metasploit::Model::Ancestors`.
  #
  # @return [Metasploit::Framework::Module::PathSet::Base]
  def path_set
    unless instance_variable_defined? :@path_set
      path_set = Metasploit::Framework::Module::PathSet::Database.new(
          cache: self
      )
      path_set.valid!

      @path_set = path_set
    end

    @path_set
  end

  # Checks that this cache is up-to-date by scanning the
  # `Metasploit::Model::Path#real_path` of each `Metasploit::Module::Path` in
  # {#path_set} for updates to `Metasploit::Model::Module::Ancestors`.
  #
  # @param options [Hash]
  # @option options [nil, Metasploit::Model::Module::Path, Array<Metasploit::Model::Module::Path>] :only only prefetch
  #   the given module paths.  If :only is not given, then all module paths in
  #   {#path_set} will be prefetched.
  # @return [void]
  # @raise (see Metasploit::Framework::Module::PathSet::Base#superset!)
  def prefetch(options={})
    options.assert_valid_keys(:only)

    module_paths = Array.wrap(options[:only])

    if module_paths.blank?
      module_paths = path_set.all
    else
      path_set.superset!(module_paths)
    end

    # TODO generalize to work with or without ActiveRecord for in-memory models
    ActiveRecord::Base.connection_pool.with_connection do
      module_paths.each do |module_path|
        module_path_load = Metasploit::Framework::Module::Path::Load.new(
            cache: self,
            module_path: module_path
        )

        module_path_load.each_module_ancestor_load do |module_ancestor_load|
          write_module_ancestor_load(module_ancestor_load)
        end

        dlog("#{module_path.real_path} prefetched")
      end
    end

    dlog("#{module_paths.map(&:real_path).to_sentence} prefetched")
  end

  # Writes `Metasploit::Model::Module::Class` and `Metasploit::Model::Module::Instance` derived from
  # `module_ancestor_load` to this cache.  Only updates cache if `module_ancestor_load` is valid.
  #
  # @param module_ancestor_load [Metasploit::Framework::Module::Ancestor::Load] load of a
  #   `Metasploit::Model::Module::Ancestor`.
  # @return [true] if cache was written because `module_ancestor_load` was valid.
  # @return [false] if cache was not written because `module_ancestor_load` was not valid.
  def write_module_ancestor_load(module_ancestor_load)
    written = true

    # TODO log validation errors
    if module_ancestor_load.valid?
      metasploit_module = module_ancestor_load.metasploit_module

      metasploit_module.each_metasploit_class do |metasploit_class|
        metasploit_class.cache_module_class

        begin
          metasploit_instance = metasploit_class.new(framework: framework)
        rescue Exception => error
          # need to rescue Exception because the user could screw up #initialize in unknown ways
          elog("#{error.class} #{error}:\n#{error.backtrace.join("\n")}")
          written &= false
        else
          if metasploit_instance.valid?
            metasploit_instance.cache_module_instance
            written &= true
          else
            real_paths = metasploit_class.module_class.ancestors.map(&:real_path)
            elog("Msf::Module instance whose class includes module #{'ancestor'.pluralize(real_paths.length)} (#{real_paths.to_sentence}) is invalid: #{metasploit_instance.errors.full_messages}")
            metasploit_instance = metasploit_class.new(framework: framework)
          end
        end
      end
    else
      written = false
    end

    written
  end
end