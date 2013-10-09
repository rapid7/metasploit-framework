require 'msf/core/handler/none'

# Namespaces for {Metasploit::Framework::Module::Ancestor::MetasploitModule#each_metasploit_class}
require 'msf/core/modules'
require 'msf/core/payloads'

module Metasploit::Framework::Module::Ancestor::MetasploitModule
  extend Metasploit::Framework::ResurrectingAttribute
  include Metasploit::Framework::Module::Ancestor::MetasploitModule::Cache
  include Metasploit::Framework::ProxiedValidation

  #
  # CONSTANTS
  #

  # The payload type that needs to be paired with this metasploit module's {#payload_type} to form a staged payload
  # metasploit `Class`.
  PAIRED_PAYLOAD_TYPE_BY_PAYLOAD_TYPE = {
      'stage' => 'stager',
      'stager' => 'stage'
  }

  #
  # Resurrecting Attributes
  #

  # @!attribute [rw] module_ancestor
  #   Cached metadata for this Module.
  #
  #   @return [Metasploit::Model::Module::Ancestor]
  resurrecting_attr_accessor :module_ancestor do
    ActiveRecord::Base.connection_pool.with_connection {
      Mdm::Module::Ancestor.where(real_path_sha1_hex_digest: real_path_sha1_hex_digest).first
    }
  end

  #
  # Methods
  #

  # Yields each payload module with {#paired_payload_type} that is compatible with this metasploit module and can be
  # combined into a staged payload 'Class'.
  #
  # @yield [metasploit_module]
  # @yieldparam metasploit_module [Module] metasploit module with {#paired_payload_type} that is compatible with this
  #   metasploit module.
  # @yieldreturn [void]
  # @return [void]
  # @raise (see #payload_metasploit_class)
  def each_compatible_metasploit_module
    metasploit_class = payload_metasploit_class
    metasploit_instance = metasploit_class.new

    each_paired_metasploit_module do |paired_metasploit_module|
      paired_metasploit_class = paired_metasploit_module.payload_metasploit_class
      paired_metasploit_instance = paired_metasploit_class.new

      platform_intersection = metasploit_instance.platform & paired_metasploit_instance.platform

      unless platform_intersection.empty?
        architecture_intersection = metasploit_instance.arch & paired_metasploit_instance.arch

        unless architecture_intersection.empty?
          if payload_type == 'stage'
            stage_instance = metasploit_instance
            stager_instance = paired_metasploit_instance
          else
            stage_instance = paired_metasploit_instance
            stager_instance = metasploit_instance
          end

          if stage_instance.compatible?(stager_instance)
            yield paired_metasploit_module
          end
        end
      end
    end
  end

  # Finds or generates all classes that can use this metasploit module.  If this metasploit module is already a class,
  # as is the case with non-payloads, then it will just be this metasploit_module alone in the Array; however, if
  # this metasploit_module is a payload, then it will yield all the Msf::Payload subclasses that can include this
  # metasploit module, which will be one if this is a single payload, but one or more if this is a stage or stager.
  # Because the staged payloads are dependent on the combination of stages and stagers that are currently loaded, this
  # list of Classes will change as more stages and stagers are loaded.
  #
  # @yield [metasploit_class]
  # @yieldparam metasploit_class [Metasploit::Framework::Module::Class::MetasploitClass] `Class` that includes this
  #   metasploit module.
  # @yieldreturn [void]
  # @return [void]
  def each_metasploit_class
    unless block_given?
      to_enum(__method__)
    else
      if payload?
        case payload_type
          when 'single'
            yield payload_metasploit_class
          when 'stage', 'stager'
            each_staged_payload_class do |staged_payload_class|
              yield staged_payload_class
            end
        end
      else
        yield cacheable_metasploit_class(self)
      end
    end
  end

  # @note The yielded modules have not been checked for compatibility, it is the responsibility of the caller to check
  #   that this metasploit module is compatible with the yielded metasploit module before combining them into a staged
  #   payload `Class`.
  #
  # Each payload module that has the {#paired_payload_type} that are loaded in memory and be paired with this
  # metasploit module to form a staged payload Class.
  #
  # @yield [metasploit_module]
  # @yieldparam metasploit_module [Module] a payload Module with {#paired_payload_type}.
  # @yieldreturn [void]
  # @return [void]
  def each_paired_metasploit_module
    inherit = false

    paired_real_path_sha1_hex_digests.each do |real_path_sha1_hex_digest|
      relative_name = "RealPathSha1HexDigest#{real_path_sha1_hex_digest}"

      if Msf::Modules.const_defined? relative_name, inherit
        namespace_module = Msf::Modules.const_get relative_name, inherit
        paired_metasploit_module = namespace_module.metasploit_module

        yield paired_metasploit_module
      end
    end
  end

  # @yieldreturn [void]
  # @return [void]
  def each_staged_payload_class
    if payload_type == 'stage'
      stage_metasploit_module = self
    else
      stager_metasploit_module = self
    end

    each_compatible_metasploit_module do |compatible_metasploit_module|
      if payload_type == 'stage'
        stager_metasploit_module = compatible_metasploit_module
      else
        stage_metasploit_module = compatible_metasploit_module
      end

      inherit = false
      relative_class_name = "RealPathSha1HexDigest#{stage_metasploit_module.real_path_sha1_hex_digest}StagedByRealPathSha1HexDigest#{stager_metasploit_module.real_path_sha1_hex_digest}"

      if Msf::Payloads.const_defined? relative_class_name, inherit
        payload_class = Msf::Payloads.const_get relative_class_name, inherit
        dlog("Reusing payload Msf::Payloads::#{relative_class_name}")
      else
        payload_class = Class.new(Msf::Payload)
        payload_class.send(:include, stage_metasploit_module)
        payload_class.send(:include, stager_metasploit_module)
        payload_class.send(:include, stager_metasploit_module.handler_module)

        Msf::Payloads.const_set(relative_class_name, payload_class)
        dlog("Creating payload Msf::Payload::#{relative_class_name}")
      end

      yield cacheable_metasploit_class(payload_class)
    end
  end

  # @note Default implementation of is_usable in-case the `Metasploit::Model::Module::Ancestor` `Module` does implement
  #   the method so that validation will always work.
  #
  # @return [true]
  def is_usable
    true
  end

  # @!method module_type
  #   {Metasploit::Framework::Module::Ancestor::Namespace#module_type}
  #
  #   @return (see Metasploit::Framework::Module::Ancestor::Namespace#module_type)
  # @!method payload_type
  #   {Metasploit::Framework::Module::Ancestor::Namespace#payload_type}
  #
  #   @return (see Metasploit::Framework::Module::Ancestor::Namespace#payload_type)
  # @!method payload?
  #   {Metasploit::Framework::Module::Ancestor::Namespace#payload?}
  #
  #   @return (see Metasploit::Framework::Module::Ancestor::Namespace#payload?)
  # @!method real_path_sha1_hex_digest
  #   {Metasploit::Framework::Module::Ancestor::Namespace#real_path_sha1_hex_digest}
  #
  #   @return (see Metasploit::Framework::Module::Ancestor::Namespace#real_path_sha1_hex_digest)
  delegate :module_type,
           :payload_type,
           :payload?,
           :real_path_sha1_hex_digest,
           to: :parent

  # The payload type that needs to be paired with {#payload_type} to make a staged payload Class.
  #
  # @return [String] 'stage' or 'stager'.
  # @raise [KeyError] if {#payload_type} is no 'stage' or 'stager'.
  def paired_payload_type
    PAIRED_PAYLOAD_TYPE_BY_PAYLOAD_TYPE.fetch(payload_type)
  end

  # Finds the `Metasploit::Model::Module::Ancestor#real_path_sha1_hex_digest` for this metasploit module's paired
  # payload type so that the corresponding metasploit modules can be looked for in-memory to combine with this
  # metasploit module to form a staged payload `Class`.
  #
  # @return [Array<String>] An Array of `Metasploit::Model::Module::Ancestor#real_path_sha1_hex_digest`.
  def paired_real_path_sha1_hex_digests
    ActiveRecord::Base.connection_pool.with_connection {
      Mdm::Module::Ancestor.where(
          module_type: Metasploit::Model::Module::Type::PAYLOAD,
          payload_type: paired_payload_type,
      ).pluck(:real_path_sha1_hex_digest)
    }
  end

  # Payload Class that only includes this metasploit module (and its handler module).  For single payload metasploit
  # modules this is the final Class that the framework user can instantiate, but for stage and stager payload
  # metasaploit modules, this Class is only instantiated to check compatibility between the class and a paired class
  # to form the final staged payload Class.
  #
  # @return [Metasploit::Framework::Module::Class::MetasploitClass] `Class` that includes this
  #   metasploit module.
  # @raise [ArgumentError] if this is a not a payload metasploit module
  def payload_metasploit_class
    unless payload?
      raise ArgumentError, "#{module_type} metasploit modules do not have a #{self.class}##{__method__}"
    end

    inherit = false
    relative_class_name = "RealPathSha1HexDigest#{real_path_sha1_hex_digest}"

    if Msf::Payloads.const_defined? relative_class_name, inherit
      payload_class = Msf::Payloads.const_get relative_class_name, inherit
      dlog("Reusing payload Msf::Payloads::#{relative_class_name}")
    else
      payload_class = Class.new(Msf::Payload)
      payload_class.send(:include, self)

      if payload_type == 'stage'
        # ensures that the stage itself does not respond to handler_module, but that {#payload_metasploit_class} can
        # be instantiated, which requires a handler module.
        handled_ancestor = Metasploit::Framework::Module::Ancestor::Payload::Stage::Handler
        payload_class.send(:include, handled_ancestor)

        handler_module = handled_ancestor.handler_module
      else
        handler_module = self.handler_module
      end

      payload_class.send(:include, handler_module)

      Msf::Payloads.const_set(relative_class_name, payload_class)
      dlog("Creating payload Msf::Payloads::#{relative_class_name}")
    end

    cacheable_metasploit_class(payload_class)
  end

  def validation_proxy_class
    Metasploit::Framework::Module::Ancestor::MetasploitModule::ValidationProxy
  end
end
