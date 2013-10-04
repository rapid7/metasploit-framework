# Namespaces for {Metasploit::Framework::Module::Ancestor::MetasploitModule#each_metasploit_class}
require 'msf/core/modules'
require 'msf/core/payloads'

module Metasploit::Framework::Module::Ancestor::MetasploitModule
  extend Metasploit::Framework::ResurrectingAttribute
  include Metasploit::Framework::Module::Ancestor::MetasploitModule::Cache
  include Metasploit::Framework::ProxiedValidation

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
        inherit = false

        case payload_type
          when 'single'
            single_payload_relative_class_name = "RealPathSha1HexDigest#{real_path_sha1_hex_digest}"

            if Msf::Payloads.const_defined? single_payload_relative_class_name, inherit
              single_payload_class = Msf::Payloads.const_get single_payload_relative_class_name, inherit
              dlog("Reusing single payload Msf::Payloads::#{single_payload_relative_class_name}")
            else
              single_payload_class = Class.new(Msf::Payload)
              single_payload_class.send(:include, self)
              begin
                single_payload_class.send(:include, handler_module)
              rescue NameError => error
                raise
              end

              Msf::Payloads.const_set(single_payload_relative_class_name, single_payload_class)
              dlog("Creating single payload Msf::Payloads::#{single_payload_relative_class_name}")
            end

            yield cacheable_metasploit_class(single_payload_class)
          when 'stage'
            # TODO implement combining this stage with all pre-existing stagers to make staged payload classes.
            elog(
                "#{self.class}##{__method__} not implemented for stage payloads.  " \
                "Cannot create Msf::Payloads::RealPathSha1HexDigest#{real_path_sha1_hex_digest}StagedByRealPathSha1HexDigest<stager.real_path_sha1_hex_digest>s."
            )
          when 'stager'
            # TODO implement combining this stager with all pre-existing stages to make staged payload classes.
            elog(
                "#{self.class}##{__method__} not implemented for stage payloads.  " \
                "Cannot create Msf::Payloads::RealPathSha1HexDigest<stage.real_path_sha1_hex_digest>StagedByRealPathSha1HexDigest#{real_path_sha1_hex_digest}s."
            )
        end
      else
        yield cacheable_metasploit_class(self)
      end
    end
  end

  # @note Default implementation of is_usable in-case the `Metasploit::Model::Module::Ancestor` `Module` does implement
  #   the method so that validation will always work.
  #
  # @return [true]
  def is_usable
    true
  end

  delegate :module_type,
           :payload_type,
           :payload?,
           :real_path_sha1_hex_digest,
           to: :parent

  def validation_proxy_class
    Metasploit::Framework::Module::Ancestor::MetasploitModule::ValidationProxy
  end
end
