module Metasploit::Framework::Module::Ancestor::MetasploitModule::Cache
  # Extends and includes modules to allow `metasploit_class` to cache in `Metasploit::Model::Module::Class` and
  # `Metasploit::Model::Module::Instance`.
  #
  # @return [Class] `metasploit_class`
  def cacheable_metasploit_class(metasploit_class)
    metasploit_class.extend Metasploit::Framework::Module::Class::MetasploitClass
    metasploit_class.send(:include, Metasploit::Framework::Module::Instance::MetasploitInstance)

    metasploit_class
  end

  # Caches `#handler_type_alias` in `module_ancestor` `Metasploit::Model::Module::Ancestor#handler_type`
  #
  # @param module_ancestor [Metasploit::Model::Module::Ancestor] module ancestor whose #handler_type to set.
  # @return [void]
  def cache_handler_type(module_ancestor)
    # only single and stager payloads are expected to respond to this message.
    if respond_to? :handler_type_alias
      module_ancestor.handler_type = handler_type_alias
    else
      # set to nil when not respond to ensure updates clear the previous value and the previous value doesn't make
      # current module_ancestor valid by mistake
      module_ancestor.handler_type = nil

      if module_ancestor.handled?
        elog(
            "#{module_ancestor.real_path} is expected to respond to #handler_type_alias, but it does not.  " \
            "Add the following to the module body:\n" \
            "module Metasploit<n>\n" \
            "  extend Metasploit::Framework::Module::Ancestor::Handler\n" \
            "  \n" \
            "  handler module_name: 'Msf::Handler::<relative_name>',\n" \
            "          # type_alias is optional.  If not given, will use Module#handler_type for Module with Module#name equal to module_name option.\n" \
            "          type_alias: '<optional_type_alias>'\n" \
            "  \n" \
            "end"
        )
      end
    end
  end

  # Caches ancestor metadata.
  #
  # @param module_ancestor [Metasploit::Model::Module::Ancestor, nil] module ancestor to which to write metadata.  If
  #   `nil` will write metadata to {#module_ancestor}.
  # @return [Metasploit::Model::Module::Ancestor]
  def cache_module_ancestor(module_ancestor=nil)
    module_ancestor ||= self.module_ancestor
    cache_handler_type(module_ancestor)

    ActiveRecord::Base.connection_pool.with_connection do
      unless module_ancestor.batched_save
        elog(
            "#{module_ancestor.real_path} didn't save its Module::Ancestor to cache because: #{module_ancestor.errors.full_messages}"
        )
      end
    end

    module_ancestor
  end
end
