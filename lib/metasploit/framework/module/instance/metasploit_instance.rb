module Metasploit::Framework::Module::Instance::MetasploitInstance
  extend Metasploit::Framework::ResurrectingAttribute

  include Metasploit::Framework::Module::Instance::MetasploitInstance::Cache

  #
  # Resurrecting Attributes
  #

  # @!attribute [rw] module_instance
  #   Cached metadata for this instance.
  #
  #   @return [Metasploit::Model::Module::Instance]
  resurrecting_attr_accessor :module_instance do
    ActiveRecord::Base.connection_pool.with_connection {
      ActiveRecord::Base.transaction {
        module_class = self.class.module_class
        module_instance = module_class.module_instance

        unless module_instance
          module_instance = module_class.build_module_instance
        end

        module_instance
      }
    }
  end
end
