module Metasploit::Framework::Module::Ancestor::MetasploitModule
  include Metasploit::Framework::ProxiedValidation

  #
  # Methods
  #

  # @note It is the caller's responsibility to check that the `module_class` saved successfully.
  #
  # Caches metadata.
  #
  # @param module_class [Metasploit::Model::Module::Class] module class to which to write metadata
  # @return [void]
  def cache(module_class)
    ActiveRecord::Base.connection_pool.with_connection do
      begin
        name = self.rank_name
      rescue Exception => error
        # module author forgot to define method or forgot to subclass Msf::Module
      else
        rank = Mdm::Module::Rank.where(name: name).first
        module_class.rank = rank
      ensure
        module_class.save
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

  def validation_proxy_class
    Metasploit::Framework::Module::Ancestor::MetasploitModule::ValidationProxy
  end
end
