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
      cache_rank(module_class)
      module_class.save
    end
  end

  # @note `module_class` is not saved after `Metasploit::Model::Module::Class#rank` is set.  Use {#cache} to set rank
  #   and save.
  #
  # Caches `#rank_name` in `module_class` `Metasploit::Model::Module::Class#rank`.
  #
  # @param module_class [Metasploit::Model::Module::Class] module class to which to write rank metadata.
  # @return [void]
  def cache_rank(module_class)
    ActiveRecord::Base.connection_pool.with_connection do
      begin
        name = self.rank_name
      rescue Exception
        # module author forgot to define method or forgot to subclass Msf::Module
      else
        rank = Mdm::Module::Rank.where(name: name).first
        module_class.rank = rank
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
