module Metasploit::Framework::Module::Ancestor::MetasploitModule
  include Metasploit::Framework::ProxiedValidation

  #
  # Methods
  #

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
