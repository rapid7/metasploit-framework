module Metasploit::Framework::Scoped::Logging
  include Metasploit::Framework::Module::Instance::Logging

  def log_scoped_error(scope, error)
    module_instance = scope_module_instance(scope)

    log_module_instance_error(module_instance, error)
  end

  def scope_module_instance(scope)
    case scope
      when Metasploit::Model::Module::Instance
        scope
      when Metasploit::Model::Module::Target
        scope.module_instance
      else
        raise ArgumentError, "Can't extract Module::Instance from #{scope.class}"
    end
  end
end