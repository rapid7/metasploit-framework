module Metasploit::Framework::Scoped::Logging
  include Metasploit::Framework::Module::Instance::Logging

  def log_scoped_error(scope, error)
    case scope
      when Metasploit::Model::Module::Instance
        module_instance = scope
      when Metasploit::Model::Module::Target
        module_instance = scope.module_instance
      else
        raise ArgumentError, "Can't extract Module::Instance from #{scope.class}"
    end

    log_module_instance_error(module_instance, error)
  end
end