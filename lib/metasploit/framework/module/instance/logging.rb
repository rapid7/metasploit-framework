module Metasploit::Framework::Module::Instance::Logging
  include Metasploit::Framework::Module::Class::Logging

  def log_module_instance_error(module_instance, error)
    location = module_instance_location(module_instance)

    elog(
        "In #{location}:\n" \
          "#{error.class}: #{error}:\n" \
          "#{error.backtrace.join("\n")}"
    )
  end

  def module_instance_location(module_instance)
    module_class = module_instance.module_class
    module_class_location(module_class)
  end

  def rescue_module_instance_error(module_instance, error_class)
    begin
      yield
    rescue error_class => error
      log_module_instance_error(module_instance, error)
    end
  end
end