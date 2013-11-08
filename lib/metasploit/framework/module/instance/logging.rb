module Metasploit::Framework::Module::Instance::Logging
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
    full_name = module_class.full_name

    ancestors = module_class.ancestors
    real_path_sentence = ancestors.map(&:real_path).to_sentence
    ancestor_label = 'ancestor'.pluralize(ancestors.length)

    "module class (#{full_name}) composed of module #{ancestor_label} (#{real_path_sentence})"
  end

  def rescue_module_instance_error(module_instance, error_class)
    begin
      yield
    rescue error_class => error
      log_module_instance_error(module_instance, error)
    end
  end
end