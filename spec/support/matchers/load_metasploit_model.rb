RSpec::Matchers.define :load_metasploit_module do
  match do |module_ancestor_load|
    module_ancestor_load.valid?
  end

  failure_message_for_should do |module_ancestor_load|
    lines = []
    lines << "#{module_ancestor_load.class} expected to be valid " \
             "and load #{module_ancestor_load.module_ancestor.full_name}, " \
             "but had errors:"
    lines.concat module_ancestor_load.errors.full_messages

    module_ancestor_errors = module_ancestor_load.module_ancestor.errors

    unless module_ancestor_errors.empty?
      lines << ''
      lines << "module_ancestor had errors:"
      lines.concat module_ancestor_errors.full_messages
    end

    namespace_module_errors = module_ancestor_load.namespace_module_errors

    unless namespace_module_errors.blank?
      lines << ''
      lines << "namespace_module had errors:"
      lines.concat namespace_module_errors.full_messages
    end

    lines.join("\n")
  end

  description do
    'load metasploit_model'
  end
end