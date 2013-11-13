# Methods for more consistent logging of Module::Class error message.
module Metasploit::Framework::Module::Class::Logging
  # Location of this class and its ancestors.
  #
  # @return [String] contains module_class full_name and ancestor real_paths.
  def module_class_location(module_class)
    full_name = module_class.full_name

    ancestors = module_class.ancestors
    real_path_sentence = ancestors.map(&:real_path).sort.to_sentence
    ancestor_label = 'ancestor'.pluralize(ancestors.length)

    "module class (#{full_name}) composed of module #{ancestor_label} (#{real_path_sentence})"
  end
end