require 'msf/core/modules'

class Metasploit::Framework::Module::Class::Load::NonPayload < Metasploit::Framework::Module::Class::Load::Base
  #
  # Validations
  #

  validates :module_type,
            inclusion: {
                in: Metasploit::Model::Module::Type::NON_PAYLOAD
            }

  #
  # Methods
  #

  protected

  def metasploit_class_from_child_constant(namespace_module)
    metasploit_module = namespace_module.metasploit_module
    metasploit_module.each_metasploit_class.first
  end

  def self.parent_constant
    Msf::Modules
  end

  def relative_constant_name
    module_ancestor_partial_name_by_payload_type[nil]
  end
end