require 'msf/core/payloads'

class Metasploit::Framework::Module::Class::Load::Payload::Base < Metasploit::Framework::Module::Class::Load::Base
  #
  # Validations
  #

  validates :module_type,
            inclusion: {
                in: [
                    Metasploit::Model::Module::Type::PAYLOAD
                ]
            }

  #
  # Methods
  #

  # @!method payload_type
  #   The payload type of the {#module_class}.
  #
  #   @return [String] `'single'` or `'staged'`
  #   @return [nil] if {#module_class} is `nil`.
  delegate :payload_type,
           # allow nil to work with validation
           allow_nil: true,
           to: :module_class

  protected

  # Returns the given constant as payload child constants are already the {Msf::Payload} subclass.
  #
  # @param metasploit_class [Class<Msf::Payload>]
  # @return [Class<Msf::Payload>] `metasploit_class`
  def metasploit_class_from_child_constant(metasploit_class)
    metasploit_class
  end

  # {Msf::Payload} subclasses are stored in constants under `Msf::Payloads` to segregate them from the Classes
  # declared directly in `Metasploit::Model::Module::Ancestor#contents` for non-payloads.
  #
  # @return [Module] `Msf::Payloads`
  def self.parent_constant
    Msf::Payloads
  end
end