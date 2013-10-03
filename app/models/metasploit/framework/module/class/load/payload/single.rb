class Metasploit::Framework::Module::Class::Load::Payload::Single < Metasploit::Framework::Module::Class::Load::Payload::Base
  #
  # Validations
  #

  validates :payload_type,
            inclusion: {
                in: [
                    'single'
                ]
            }

  #
  # Methods
  #

  protected

  def relative_constant_name
    module_ancestor_partial_name_by_payload_type['single']
  end
end