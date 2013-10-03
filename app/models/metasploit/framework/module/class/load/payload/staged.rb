class Metasploit::Framework::Module::Class::Load::Payload::Staged < Metasploit::Framework::Module::Class::Load::Payload::Base
  #
  # Validations
  #

  validates :payload_type,
            inclusion: {
                in: [
                    'staged'
                ]
            }

  #
  # Methods
  #

  protected

  def relative_constant_name
    "#{module_ancestor_partial_name_by_payload_type['stage']}StagedBy#{module_ancestor_partial_name_by_payload_type['stager']}"
  end
end