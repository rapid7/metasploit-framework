# Error raised if a {Metasploit::Model} ActiveModel is invalid.
class Metasploit::Model::Invalid < Metasploit::Model::Error
  def initialize(model)
    @model = model

    errors = @model.errors.full_messages.join(', ')
    # Must be called model_invalid so it doesn't alias errors.messages.invalid
    translated_message = ::I18n.translate('metasploit.model.errors.messages.model_invalid', :errors => errors)
    super(translated_message)
  end

  attr_reader :model
end
