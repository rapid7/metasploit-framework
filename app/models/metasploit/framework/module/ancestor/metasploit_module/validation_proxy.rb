class Metasploit::Framework::Module::Ancestor::MetasploitModule::ValidationProxy < Metasploit::Framework::ValidationProxy
  #
  # Validations
  #

  validate :usable

  #
  # Methods
  #

  def self.model_name
    ActiveModel::Name.new(Metasploit::Framework::Module::Ancestor::MetasploitModule)
  end

  private

  def usable
    unless is_usable
      errors.add(:base, :unusable)
    end
  end
end