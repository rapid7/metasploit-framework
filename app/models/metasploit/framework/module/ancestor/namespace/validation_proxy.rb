class Metasploit::Framework::Module::Ancestor::Namespace::ValidationProxy < Metasploit::Framework::ValidationProxy
  #
  #
  # Validations
  #
  #

  #
  # Method Validations
  #

  validate :metasploit_module_valid

  #
  # Attribute Validations
  #

  validates :metasploit_module,
            presence: true
  validates :minimum_api_version,
            allow_nil: true,
            numericality: {
                less_than_or_equal_to: Msf::Framework::VersionAPI
            }
  validates :minimum_core_version,
            allow_nil: true,
            numericality: {
                less_than_or_equal_to: Msf::Framework::VersionCore
            }
  validates :module_ancestor_eval_exception,
            nil: true

  #
  # Methods
  #

  def self.model_name
    ActiveModel::Name.new(Metasploit::Framework::Module::Ancestor::Namespace)
  end

  private

  def metasploit_module_valid
    if metasploit_module and !metasploit_module.valid?
      errors.add(:metasploit_module, :invalid)
    end
  end
end