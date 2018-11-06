# The cryptographic hash of a {Metasploit::Credential::Password password}.
class Metasploit::Credential::PasswordHash < Metasploit::Credential::Private
  #
  # Attributes
  #

  # @!attribute data
  #   @note Unlike {Metasploit::Credential::Private#data}, {#data} cannot be blank because blank hashes have no meaning.
  #
  #   The cryptographic hash of {Metasploit::Credential::Password#data}.
  #
  #   @return [String]

  #
  # Validations
  #

  validates :data,
            presence: true

  Metasploit::Concern.run(self)
end
