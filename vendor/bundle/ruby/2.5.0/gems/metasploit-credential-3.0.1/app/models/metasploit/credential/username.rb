# A public credential in the form of a Username.
class Metasploit::Credential::Username < Metasploit::Credential::Public

  #
  # Validations
  #

  validates :username,
            presence: true,
            uniqueness: true

  Metasploit::Concern.run(self)
end