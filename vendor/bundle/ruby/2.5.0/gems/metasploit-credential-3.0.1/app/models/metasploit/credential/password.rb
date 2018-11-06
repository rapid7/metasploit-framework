# A password.
class Metasploit::Credential::Password < Metasploit::Credential::Private
  #
  # Attribute
  #

  # @!attribute data
  #   @note May be blank as some services allow blank passwords, but still require a password.
  #
  #   A user enterable, plain-text password.
  #
  #   @return [String]

  Metasploit::Concern.run(self)
end
