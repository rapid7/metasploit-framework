# A {Metasploit::Credential::PasswordHash password hash} that can be replayed to authenticate to additional services.
class Metasploit::Credential::ReplayableHash < Metasploit::Credential::PasswordHash
  #
  # Attributes
  #

  # @!attribute data
  #   A password hash that can be sent in place of a {Metasploit::Credential::Password#data password} to authenticate
  #   to a service.
  #
  #   @return [String]

  Metasploit::Concern.run(self)
end
