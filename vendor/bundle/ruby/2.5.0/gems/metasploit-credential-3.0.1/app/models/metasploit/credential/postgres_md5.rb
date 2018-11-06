# A {Metasploit::Credential::PasswordHash password hash} that can be {Metasploit::Credential::ReplayableHash replayed}
# to authenticate to PostgreSQL servers. It is composed of a hexadecimal string of 32 charachters prepended by the string
# 'md5'
class Metasploit::Credential::PostgresMD5 < Metasploit::Credential::ReplayableHash
  #
  # CONSTANTS
  #

  # Valid format for {Metasploit::Credential::Private#data}
  DATA_REGEXP = /md5([a-f0-9]{32})/

  #
  # Callbacks
  #

  before_validation :normalize_data

  #
  # Validations
  #

  validate :data_format

  private

  # Normalizes {#data} by making it all lowercase so that the unique validation and index on
  # ({Metasploit::Credential::Private#type}, {#data}) catches collision in a case-insensitive manner without the need
  # to use case-insensitive comparisons.
  def normalize_data
    if data
      self.data = data.downcase
    end
  end

  def data_format
    unless DATA_REGEXP.match(data)
      errors.add(:data, 'is not in Postgres MD5 Hash format')
    end
  end

  public

  Metasploit::Concern.run(self)

end