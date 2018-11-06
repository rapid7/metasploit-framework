require 'net/ntlm'

# A {Metasploit::Credential::PasswordHash password hash} that can be {Metasploit::Credential::ReplayableHash replayed}
# to authenticate to SMB.  It is composed of two hash hex digests (where the hash bytes are printed as a
# hexadecimal string where 2 characters represent a byte of the original hash with the high nibble first): (1)
# {lan_manager_hex_digest_from_password_data the LAN Manager hash's hex digest} and (2)
# {nt_lan_manager_hex_digest_from_password_data the NTLM hash's hex digest}.
class Metasploit::Credential::NTLMHash < Metasploit::Credential::ReplayableHash
  #
  # CONSTANTS
  #

  # If the password data exceeds 14 characters, then a LanManager hash cannot be calculated and then the effective
  # password data is '' when calculating the {lan_manager_hex_digest_from_password_data}.
  #
  # @see https://en.wikipedia.org/wiki/LM_hash#Algorithm
  LAN_MANAGER_MAX_CHARACTERS = 14
  # Valid format for LAN Manager hex digest portion of {#data}: 32 lowercase hexadecimal characters.
  LAN_MANAGER_HEX_DIGEST_REGEXP = /[0-9a-f]{32}/
  # Valid format for NT LAN Manager hex digest portion of {#data}: 32 lowercase hexadecimal characters.
  NT_LAN_MANAGER_HEX_DIGEST_REGEXP = /[0-9a-f]{32}/
  # Valid format for {#data} composed of `'<LAN Manager hex digest>:<NT LAN Manager hex digest>'`.
  DATA_REGEXP = /\A#{LAN_MANAGER_HEX_DIGEST_REGEXP}:#{NT_LAN_MANAGER_HEX_DIGEST_REGEXP}\z/

  # Value of {lan_manager_hex_digest_from_password_data} when the effective password is blank because it exceeds
  # {LAN_MANAGER_MAX_CHARACTERS}
  BLANK_LM_HASH = 'aad3b435b51404eeaad3b435b51404ee'
  # Value of {nt_lan_manager_hex_digest_from_password_data} when the password is blank.
  BLANK_NT_HASH = '31d6cfe0d16ae931b73c59d7e0c089c0'

  #
  # Attributes
  #

  # @!attribute data
  #   The LAN Manager hex digest combined with the NT LAN Manager hex digest.
  #
  #   @return [String] `'<LAN Manager hex digest>:<NT LAN Manager hex digest>'`

  #
  # Callbacks
  #

  before_validation :normalize_data

  #
  # Validations
  #

  validate :data_format

  #
  # Class Methods
  #

  # Converts {Metasploit::Credential::Password#data} to {#data}.  Handles passwords over the LanManager limit of 14
  # characters by treating them as '' for the LanManager Hash calculation, but their actual value for the NTLM hash
  # calculation.
  #
  # @return (see #data)
  def self.data_from_password_data(password_data)
    hex_digests = ['', 'nt_'].collect do |prefix|
      send("#{prefix}lan_manager_hex_digest_from_password_data", password_data)
    end

    hex_digests.join(':')
  end

  # Converts a buffer containing `hash` bytes to a String containing the hex digest of that `hash`.
  #
  # @param hash [String] a buffer of bytes
  # @return [String] a string where every 2 hexadecimal characters represents a byte in the original hash buffer.
  def self.hex_digest(hash)
    hash.unpack('H*').first
  end

  # Converts {Metasploit::Credential::Password#data} to an LanManager Hash hex digest.  Handles passwords over the
  # LanManager limit of 14 characters by treating them as '' for the LanManager Hash calculation.
  #
  # @param password_data [String] the plain text password
  # @return [String] a 32 character hexadecimal string
  def self.lan_manager_hex_digest_from_password_data(password_data)
    effective_password_data = password_data

    if password_data.length > LAN_MANAGER_MAX_CHARACTERS
      effective_password_data = ''
    end

    lm_hash = Net::NTLM.lm_hash(effective_password_data)
    hex_digest(lm_hash)
  end

  # Converts {Metasploit::Credential::Password#data} to a NTLM Hash hex digest.
  #
  # @param password_data [String] the plain text password
  # @return [String] a 32 character hexadecimal string
  def self.nt_lan_manager_hex_digest_from_password_data(password_data)
    ntlm_hash = Net::NTLM.ntlm_hash(password_data)
    hex_digest(ntlm_hash)
  end

  #
  # Instance Methods
  #

  def blank_password?
    self.data.include? "#{BLANK_LM_HASH}:#{BLANK_NT_HASH}"
  end

  def lm_hash_present?
    !self.data.start_with? BLANK_LM_HASH
  end

  private

  # Normalizes {#data} by making it all lowercase so that the unique validation and index on
  # ({Metasploit::Credential::Private#type}, {#data}) catches collision in a case-insensitive manner without the need
  # to use case-insensitive comparisons.
  def normalize_data
    if data
      self.data = data.downcase
    end
  end

  # Validates that {#data} is in the NTLM data format of <LAN Manager hex digest>:<NT LAN Manager hex digest>. Both hex
  # digests are 32 lowercase hexadecimal characters.
  def data_format
    unless DATA_REGEXP.match(data)
      errors.add(:data, :format)
    end
  end

  public

  Metasploit::Concern.run(self)
end
