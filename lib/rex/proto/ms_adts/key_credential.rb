require 'securerandom'

module Rex::Proto::MsAdts
  class KeyCredential

    KEY_USAGE_NGC = 0x01
    KEY_USAGE_FIDO = 0x07
    KEY_USAGE_FEK = 0x08

    KEY_CREDENTIAL_VERSION_2 = 0x200
    DEFAULT_KEY_INFORMATION = "\x01\x00" # Version and flags

    def initialize
      self.key_source = 0
      self.device_id = SecureRandom.bytes(16)
      self.custom_key_information = DEFAULT_KEY_INFORMATION
    end

    # Set the key material for this credential object
    # @param public_key [OpenSSL::RSA::PKey] Public key used for authentication
    # @param key_usage [Enumeration] From the KEY_USAGE constants in this class
    def set_key(public_key, key_usage)
      self.public_key = public_key
      self.key_usage = key_usage

      calculate_raw_key_material
    end

    # Set the time data for this credential object
    # @param last_logon_time [Time] Last time this credential was used to log on
    # @param creation_time [Time] Time that this key was created
    def set_times(last_logon_time, creation_time)
      self.key_approximate_last_logon_time_stamp = last_logon_time
      self.key_approximate_last_logon_time_stamp_raw = RubySMB::Field::FileTime.new(self.key_approximate_last_logon_time_stamp).to_binary_s
      self.key_creation_time = creation_time
      self.key_creation_time_raw = RubySMB::Field::FileTime.new(self.key_creation_time).to_binary_s
    end

    # Creates a KeyCredentialStruct, including calculating the value for key_hash
    # @return [KeyCredentialStruct] A structured object able to be converted to binary and sent to a DCc
    def to_struct
      result = KeyCredentialStruct.new
      result.version = KEY_CREDENTIAL_VERSION_2
      add_entry(result, 3, self.raw_key_material)
      add_entry(result, 4, [self.key_usage].pack('C'))
      add_entry(result, 5, [self.key_source].pack('C'))
      add_entry(result, 6, self.device_id)
      add_entry(result, 7, self.custom_key_information)
      add_entry(result, 8, self.key_approximate_last_logon_time_stamp_raw)
      add_entry(result, 9, self.key_creation_time_raw)

      calculate_key_hash(result)

      add_entry(result, 2, self.key_hash, insert_at_end: false)
      add_entry(result, 1, self.key_id, insert_at_end: false)

      result
    end

    # Construct a KeyCredential object from a KeyCredentialStruct (likely received from a Domain Controller)
    # @param cred_struct [KeyCredentialStruct] Credential structure to convert
    def self.from_struct(cred_struct)
      obj = KeyCredential.new
      obj.key_id = get_entry(cred_struct, 1)
      obj.key_hash = get_entry(cred_struct, 2)
      obj.raw_key_material = get_entry(cred_struct, 3)
      abc = get_entry(cred_struct, 4)
      obj.key_usage = get_entry(cred_struct, 4).unpack('C')[0]
      obj.key_source = get_entry(cred_struct, 5).unpack('C')[0]
      obj.device_id = get_entry(cred_struct, 6)
      obj.custom_key_information = get_entry(cred_struct, 7)
      ft = get_entry(cred_struct, 8)
      obj.key_approximate_last_logon_time_stamp_raw = ft
      obj.key_approximate_last_logon_time_stamp = RubySMB::Field::FileTime.new(ft.unpack('Q')[0]).to_time
      ft = get_entry(cred_struct, 9)
      obj.key_creation_time_raw = ft
      obj.key_creation_time = RubySMB::Field::FileTime.new(ft.unpack('Q')[0]).to_time

      construct_public_key_from_raw_material(obj)

      obj
    end

    # Properties
    attr_accessor :key_id # SHA256 hash of KeyMaterial
    attr_accessor :key_hash # SHA256 hash of all entries after this entry
    attr_accessor :public_key # The public_key applied to the account
    attr_accessor :raw_key_material # Key material of the credential, in bytes
    attr_accessor :key_usage # Enumeration
    attr_accessor :key_source # Always KEY_SOURCE_AD (0)
    attr_accessor :device_id # Identifier for this credential
    attr_accessor :custom_key_information # Two bytes is fine: Version and Flags
    attr_accessor :key_approximate_last_logon_time_stamp_raw # Raw bytes for approximate time this key was last used
    attr_accessor :key_creation_time_raw # Raw bytes for approximate time this key was created
    attr_accessor :key_approximate_last_logon_time_stamp # Approximate time this key was last used
    attr_accessor :key_creation_time # Approximate time this key was created

    # Find the entry with the given identifier
    # @param struct [KeyCredentialStruct] Structure containing entries to search through
    # @param struct [Integer] Identifier to search for, from https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/a99409ea-4982-4f72-b7ef-8596013a36c7
    # @return [String] The data associated with this identifier, or nil if not found
    def self.get_entry(struct, identifier)
      struct.credential_entries.each do |entry|
        if entry.identifier == identifier
          return entry.data
        end
      end
    end

    private

    # Create a KeyCredentialEntryStruct from the provided data, and insert it in to the provided structure
    # @param struct [KeyCredentialStruct] Structure to insert the resulting entry into
    # @param identifier [Integer] Identifier associated with this entry, from https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/a99409ea-4982-4f72-b7ef-8596013a36c7
    # @param data [String] The data to create an entry from
    # @param insert_at_end [Boolean] Whether to insert the new entry at the end of the credential_entries; otherwise will insert at start
    def add_entry(struct, identifier, data, insert_at_end: true)
      entry = KeyCredentialEntryStruct.new
      entry.identifier = identifier
      entry.data = data
      entry.struct_length = data.length
      if insert_at_end
        struct.credential_entries.insert(struct.credential_entries.length, entry)
      else # Insert at start
        struct.credential_entries.insert(0, entry)
      end
    end

    def self.int_to_bytes(num)
      str = num.to_s(16).rjust(2, '0')

      [str].pack('H*')
    end

    def self.bytes_to_int(num)
      num.unpack('H*')[0].to_i(16)
    end

    # Sets self.key_hash based on the credential_entries value in the provided parameter
    # @param struct [KeyCredentialStruct] Its credential_entries value should have only those required to calculate the key_hash value (no key_id or key_hash)
    def calculate_key_hash(struct)
        sha256 = OpenSSL::Digest.new('SHA256')
        self.key_hash = sha256.digest(struct.credential_entries.to_binary_s)
    end

    # Sets self.raw_key_material, based on the key material, and the key usage
    def calculate_raw_key_material
      case self.key_usage
      when KEY_USAGE_NGC
        result = Rex::Proto::BcryptPublicKey.new
        result.magic = Rex::Proto::BcryptPublicKey::MAGIC
        result.key_length = self.public_key.n.num_bits
        n = self.class.int_to_bytes(self.public_key.n)
        e = self.class.int_to_bytes(self.public_key.e)
        result.exponent = e
        result.modulus = n
        result.prime1 = ''
        result.prime2 = ''
        self.raw_key_material = result.to_binary_s
      else
        # Unknown key type
        return
      end
      sha256 = OpenSSL::Digest.new('SHA256')
      self.key_id = sha256.digest(self.raw_key_material)
    end

    # Parse the object's raw key material field into a OpenSSL::RSA::PKey object
    # @param obj [KeyCredential] The object for which to parse the key
    def self.construct_public_key_from_raw_material(obj)
      case obj.key_usage
      when KEY_USAGE_NGC
        if obj.raw_key_material.start_with?([Rex::Proto::BcryptPublicKey::MAGIC].pack('I'))
          result = Rex::Proto::BcryptPublicKey.read(obj.raw_key_material)
          exponent = OpenSSL::ASN1::Integer.new(bytes_to_int(result.exponent))
          modulus = OpenSSL::ASN1::Integer.new(bytes_to_int(result.modulus))
          # OpenSSL's API has changed over time - constructing from DER has been consistent
          data_sequence = OpenSSL::ASN1::Sequence([modulus, exponent])
          key = OpenSSL::PKey::RSA.new(data_sequence.to_der)
          obj.public_key = key
        end
      end
    end
  end
end