module Rex::Proto::MsAdts
  class KeyCredential

    KEY_USAGE_NGC = 0x01
    KEY_USAGE_FIDO = 0x07
    KEY_USAGE_FEK = 0x08

    KEY_CREDENTIAL_VERSION_2 = 0x200
    DEFAULT_KEY_INFORMATION = "\x01\x00" # Version and flags

    def initialize
      self.key_source = 0
      self.device_id = Rex::Proto::MsDtyp::MsDtypGuid.new
      self.device_id.set(Rex::Proto::MsDtyp::MsDtypGuid.random_generate)
      self.custom_key_information = DEFAULT_KEY_INFORMATION
    end

    # Set the key material for this credential object
    # @param public_key [OpenSSL::PKey::RSA] Public key used for authentication
    # @param key_usage [Enumeration] From the KEY_USAGE constants in this class
    def set_key(public_key, key_usage)
      self.key_usage = key_usage

      case self.key_usage
      when KEY_USAGE_NGC
        result = Rex::Proto::BcryptPublicKey.new
        result.key_length = public_key.n.num_bits
        n = self.class.int_to_bytes(public_key.n)
        e = self.class.int_to_bytes(public_key.e)
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

    # Approximate time this key was last used
    # @return [Time] Approximate time this key was last used
    def key_approximate_last_logon_time
      ft = key_approximate_last_logon_time_raw
      RubySMB::Field::FileTime.new(ft.unpack('Q')[0]).to_time
    end

    # Set the approximate last logon time for this credential object
    # @param time [Time] Last time this credential was used to log on
    def key_approximate_last_logon_time=(time)
      self.key_approximate_last_logon_time_raw = RubySMB::Field::FileTime.new(time).to_binary_s
    end

    # Approximate time this key was created
    # @return [Time] Approximate time this key was created
    def key_creation_time
      ft = key_creation_time_raw
      RubySMB::Field::FileTime.new(ft.unpack('Q')[0]).to_time
    end

    # Set the creation time for this credential object
    # @param time [Time] Time that this key was created
    def key_creation_time=(time)
      self.key_creation_time_raw = RubySMB::Field::FileTime.new(time).to_binary_s
    end

    # Creates a MsAdtsKeyCredentialStruct, including calculating the value for key_hash
    # @return [MsAdtsKeyCredentialStruct] A structured object able to be converted to binary and sent to a DCc
    def to_struct
      result = MsAdtsKeyCredentialStruct.new
      result.version = KEY_CREDENTIAL_VERSION_2
      add_entry(result, 3, self.raw_key_material)
      add_entry(result, 4, [self.key_usage].pack('C'))
      add_entry(result, 5, [self.key_source].pack('C'))
      add_entry(result, 6, self.device_id.to_binary_s)
      add_entry(result, 7, self.custom_key_information)
      add_entry(result, 8, self.key_approximate_last_logon_time_raw)
      add_entry(result, 9, self.key_creation_time_raw)

      calculate_key_hash(result)

      add_entry(result, 2, self.key_hash, insert_at_end: false)
      add_entry(result, 1, self.key_id, insert_at_end: false)

      result
    end

    # Construct a KeyCredential object from a MsAdtsKeyCredentialStruct (likely received from a Domain Controller)
    # @param cred_struct [MsAdtsKeyCredentialStruct] Credential structure to convert
    def self.from_struct(cred_struct)
      obj = KeyCredential.new
      obj.key_id = get_entry(cred_struct, 1)
      obj.key_hash = get_entry(cred_struct, 2)
      obj.raw_key_material = get_entry(cred_struct, 3)
      obj.key_usage = get_entry(cred_struct, 4).unpack('C')[0]
      obj.key_source = get_entry(cred_struct, 5).unpack('C')[0]
      obj.device_id = Rex::Proto::MsDtyp::MsDtypGuid.read(get_entry(cred_struct, 6))
      obj.custom_key_information = get_entry(cred_struct, 7)
      ft = get_entry(cred_struct, 8)
      obj.key_approximate_last_logon_time_raw = ft
      ft = get_entry(cred_struct, 9)
      obj.key_creation_time_raw = ft

      obj
    end

    # Properties
    attr_accessor :key_id # SHA256 hash of KeyMaterial
    attr_accessor :key_hash # SHA256 hash of all entries after this entry
    attr_accessor :raw_key_material # Key material of the credential, in bytes
    attr_accessor :key_usage # Enumeration
    attr_accessor :key_source # Always KEY_SOURCE_AD (0)
    attr_accessor :device_id # [MsDtypGuid] Identifier for this credential
    attr_accessor :custom_key_information # Two bytes is fine: Version and Flags
    attr_accessor :key_approximate_last_logon_time_raw # Raw bytes for approximate time this key was last used
    attr_accessor :key_creation_time_raw # Raw bytes for approximate time this key was created

    # Find the entry with the given identifier
    # @param struct [MsAdtsKeyCredentialStruct] Structure containing entries to search through
    # @param struct [Integer] Identifier to search for, from https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/a99409ea-4982-4f72-b7ef-8596013a36c7
    # @return [String] The data associated with this identifier, or nil if not found
    def self.get_entry(struct, identifier)
      struct.credential_entries.each do |entry|
        if entry.identifier == identifier
          return entry.data
        end
      end
    end

    # Parse the object's raw key material field into a OpenSSL::PKey::RSA object
    # @param obj [KeyCredential] The object for which to parse the key
    def public_key
      case key_usage
      when KEY_USAGE_NGC
        if raw_key_material.start_with?([Rex::Proto::BcryptPublicKey::MAGIC].pack('I'))
          result = Rex::Proto::BcryptPublicKey.read(raw_key_material)
          exponent = OpenSSL::ASN1::Integer.new(bytes_to_int(result.exponent))
          modulus = OpenSSL::ASN1::Integer.new(bytes_to_int(result.modulus))
          # OpenSSL's API has changed over time - constructing from DER has been consistent
          data_sequence = OpenSSL::ASN1::Sequence([modulus, exponent])

          OpenSSL::PKey::RSA.new(data_sequence.to_der)
        end
      end
    end

    private

    # Create a MsAdtsKeyCredentialEntryStruct from the provided data, and insert it in to the provided structure
    # @param struct [MsAdtsKeyCredentialStruct] Structure to insert the resulting entry into
    # @param identifier [Integer] Identifier associated with this entry, from https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/a99409ea-4982-4f72-b7ef-8596013a36c7
    # @param data [String] The data to create an entry from
    # @param insert_at_end [Boolean] Whether to insert the new entry at the end of the credential_entries; otherwise will insert at start
    def add_entry(struct, identifier, data, insert_at_end: true)
      entry = MsAdtsKeyCredentialEntryStruct.new
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

    def bytes_to_int(num)
      num.unpack('H*')[0].to_i(16)
    end

    # Sets self.key_hash based on the credential_entries value in the provided parameter
    # @param struct [MsAdtsKeyCredentialStruct] Its credential_entries value should have only those required to calculate the key_hash value (no key_id or key_hash)
    def calculate_key_hash(struct)
      sha256 = OpenSSL::Digest.new('SHA256')
      self.key_hash = sha256.digest(struct.credential_entries.to_binary_s)
    end
  end
end