require 'securerandom'
require 'pry-byebug'

module Rex::Proto::MsAdts
  class KeyCredential

    KEY_USAGE_NGC = 0x01
    KEY_USAGE_FIDO = 0x07
    KEY_USAGE_FIDO = 0x08

    def init(key_material, key_usage, last_logon_time, creation_time)
      self.key_material = key_material
      self.key_usage = key_usage

      calculate_raw_key_material

      self.key_approximate_last_logon_time_stamp
      self.key_creation_time = creation_time

      self.key_source = 0
      self.device_id = SecureRandom.uuid
      self.custom_key_information = "\x01\x00" # Version and flags
      sha256 = OpenSSL::Digest.new('SHA256')
      self.key_id = sha256.digest(self.raw_key_material.to_der)
    end

    # Creates a KeyCredentialStruct, including calculating the value for key_hash
    def to_struct
      result = KeyCredentialStruct.new
      add_entry(result, 3, self.raw_key_material)
      add_entry(result, 4, [self.key_usage].pack('C'))
      add_entry(result, 5, [self.key_source].pack('C'))
      add_entry(result, 6, self.device_id)
      add_entry(result, 7, self.custom_key_information)
      add_entry(result, 8, RubySMB::Field::FileTime.new(self.key_approximate_last_logon_time_stamp).to_binary_s)
      add_entry(result, 9, RubySMB::Field::FileTime.new(self.key_creation_time).to_binary_s)

      calculate_key_hash

      add_entry(result, 1, self.key_id, insert_at_end: false)
      add_entry(result, 2, self.key_hash, insert_at_end: false)
    end


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
      ft = get_entry(cred_struct, 8).unpack('Q')[0]
      obj.key_approximate_last_logon_time_stamp = RubySMB::Field::FileTime.new(ft).to_time
      ft = get_entry(cred_struct, 9).unpack('Q')[0]
      obj.key_creation_time = RubySMB::Field::FileTime.new(ft).to_time

      construct_cert_from_raw_material(obj)

      obj
    end

    # Properties
    attr_accessor :key_id # SHA256 hash of KeyMaterial
    attr_accessor :key_hash # SHA256 hash of all entries after this entry
    attr_accessor :key_material # Key material of the credential
    attr_accessor :raw_key_material # Key material of the credential
    attr_accessor :key_usage # Enumeration
    attr_accessor :key_source # Always KEY_SOURCE_AD (0)
    attr_accessor :device_id # Identifier for this credential
    attr_accessor :custom_key_information # Two bytes is fine: Version and Flags
    attr_accessor :key_approximate_last_logon_time_stamp # Approximate time this key was last used
    attr_accessor :key_creation_time # Approximate time this key was created

    def self.get_entry(struct, identifier)
      struct.credential_entries.each do |entry|
        if entry.identifier == identifier
          return entry.data
        end
      end
    end

    private

    def add_entry(struct, identifier, data, insert_at_end: true)
      entry = KeyCredentialEntryStruct.new
      entry.identifier = identifier
      entry.data = data
      entry.struct_length = data.length
      if insert_at_end
        struct.credential_entries.append(entry)
      else # Insert at start
        struct.credential_entries.insert(0, entry)
      end
    end

    # Sets self.key_hash based on the credential_entries value in the provided parameter
    # @param struct [KeyCredentialStruct] Its entries value should have only those required to calculate the key_hash value (no key_id or key_hash)
    def calculate_key_hash(struct)
        sha256 = OpenSSL::Digest.new('SHA256')
        self.key_hash = sha256.digest(struct.entries.to_binary_s)
    end

    # Sets self.raw_key_material, based on the key material, and the key usage
    def calculate_raw_key_material
      case self.key_usage
      when 
      end
    end

    def self.construct_cert_from_raw_material(obj)
      case obj.key_usage
      when 1
      end
    end
  end
end