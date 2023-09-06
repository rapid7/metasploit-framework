require 'ruby_smb'

module Msf
module Util
module WindowsRegistry

  #
  # This module include helpers for the SECURITY hive
  #
  module Security

    include Msf::Util::WindowsCryptoHelpers

    # All of these structures were taken from Impacket secretsdump.py
    class CacheData < BinData::Record
      mandatory_parameter :user_name_length
      mandatory_parameter :domain_name_length
      mandatory_parameter :dns_domain_name_length
      mandatory_parameter :upn_length
      mandatory_parameter :effective_name_length
      mandatory_parameter :full_name_length
      mandatory_parameter :logon_script_length
      mandatory_parameter :profile_path_length
      mandatory_parameter :home_directory_length
      mandatory_parameter :home_directory_drive_length
      mandatory_parameter :group_count
      mandatory_parameter :logon_domain_name_length

      endian :little

      string   :enc_hash, length: 16
      string   :unknown, length: 56
      string16 :username, length: -> { user_name_length }, byte_align: 4
      string16 :domain_name, length: -> { domain_name_length }, byte_align: 4
      string16 :dns_domain_name, length: -> { dns_domain_name_length }, byte_align: 4
      string16 :upn, length: -> { upn_length }, byte_align: 4
      string16 :effective_name, length: -> { effective_name_length }, byte_align: 4
      string16 :full_name, length: -> { full_name_length }, byte_align: 4
      string16 :logon_script, length: -> { logon_script_length }, byte_align: 4
      string16 :profile_path, length: -> { profile_path_length }, byte_align: 4
      string16 :home_directory, length: -> { home_directory_length }, byte_align: 4
      string16 :home_directory_drive, length: -> { home_directory_drive_length }, byte_align: 4
      array    :groups, initial_length: -> { group_count }, byte_align: 4 do
        uint32 :relative_id
        uint32 :attributes
      end
      string16 :logon_domain_name, length: -> { logon_domain_name_length }, byte_align: 4
    end

    class CacheEntry < BinData::Record
      endian :little

      uint16    :user_name_length
      uint16    :domain_name_length
      uint16    :effective_name_length
      uint16    :full_name_length
      uint16    :logon_script_length
      uint16    :profile_path_length
      uint16    :home_directory_length
      uint16    :home_directory_drive_length
      uint32    :user_id
      uint32    :primary_group_id
      uint32    :group_count
      uint16    :logon_domain_name_length
      uint16    :logon_domain_id_length
      file_time :last_access
      uint32    :revision
      uint32    :sid_count
      uint16    :valid
      uint16    :iteration_count
      uint32    :sif_length
      uint32    :logon_package
      uint16    :dns_domain_name_length
      uint16    :upn_length
      string    :iv, length: 16
      string    :ch, length: 16
      array     :enc_data, type: :uint8, read_until: :eof
    end

    attr_accessor :lsa_vista_style

    # Retrieve the decrypted LSA secret key from a given BootKey. This also sets
    # the @lsa_vista_style attributes according to the registry keys found
    # under `HKLM\SECURTY\Policy`. If set to `true`, the system version is
    # Windows Vista and above, otherwise it is Windows XP or below.
    #
    # @param boot_key [String] The BootKey
    # @return [String] The decrypted LSA secret key
    def lsa_secret_key(boot_key)
      # vprint_status('Getting PolEKList...')
      _value_type, value_data = get_value('\\Policy\\PolEKList')
      if value_data
        # Vista or above system
        @lsa_vista_style = true

        lsa_key = decrypt_lsa_data(value_data, boot_key)
        lsa_key = lsa_key[68, 32] unless lsa_key.empty?
      else
        # vprint_status('Getting PolSecretEncryptionKey...')
        _value_type, value_data = get_value('\\Policy\\PolSecretEncryptionKey')
        # If that didn't work, then we're out of luck
        return nil if value_data.nil?

        # XP or below system
        @lsa_vista_style = false

        md5x = Digest::MD5.new
        md5x << boot_key
        1000.times do
          md5x << value_data[60, 16]
        end

        rc4 = OpenSSL::Cipher.new('rc4')
        rc4.decrypt
        rc4.key = md5x.digest
        lsa_key = rc4.update(value_data[12, 48])
        lsa_key << rc4.final
        lsa_key = lsa_key[0x10..0x1F]
      end

      lsa_key
    end

    # Returns the decrypted LSA secrets under HKLM\SECURTY\Policy\Secrets. For
    # this, the LSA secret key must be provided, which can be retrieved with
    # the #lsa_secret_key method.
    #
    # @param lsa_key [String] The LSA secret key
    # @return [Hash] A hash containing the LSA secrets.
    def lsa_secrets(lsa_key)
      keys = enum_key('\\Policy\\Secrets')
      return unless keys

      keys.delete('NL$Control')

      keys.each_with_object({}) do |key, lsa_secrets|
        # vprint_status("Looking into #{key}")
        _value_type, value_data = get_value("\\Policy\\Secrets\\#{key}\\CurrVal")
        encrypted_secret = value_data
        next unless encrypted_secret

        if @lsa_vista_style
          decrypted = decrypt_lsa_data(encrypted_secret, lsa_key)
          secret_size = decrypted[0, 4].unpack('L<').first
          secret = decrypted[16, secret_size]
        else
          encrypted_secret_size = encrypted_secret[0, 4].unpack('L<').first
          secret = decrypt_secret_data(encrypted_secret[(encrypted_secret.size - encrypted_secret_size)..-1], lsa_key)
        end
        lsa_secrets[key] = secret
      end
    end

    # Returns the decrypted NLKM secret key from
    # HKLM\SECURTY\Policy\Secrets\NL$KM\CurrVal. For this, the LSA secret key
    # must be provided, which can be retrieved with the #lsa_secret_key method.
    #
    # @param lsa_key [String] The LSA secret key
    # @return [String] The NLKM secret key
    def nlkm_secret_key(lsa_key)
      _value_type, value_data = get_value('\\Policy\\Secrets\\NL$KM\\CurrVal')
      return nil unless value_data

      if @lsa_vista_style
        nlkm_dec = decrypt_lsa_data(value_data, lsa_key)
      else
        value_data_size = value_data[0, 4].unpack('L<').first
        nlkm_dec = decrypt_secret_data(value_data[(value_data.size - value_data_size)..-1], lsa_key)
      end

      nlkm_dec
    end

    # This structure consolidates Cache data and information, as retrieved by the #cached_infos method
    CacheInfo = Struct.new(
      :name,
      :iteration_count,
      :real_iteration_count,
      :entry, # CacheEntry structure
      :data, # CacheData structure
      keyword_init: true
    )

    # Returns the decrypted Cache data and information from HKLM\Cache. For
    # this, the NLKM secret key must be provided, which can be retrieved with
    # the #nlkm_secret_key method.
    #
    # @param nlkm_key [String] The NLKM secret key
    # @return [Array] An array of CacheInfo structures containing the Cache information
    def cached_infos(nlkm_key)
      values = enum_values('\\Cache')
      unless values
        elog('[Msf::Util::WindowsRegistry::Sam::cached_hashes] No cashed entries')
        return
      end

      values.delete('NL$Control')

      iteration_count = nil
      if values.delete('NL$IterationCount')
        _value_type, value_data = reg_parser.get_value('\\Cache', 'NL$IterationCount')
        iteration_count = value_data.to_i
      end

      values.map do |value|
        _value_type, value_data = get_value('\\Cache', value)
        cache = CacheEntry.read(value_data)

        cache_info = CacheInfo.new(name: value, entry: cache)

        next cache_info unless cache.user_name_length > 0

        enc_data = cache.enc_data.map(&:chr).join
        if @lsa_vista_style
          dec_data = decrypt_aes(enc_data, nlkm_key[16...32], cache.iv)
        else
          dec_data = decrypt_hash(enc_data, nlkm_key, cache.iv)
        end

        params = cache.snapshot.to_h.select { |key, _v| key.to_s.end_with?('_length') }
        params[:group_count] = cache.group_count
        cache_data = CacheData.new(params).read(dec_data)
        cache_info.data = cache_data

        if @lsa_vista_style
          cache_info.iteration_count = iteration_count ? iteration_count : cache.iteration_count
          if (cache_info.iteration_count > 10240)
            cache_info.real_iteration_count = cache_info.iteration_count & 0xfffffc00
          else
            cache_info.real_iteration_count = cache_info.iteration_count * 1024
          end
        end

        cache_info
      end
    end

  end
end
end
end

