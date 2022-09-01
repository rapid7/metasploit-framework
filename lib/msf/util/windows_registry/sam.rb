module Msf
module Util
module WindowsRegistry

  #
  # This module include helpers for the SAM hive
  #
  module Sam

    # Returns the HashedBootKey from a given BootKey.
    #
    # @param boot_key [String] The BootKey
    # @return [String] The HashedBootKey or an empty string if the revision
    #   number is unknown
    def get_hboot_key(boot_key)
      qwerty = "!@#$%^&*()qwertyUIOPAzxcvbnmQQQQQQQQQQQQ)(*@&%\0"
      digits = "0123456789012345678901234567890123456789\0"

      _value_type, value_data = get_value('SAM\\Domains\\Account', 'F')
      revision = value_data[0x68, 4].unpack('V')[0]
      case revision
      when 1
        hash = Digest::MD5.new
        hash.update(value_data[0x70, 16] + qwerty + boot_key + digits)
        rc4 = OpenSSL::Cipher.new('rc4')
        rc4.decrypt
        rc4.key = hash.digest
        hboot_key = rc4.update(value_data[0x80, 32])
        hboot_key << rc4.final
        hboot_key
      when 2
        aes = OpenSSL::Cipher.new('aes-128-cbc')
        aes.decrypt
        aes.key = boot_key
        aes.padding = 0
        aes.iv = value_data[0x78, 16]
        aes.update(value_data[0x88, 16]) # we need only 16 bytes
      else
        elog("[Msf::Util::WindowsRegistry::Sam::get_hboot_key] Unknown hbootKey revision: #{revision}")
        ''.b
      end
    end

    # Returns the `Users` key information under HKLM\SAM\Domains\Account\Users.
    # This includes the RID, name and `V` value for each user.
    #
    # @return [Hash] A hash with the following structure:
    #   {
    #     <User RID>: { V: <V value>, Name: <User name> },
    #     ...
    #   }
    def get_user_keys
      users = {}
      users_key = 'SAM\\Domains\\Account\\Users'
      rids = enum_key(users_key)
      if rids
        rids.delete('Names')

        rids.each do |rid|
          _value_type, value_data = get_value("#{users_key}\\#{rid}", 'V')
          users[rid.to_i(16)] ||= {}
          users[rid.to_i(16)][:V] = value_data

          # Attempt to get Hints
          _value_type, value_data = get_value("#{users_key}\\#{rid}", 'UserPasswordHint')
          next unless value_data

          users[rid.to_i(16)][:UserPasswordHint] =
            value_data.dup.force_encoding(::Encoding::UTF_16LE).encode(::Encoding::UTF_8).strip
        end
      end

      # Retrieve the user names for each RID
      # TODO: use a proper structure to do this, since the user names are included in V data
      names = enum_key("#{users_key}\\Names")
      if names
        names.each do |name|
          value_type, _value_data = get_value("#{users_key}\\Names\\#{name}", '')
          users[value_type] ||= {}
          # Apparently, key names are ISO-8859-1 encoded
          users[value_type][:Name] = name.dup.force_encoding(::Encoding::ISO_8859_1).encode(::Encoding::UTF_8)
        end
      end

      users
    end
  end

end
end
end

