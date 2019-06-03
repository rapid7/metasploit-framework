# -*- coding: binary -*-

require 'openssl/ccm'
require 'metasm'

##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

module Rex
  module Parser
    ###
    #
    # This class parses the content of a Bitlocker partition file.
    # Author : Danil Bazin <danil.bazin[at]hsc.fr> @danilbaz
    #
    ###
    class BITLOCKER
      BLOCK_HEADER_SIZE = 64
      METADATA_HEADER_SIZE = 48

      ENTRY_TYPE_NONE  = 0x0000
      ENTRY_TYPE_VMK  = 0x0002
      ENTRY_TYPE_FVEK  = 0x0003
      ENTRY_TYPE_STARTUP_KEY  = 0x0006
      ENTRY_TYPE_DESC  = 0x0007
      ENTRY_TYPE_HEADER  = 0x000f

      VALUE_TYPE_ERASED = 0x0000
      VALUE_TYPE_KEY = 0x0001
      VALUE_TYPE_STRING = 0x0002
      VALUE_TYPE_STRETCH_KEY = 0x0003
      VALUE_TYPE_ENCRYPTED_KEY = 0x0005
      VALUE_TYPE_TPM = 0x0006
      VALUE_TYPE_VALIDATION = 0x0007
      VALUE_TYPE_VMK = 0x0008
      VALUE_TYPE_EXTERNAL_KEY = 0x0009
      VALUE_TYPE_UPDATE = 0x000a
      VALUE_TYPE_ERROR = 0x000b

      PROTECTION_TPM = 0x0100
      PROTECTION_CLEAR_KEY = 0x0000
      PROTECTION_STARTUP_KEY = 0x0200
      PROTECTION_RECOVERY_PASSWORD = 0x0800
      PROTECTION_PASSWORD = 0x2000

      def initialize(file_handler)
        @file_handler = file_handler
        volume_header = @file_handler.read(512)
        @fs_sign = volume_header[3, 8]
        unless @fs_sign == '-FVE-FS-'
          fail ArgumentError, 'File system signature does not match Bitlocker :
           #@fs_sign}, bitlocker not used', caller
        end
        @fve_offset = volume_header[176, 8].unpack('Q')[0]

        @file_handler.seek(@fve_offset)
        @fve_raw = @file_handler.read(4096)
        @encryption_methods = @fve_raw[BLOCK_HEADER_SIZE + 36, 4].unpack('V')[0]
        size = @fve_raw[BLOCK_HEADER_SIZE, 4].unpack('V')[0] -
               METADATA_HEADER_SIZE
        @metadata_entries = @fve_raw[BLOCK_HEADER_SIZE + METADATA_HEADER_SIZE,
                                     size]
        @version = @fve_raw[BLOCK_HEADER_SIZE + 4]
        @fve_metadata_entries = fve_entries(@metadata_entries)
        @vmk_entries_hash = vmk_entries
      end

      # Extract FVEK and prefix it with the encryption methods integer on
      # 2 bytes
      def fvek_from_recovery_password_dislocker(recoverykey)
        [@encryption_methods].pack('v') +
          fvek_from_recovery_password(recoverykey)
      end

      # stretch recovery key with all stretch key and try to decrypt all VMK
      # encrypted with a recovery key
      def vmk_from_recovery_password(recoverykey)
        recovery_keys_stretched = recovery_key_transformation(recoverykey)
        vmk_encrypted_in_recovery_password_list =  @vmk_entries_hash[
                                                   PROTECTION_RECOVERY_PASSWORD]
        vmk_recovery_password = ''
        vmk_encrypted_in_recovery_password_list.each do |vmk|
          vmk_encrypted = vmk[ENTRY_TYPE_NONE][VALUE_TYPE_ENCRYPTED_KEY][0]
          recovery_keys_stretched.each do |recovery_key|
            vmk_recovery_password = decrypt_aes_ccm_key(
            vmk_encrypted, recovery_key)
            break if vmk_recovery_password != ''
          end
          break if vmk_recovery_password != ''
        end
        if vmk_recovery_password == ''
          fail ArgumentError, 'Wrong decryption, bad recovery key?'
        end
        vmk_recovery_password
      end

      # Extract FVEK using the provided recovery key
      def fvek_from_recovery_password(recoverykey)
        vmk_recovery_password = vmk_from_recovery_password(recoverykey)
        fvek_encrypted = fvek_entries
        fvek = decrypt_aes_ccm_key(fvek_encrypted, vmk_recovery_password)
        fvek
      end

      def decrypt_aes_ccm_key(fve_entry, key)
        nonce = fve_entry[0, 12]
        mac = fve_entry[12, 16]
        encrypted_data = fve_entry[28..-1]
        ccm = OpenSSL::CCM.new('AES',  key, 16)
        decrypted_data = ccm.decrypt(encrypted_data + mac, nonce)
        decrypted_data[12..-1]
      end

      # Parse the metadata_entries and return a hashmap using the
      # following format:
      # metadata_entry_type => metadata_value_type => [fve_entry,...]
      def fve_entries(metadata_entries)
        offset_entry = 0
        entry_size = metadata_entries[0, 2].unpack('v')[0]
        result = Hash.new({})
        while entry_size != 0
          metadata_entry_type = metadata_entries[
                                offset_entry + 2, 2].unpack('v')[0]
          metadata_value_type = metadata_entries[
                                offset_entry + 4, 2].unpack('v')[0]
          metadata_entry = metadata_entries[offset_entry + 8, entry_size - 8]
          if result[metadata_entry_type] == {}
            result[metadata_entry_type] = { metadata_value_type => [
              metadata_entry] }
          else
            if result[metadata_entry_type][metadata_value_type].nil?
              result[metadata_entry_type][metadata_value_type] = [
                metadata_entry]
            else
              result[metadata_entry_type][metadata_value_type] += [
                metadata_entry]
            end
          end
          offset_entry += entry_size
          if metadata_entries[offset_entry, 2] != ''
            entry_size = metadata_entries[offset_entry, 2].unpack('v')[0]
          else
            entry_size = 0
          end
        end
        result
      end

      # Dummy strcpy to use with metasm and string asignement
      def strcpy(str_src, str_dst)
        (0..(str_src.length - 1)).each do |cpt|
          str_dst[cpt] = str_src[cpt].ord
        end
      end

      # stretch all the Recovery key and returns it
      def recovery_key_transformation(recoverykey)
        # recovery key stretching phase 1
        recovery_intermediate = recoverykey.split('-').map(&:to_i)
        recovery_intermediate.each do |n|
          n % 11 != 0 && (fail ArgumentError, 'Invalid recovery key')
        end
        recovery_intermediate =
                           recovery_intermediate.map { |a| (a / 11) }.pack('v*')

        # recovery key stretching phase 2
        recovery_keys = []
        cpu = Metasm.const_get('Ia32').new
        exe = Metasm.const_get('Shellcode').new(cpu)
        cp = Metasm::C::Parser.new(exe)
        bitlocker_struct_src = <<-EOS
          typedef struct {
          unsigned char updated_hash[32];
          unsigned char password_hash[32];
          unsigned char salt[16];
          unsigned long long int hash_count;
          } bitlocker_chain_hash_t;
        EOS
        cp.parse bitlocker_struct_src
        btl_struct = Metasm::C::AllocCStruct.new(cp, cp.find_c_struct(
                                                     'bitlocker_chain_hash_t'))
        vmk_protected_by_recovery_key = @vmk_entries_hash[
                                        PROTECTION_RECOVERY_PASSWORD]
        if vmk_protected_by_recovery_key.nil?
          fail ArgumentError, 'No recovery key on disk'
        end
        vmk_protected_by_recovery_key.each do |vmk_encrypted|
          vmk_encrypted_raw = vmk_encrypted[ENTRY_TYPE_NONE][
                              VALUE_TYPE_STRETCH_KEY][0]
          stretch_key_salt = vmk_encrypted_raw[4, 16]
          strcpy(Digest::SHA256.digest(recovery_intermediate),
                 btl_struct.password_hash)
          strcpy(stretch_key_salt, btl_struct.salt)
          btl_struct.hash_count = 0
          sha256 = Digest::SHA256.new
          btl_struct_raw = btl_struct.str
          btl_struct_hash_count_offset = btl_struct.struct.fldoffset[
                                         'hash_count']
          (1..0x100000).each do |c|
            updated_hash = sha256.digest(btl_struct_raw)
            btl_struct_raw = updated_hash + btl_struct_raw \
                             [btl_struct.updated_hash.sizeof..(
                             btl_struct_hash_count_offset - 1)] + [c].pack('Q')
            sha256.reset
          end
          recovery_keys += [btl_struct_raw[btl_struct.updated_hash.stroff,
                           btl_struct.updated_hash.sizeof]]
        end
        recovery_keys
      end

      # Return FVEK entry, encrypted with the VMK
      def fvek_entries
        @fve_metadata_entries[ENTRY_TYPE_FVEK][
          VALUE_TYPE_ENCRYPTED_KEY][ENTRY_TYPE_NONE]
      end

      # Produce a hash map using the following format:
      # PROTECTION_TYPE => [fve_entry, fve_entry...]
      def vmk_entries
        res = {}
        (@fve_metadata_entries[ENTRY_TYPE_VMK][VALUE_TYPE_VMK]).each do |vmk|
          protection_type = vmk[26, 2].unpack('v')[0]
          if res[protection_type].nil?
            res[protection_type] = [fve_entries(vmk[28..-1])]
          else
            res[protection_type] += [fve_entries(vmk[28..-1])]
          end
        end
        res
      end
    end
  end
end
