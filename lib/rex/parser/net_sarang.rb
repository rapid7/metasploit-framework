
module Rex
  module Parser
    module NetSarang
      # @author Kali-Team
      class NetSarangCrypto
        attr_accessor :version
        attr_accessor :username
        attr_accessor :sid
        attr_accessor :master_password
        attr_accessor :key

        # This class implements encryption and decryption of NetSarang
        #
        # @param type [String] only Xshell or Xftp.
        # @param version [String] Specify version of session file. e.g.:5.3
        # @param username [String] Specify username. This parameter will be used if version > 5.2.
        # @param sid [String] Specify SID. This parameter will be used if version >= 5.1.
        # @option master_password [String] Specify user's master password.
        #
        # @return [Rex::Parser::NetSarang::NetSarangCrypto] The NetSarangCrypto object
        def initialize(type, version, username, sid, master_password = nil)
          self.version = version.to_f
          self.username = username
          self.sid = sid
          self.master_password = master_password
          md5 = OpenSSL::Digest.new('MD5')
          sha256 = OpenSSL::Digest.new('SHA256')
          if (self.version > 0) && (self.version < 5.1)
            self.key = (type == 'Xshell') ? md5.digest('!X@s#h$e%l^l&') : md5.digest('!X@s#c$e%l^l&')
          elsif (self.version >= 5.1) && (self.version <= 5.2)
            self.key = sha256.digest(self.sid)
          elsif (self.version > 5.2)
            if self.master_password.nil?
              self.key = sha256.digest(self.username + self.sid)
            else
              self.key = sha256.digest(self.master_password)
            end
          else
            raise 'Invalid argument: version'
          end
        end

        # Encrypt
        #
        # @param string [String]
        # @return [String] ciphertext
        def encrypt_string(string)
          cipher = Rex::Crypto.rc4(key, string)
          if (version < 5.1)
            return Rex::Text.encode_base64(cipher)
          else
            sha256 = OpenSSL::Digest.new('SHA256')
            checksum = sha256.digest(string)
            ciphertext = cipher
            return Rex::Text.encode_base64(ciphertext + checksum)
          end
        end

        # Decrypt
        #
        # @param string [String]
        # @return [String] plaintext failed return nil
        def decrypt_string(string)
          if (version < 5.1)
            return Rex::Crypto.rc4(key, Rex::Text.decode_base64(string))
          else
            data = Rex::Text.decode_base64(string)
            ciphertext = data[0, data.length - 0x20]
            plaintext = Rex::Crypto.rc4(key, ciphertext)
            if plaintext.is_utf8?
              return plaintext
            else
              return nil
            end
          end
        end
      end

      # parser xsh session file
      #
      # @param ini [String]
      # @return [version, host, port, username, password]
      def parser_xsh(file)
        ini = Rex::Parser::Ini.from_s(file)
        version = ini['SessionInfo']['Version']
        port = ini['CONNECTION']['Port']
        host = ini['CONNECTION']['Host']
        username = ini['CONNECTION:AUTHENTICATION']['UserName']
        password = ini['CONNECTION:AUTHENTICATION']['Password'] || nil
        [version, host, port, username, password]
      end

      # parser xfp session file
      #
      # @param ini [String]
      # @return [version, host, port, username, password]
      def parser_xfp(file)
        ini = Rex::Parser::Ini.from_s(file)
        version = ini['SessionInfo']['Version']
        port = ini['Connection']['Port']
        host = ini['Connection']['Host']
        username = ini['Connection']['UserName']
        password = ini['Connection']['Password']
        [version, host, port, username, password]
      end
    end
  end
end
