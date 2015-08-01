require 'rex/parser/ini'

module Rex
module Parser
  module WinSCP
    def read_and_parse_ini(filename)
      file = File.read(filename)
      return if file.to_s.empty?
      parse_ini(file)
    end

    def parse_protocol(fsprotocol)
      case fsprotocol.to_i
      when 5 then 'FTP'
      when 0 then 'SSH'
      else
        'Unknown'
      end
    end

    def parse_ini(file)
      results = []
      raise RuntimeError, 'No data to parse' if file.nil? || file.empty?

      ini = Rex::Parser::Ini.from_s(file)

      if ini['Configuration\\Security']
        # if a Master Password is in use we give up
        if ini['Configuration\\Security']['MasterPassword'].to_i == 1
          raise RuntimeError, 'Master Password Set, unable to recover saved passwords!'
        end
      end

      # Runs through each group in the ini file looking for all of the Sessions
      ini.each_key do |group|
        if group.include?('Sessions') && ini[group].has_key?('Password')
          # Decrypt our password, and report on results
          encrypted_password = ini[group]['Password']
          user = ini[group]['UserName']
          host = ini[group]['HostName']
          sname = parse_protocol(ini[group]['FSProtocol'])
          plaintext = decrypt_password(encrypted_password, "#{user}#{host}")

          results << {
            hostname: host,
            password: plaintext,
            portnumber: ini[group]['PortNumber'] || 22,
            username: user,
            protocol: sname
          }
        end
      end

      results
    end

    def decrypt_next_char
      pwalg_simple_magic = 0xA3
      pwalg_simple_string = "0123456789ABCDEF"

      # Decrypts the next character in the password sequence
      if @password.length > 0
        # Takes the first char from the encrypted password and finds its position in the
        # pre-defined string, then left shifts the returned index by 4 bits
        unpack1 = pwalg_simple_string.index(@password[0,1])
        unpack1 = unpack1 << 4

        # Takes the second char from the encrypted password and finds its position in the
        # pre-defined string
        unpack2 = pwalg_simple_string.index(@password[1,1])
        # Adds the two results, XORs against 0xA3, NOTs it and then ands it with 0xFF
        result= ~((unpack1+unpack2) ^ pwalg_simple_magic) & 0xff
        # Strips the first two chars off and returns our result
        @password = @password[2,@password.length]
        return result
      end
    end

    def decrypt_password(pwd, key)
      pwalg_simple_flag = 0xFF
      @password = pwd
      flag = decrypt_next_char()

      if flag == pwalg_simple_flag
        decrypt_next_char()
        length = decrypt_next_char()
      else
        length = flag
      end
      ldel = (decrypt_next_char())*2
      @password = @password[ldel,@password.length]

      result = ""
      length.times do
        result << decrypt_next_char().chr
      end

      if flag == pwalg_simple_flag
        result = result[key.length, result.length]
      end

      result
    end
  end
end
end
