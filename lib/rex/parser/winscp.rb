require 'rex/parser/ini'

module Rex
module Parser
  module WinSCP
    PWDALG_SIMPLE_MAGIC = 0xA3
    PWDALG_SIMPLE_FLAG = 0xFF

    def read_and_parse_ini(filename)
      file = File.read(filename)
      return if file.to_s.empty?
      parse_ini(file)
    end

    def parse_protocol(fsprotocol)
      return 'Unknown' if fsprotocol.nil?

      case fsprotocol
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
        if ini['Configuration\\Security']['UseMasterPassword'].to_i == 1
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
          sname = parse_protocol(ini[group]['FSProtocol'].to_i)
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

    # Decrypts the next character in the password sequence
    def decrypt_next_char(pwd)
      if pwd.nil? || pwd.length <= 0
        return 0, pwd
      end

      # Takes the first char from the encrypted password and then left shifts the returned index by 4 bits
      a = pwd[0].hex << 4

      # Takes the second char from the encrypted password
      b = pwd[1].hex

      # Adds the two results, XORs against 0xA3, NOTs it and then ANDs it with 0xFF
      result = ~((a + b) ^ PWDALG_SIMPLE_MAGIC) & PWDALG_SIMPLE_FLAG

      # Strips the first two chars off and returns our result
      return result, pwd[2..-1]
    end

    def decrypt_password(pwd, key)
      flag, pwd = decrypt_next_char(pwd)

      if flag == PWDALG_SIMPLE_FLAG
        _, pwd = decrypt_next_char(pwd)
        length, pwd = decrypt_next_char(pwd)
      else
        length = flag
      end

      del, pwd = decrypt_next_char(pwd)
      pwd = pwd[del*2..-1]

      result = ""
      length.times do
        r, pwd = decrypt_next_char(pwd)
        result << r.chr
      end

      if flag == PWDALG_SIMPLE_FLAG
        result = result[key.length..-1]
      end

      result
    end
  end
end
end
