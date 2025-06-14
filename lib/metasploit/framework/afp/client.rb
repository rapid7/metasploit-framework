# -*- coding: binary -*-
module Metasploit
  module Framework
    module AFP
      module Client

        def next_id
          @request_id ||= -1
          @request_id += 1

          @request_id
        end

        def get_info
          packet =  "\00"    # Flag: Request
          packet << "\x03"   # Command: FPGetSrvrInfo
          packet << [next_id].pack('n') # requestID
          packet << "\x00\x00\x00\x00" # Data offset
          packet << "\x00\x00\x00\x00" # Length
          packet << "\x00\x00\x00\x00" # Reserved

          sock.put(packet)

          response = sock.timed_read(1024)
          return parse_info_response(response)
        end

        def open_session
          packet =  "\00"              # Flag: Request
          packet << "\x04"             # Command: DSIOpenSession
          packet << [next_id].pack('n') # requestID
          packet << "\x00\x00\x00\x00" # Data offset
          packet << "\x00\x00\x00\x06" # Length
          packet << "\x00\x00\x00\x00" # Reserved
          packet << "\x01"             # Attention Quantum
          packet << "\x04"             # Length
          packet << "\x00\x00\x04\x00" # 1024

          sock.put(packet)

          response = sock.timed_read(1024)
          return parse_open_session_response(response)
        end

        def login(user, pass)
          if user == ''
            return no_user_authent_login
          end

          p = OpenSSL::BN.new("BA2873DFB06057D43F2024744CEEE75B", 16)
          g = OpenSSL::BN.new("7", 10)
          ra = OpenSSL::BN.new('86F6D3C0B0D63E4B11F113A2F9F19E3BBBF803F28D30087A1450536BE979FD42', 16)
          ma = g.mod_exp(ra, p)

          padded_user = (user.length + 1) % 2 != 0 ? user + "\x00" : user
          bin_user = [padded_user.length, padded_user].pack("Ca*")

          length = 18 + bin_user.length + ma.to_s(2).length

          packet =  "\00"              # Flag: Request
          packet << "\x02"             # Command: DSICommand
          packet << [next_id].pack('n') # requestID
          packet << "\x00\x00\x00\x00" # Data offset
          packet << [length].pack('N') # Length (42)
          packet << "\x00\x00\x00\x00" # Reserved
          packet << "\x12"             # AFPCommand: FPLogin (18)
          packet << "\x06\x41\x46\x50\x33\x2e\x31" # AFPVersion: AFP3.1
          packet << "\x09\x44\x48\x43\x41\x53\x54\x31\x32\x38" #UAM: DHCAST128
          packet << bin_user           # username
          packet << ma.to_s(2)         # random number

          sock.put(packet)

          begin
            response = sock.timed_read(1024, self.login_timeout)
          rescue Timeout::Error
            raise RuntimeError, "AFP Login timeout (AFP server delay response for 20 - 22 seconds after 7 incorrect logins)"
          end

          flags, command, request_id, error_code, length, reserved = parse_header(response)

          case error_code
          when -5001 #kFPAuthContinue
            return parse_login_response_add_send_login_count(response, {:p => p, :g => g, :ra => ra, :ma => ma,
                                                                        :password => pass, :user => user})
          when -5023 #kFPUserNotAuth (User doesn't exists)
            return :skip_user
          else
            return :connection_error
          end

        end

        def close_session
          packet =  "\00"              # Flag: Request
          packet << "\x01"             # Command: DSICloseSession
          packet << [next_id].pack('n')    # requestID
          packet << "\x00\x00\x00\x00" #Data offset
          packet << "\x00\x00\x00\x00" #Length
          packet << "\x00\x00\x00\x00" #Reserved

          sock.put(packet)
        end

        def no_user_authent_login
          packet =  "\00"              # Flag: Request
          packet << "\x02"             # Command: DSICommand
          packet << [next_id].pack('n')    # requestID
          packet << "\x00\x00\x00\x00" # Data offset
          packet << "\x00\x00\x00\x18" # Length (24)
          packet << "\x00\x00\x00\x00" # Reserved
          packet << "\x12"             # AFPCommand: FPLogin (18)
          packet << "\x06\x41\x46\x50\x33\x2e\x31" #AFP3.1
          packet << "\x0f\x4e\x6f\x20\x55\x73\x65\x72\x20\x41\x75\x74\x68\x65\x6e\x74" #UAM: No User Authent

          sock.put(packet)

          begin
            response = sock.timed_read(1024, self.login_timeout)
          rescue Timeout::Error
            raise RuntimeError, "AFP Login timeout (AFP server delay response for 20 - 22 seconds after 7 incorrect logins)"
          end

          flags, command, request_id, error_code, length, reserved = parse_header(response)

          if error_code == 0
            return :true
          else
            return false
          end
        end

        def parse_login_response_add_send_login_count(response, data)
          dhx_s2civ = 'CJalbert'
          dhx_c2civ = 'LWallace'

          flags, command, request_id, error_code, length, reserved = parse_header(response)
          body = get_body(response, length)
          id, mb, enc_data = body.unpack("nH32a*")

          mb = OpenSSL::BN.new(mb, 16)
          k = mb.mod_exp(data[:ra], data[:p] )

          cipher = OpenSSL::Cipher.new('cast5-cbc').decrypt
          cipher.key = k.to_s(2)
          cipher.iv = dhx_s2civ
          cipher.padding = 0

          nonce = cipher.update(enc_data)
          nonce << cipher.final
          nonce = nonce[0..15]
          nonce = OpenSSL::BN.new(nonce, 2) + 1

          plain_text = nonce.to_s(2) + data[:password].ljust(64, "\x00")
          cipher = OpenSSL::Cipher.new('cast5-cbc').encrypt
          cipher.key = k.to_s(2)
          cipher.iv = dhx_c2civ
          auth_response = cipher.update(plain_text)
          auth_response << cipher.final

          packet =  "\00"              # Flag: Request
          packet << "\x02"             # Command: DSICommand
          packet << [next_id].pack('n')    # requestID
          packet << "\x00\x00\x00\x00" # Data offset
          packet << [auth_response.length + 2].pack("N")  # Length
          packet << "\x00\x00\x00\x00" # Reserved
          packet << "\x13"             # AFPCommand: FPLoginCont (19)
          packet << "\x00"
          packet << [id].pack('n')
          packet << auth_response

          sock.put(packet)

          begin
            response = sock.timed_read(1024, self.login_timeout)
          rescue Timeout::Error
            raise RuntimeError, "AFP Login timeout (AFP server delay response for 20 - 22 seconds after 7 incorrect logins)"
          end

          flags, command, request_id, error_code, length, reserved = parse_header(response)
          if error_code == 0
            return true
          else
            return false
          end
        end

        def parse_open_session_response(response)
          _, _, _, error_code, _, _ = parse_header(response)
          return error_code == 0 ? true : false
        end

        def parse_info_response(response)
          parsed_data = {}

          flags, command, request_id, error_code, length, reserved = parse_header(response)
          raise RuntimeError, "AFP Server response with error" if error_code != 0
          body = get_body(response, length)
          machine_type_offset, afp_versions_offset, uam_count_offset, icon_offset, server_flags =
            body.unpack('nnnnn')

          server_name_length = body.unpack('@10C').first
          parsed_data[:server_name] = body.unpack("@11A#{server_name_length}").first

          pos = 11 + server_name_length
          pos += 1 if pos % 2 != 0 #padding

          server_signature_offset, network_addresses_offset, directory_names_offset,
            utf8_servername_offset = body.unpack("@#{pos}nnnn")

          parsed_data[:machine_type] = read_pascal_string(body, machine_type_offset)
          parsed_data[:versions] = read_array(body, afp_versions_offset)
          parsed_data[:uams] = read_array(body, uam_count_offset)
          # skipped icon
          parsed_data[:server_flags] = parse_flags(server_flags)
          parsed_data[:signature] = body.unpack("@#{server_signature_offset}H32").first

          network_addresses = read_array(body, network_addresses_offset, true)
          parsed_data[:network_addresses] = parse_network_addresses(network_addresses)
          # skipped directory names
          #Error catching for offset issues on this field. Need better error handling all through here
          begin
            parsed_data[:utf8_server_name] = read_utf8_pascal_string(body, utf8_servername_offset)
          rescue
            parsed_data[:utf8_server_name] = "N/A"
          end

          return parsed_data
        end

        def parse_header(packet)
          header = packet.unpack('CCnNNN') #ruby 1.8.7 don't support unpacking signed integers in big-endian order
          header[3] = packet[4..7].reverse.unpack("l").first
          return header
        end

        def get_body(packet, body_length)
          body = packet[16..body_length + 15]
          raise RuntimeError, "AFP Invalid body length" if body.length != body_length
          return body
        end

        def read_pascal_string(str, offset)
          length = str.unpack("@#{offset}C").first
          return str.unpack("@#{offset + 1}A#{length}").first
        end

        def read_utf8_pascal_string(str, offset)
          length = str.unpack("@#{offset}n").first
          return str[offset + 2..offset + length + 1]
        end

        def read_array(str, offset, afp_network_address=false)
          size = str.unpack("@#{offset}C").first
          pos = offset + 1

          result = []
          size.times do
            result << read_pascal_string(str, pos)
            pos += str.unpack("@#{pos}C").first
            pos += 1 unless afp_network_address
          end
          return result
        end

        def parse_network_addresses(network_addresses)
          parsed_addreses = []
          network_addresses.each do |address|
            case address.unpack('C').first
            when 0 #Reserved
              next
            when 1 # Four-byte IP address
              parsed_addreses << IPAddr.ntop(address[1..4]).to_s
            when 2 # Four-byte IP address followed by a two-byte port number
              parsed_addreses <<  "#{IPAddr.ntop(address[1..4])}:#{address[5..6].unpack("n").first}"
            when 3 # DDP address (deprecated)
              next
            when 4 # DNS name (maximum of 254 bytes)
              parsed_addreses << address[1..address.length - 1]
            when 5 # This functionality is deprecated.
              next
            when 6 # IPv6 address (16 bytes)
              parsed_addreses << "[#{IPAddr.ntop(address[1..16])}]"
            when 7 # IPv6 address (16 bytes) followed by a two-byte port number
              parsed_addreses << "[#{IPAddr.ntop(address[1..16])}]:#{address[17..18].unpack("n").first}"
            else   # Something wrong?
              raise RuntimeError, "Error parsing network addresses"
            end
          end
          return parsed_addreses
        end

        def parse_flags(flags)
          flags = flags.to_s(2)
          result = {}
          result['Super Client'] = flags[0,1] == '1' ? true : false
          result['UUIDs'] = flags[5,1] == '1' ? true : false
          result['UTF8 Server Name'] = flags[6,1] == '1' ? true : false
          result['Open Directory'] = flags[7,1] == '1' ? true : false
          result['Reconnect'] = flags[8,1] == '1' ? true : false
          result['Server Notifications'] = flags[9,1] == '1' ? true : false
          result['TCP/IP'] = flags[10,1] == '1' ? true : false
          result['Server Signature'] = flags[11,1] == '1' ? true : false
          result['Server Messages'] = flags[12,1] == '1' ? true : false
          result['Password Saving Prohibited'] = flags[13,1] == '1' ? true : false
          result['Password Changing'] = flags[14,1] == '1' ? true : false
          result['Copy File'] = flags[5,1] == '1' ? true : false
          return result
        end

      end
    end

  end
end

