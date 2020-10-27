# -*- coding: binary -*-

module Msf
  ###
  #
  # This module provides methods for working with Cisco equipment
  #
  ###
  module Auxiliary::Cisco
    include Msf::Auxiliary::Report

    def cisco_ios_decrypt7(inp)
      xlat = [
        0x64, 0x73, 0x66, 0x64, 0x3b, 0x6b, 0x66, 0x6f,
        0x41, 0x2c, 0x2e, 0x69, 0x79, 0x65, 0x77, 0x72,
        0x6b, 0x6c, 0x64, 0x4a, 0x4b, 0x44, 0x48, 0x53,
        0x55, 0x42
      ]

      return nil if !(inp[0, 2] =~ /\d\d/)

      seed = nil
      clear = ''
      inp.scan(/../).each do |byte|
        if !seed
          seed = byte.to_i
          next
        end
        byte = byte.to_i(16)
        clear << [ byte ^ xlat[seed]].pack('C')
        seed += 1
      end
      clear
    end

    def cisco_ios_config_eater(thost, tport, config)

      if framework.db.active
        credential_data = {
          address: thost,
          port: tport,
          protocol: 'tcp',
          workspace_id: myworkspace_id,
          origin_type: :service,
          private_type: :password,
          service_name: '',
          module_fullname: fullname,
          status: Metasploit::Model::Login::Status::UNTRIED
        }
      end

      # Default SNMP to UDP
      if tport == 161
        credential_data[:protocol] = 'udp'
      end

      store_loot('cisco.ios.config', 'text/plain', thost, config.strip, 'config.txt', 'Cisco IOS Configuration')

      tuniface = nil

      host_info = {
        host: thost,
        os_name: 'Cisco IOS'
      }
      report_host(host_info)

      config.each_line do |line|
        case line
          #
          # Cover host details
          #
        when /^version (\d\d\.\d)/i
          host_info[:os_flavor] = Regexp.last_match(1).to_s
          report_host(host_info)
        when /^hostname (\S+)/i
          host_info[:name] = Regexp.last_match(1).to_s
          report_host(host_info)
          #
          # Enable passwords
          #
        when /^\s*enable (password|secret) (\d+) (.*)/i
          stype = Regexp.last_match(2).to_i
          shash = Regexp.last_match(3).strip

          if framework.db.active
            cred = credential_data.dup
            cred[:private_data] = shash
          else
            cred = {} # throw away
          end

          case stype
          when 5
            print_good("#{thost}:#{tport} MD5 Encrypted Enable Password: #{shash}")
            cred[:jtr_format] = 'md5'
            cred[:private_type] = :nonreplayable_hash
            create_credential_and_login(cred) if framework.db.active
          when 0 # unencrypted
            print_good("#{thost}:#{tport} Enable Password: #{shash}")
            create_credential_and_login(cred) if framework.db.active
          when 7
            shash = begin
                    cisco_ios_decrypt7(shash)
                    rescue StandardError
                      shash
                  end
            print_good("#{thost}:#{tport} Decrypted Enable Password: #{shash}")
            cred[:private_data] = shash
            create_credential_and_login(cred) if framework.db.active
          end

        when /^\s*enable password (.*)/i
          spass = Regexp.last_match(1).strip
          print_good("#{thost}:#{tport} Unencrypted Enable Password: #{spass}")

          if framework.db.active
            cred = credential_data.dup
            cred[:private_data] = spass
            create_credential_and_login(cred)
          end

          #
          # SNMP
          #
        when /^\s*snmp-server community ([^\s]+) (RO|RW)/i
          stype = Regexp.last_match(2).strip
          scomm = Regexp.last_match(1).strip
          print_good("#{thost}:#{tport} SNMP Community (#{stype}): #{scomm}")

          cred = credential_data.dup
          cred[:access_level] = stype.upcase
          cred[:protocol] = "udp"
          cred[:port] = 161
          cred[:private_data] = scomm
          create_credential_and_login(cred)
#
# VTY Passwords
#
        when /^\s*password 7 ([^\s]+)/i
          spass = Regexp.last_match(1).strip
          spass = begin
                  cisco_ios_decrypt7(spass)
                  rescue StandardError
                    spass
                end

          print_good("#{thost}:#{tport} Decrypted VTY Password: #{spass}")

          if framework.db.active
            cred = credential_data.dup
            cred[:private_data] = spass
            create_credential_and_login(cred)
          end

        when /^\s*(password|secret) 5 (.*)/i
          shash = Regexp.last_match(2).strip
          print_good("#{thost}:#{tport} MD5 Encrypted VTY Password: #{shash}")
          if framework.db.active
            cred = credential_data.dup
            cred[:jtr_format] = 'md5'
            cred[:private_data] = shash
            cred[:private_type] = :nonreplayable_hash
            create_credential_and_login(cred)
          end

        when /^\s*password (0 |)([^\s]+)/i
          spass = Regexp.last_match(2).strip
          print_good("#{thost}:#{tport} Unencrypted VTY Password: #{spass}")

          if framework.db.active
            cred = credential_data.dup
            cred[:private_data] = spass
            create_credential_and_login(cred)
          end

          #
          # WiFi Passwords
          #
        when /^\s*encryption key \d+ size \d+bit (\d+) ([^\s]+)/
          spass = Regexp.last_match(2).strip
          print_good("#{thost}:#{tport} Wireless WEP Key: #{spass}")

        when /^\s*wpa-psk (ascii|hex) (\d+) ([^\s]+)/i

          stype = Regexp.last_match(2).to_i
          spass = Regexp.last_match(3).strip

          if framework.db.active
            cred = credential_data.dup
            cred[:private_data] = spass
          else
            cred = {} # throw away
          end

          case stype
          when 5
            print_good("#{thost}:#{tport} Wireless WPA-PSK MD5 Password Hash: #{spass}")
            cred[:jtr_format] = 'md5'
            cred[:private_type] = :nonreplayable_hash
            create_credential_and_login(cred) if framework.db.active
          when 0
            print_good("#{thost}:#{tport} Wireless WPA-PSK Password: #{spass}")
            create_credential_and_login(cred) if framework.db.active
          when 7
            spass = begin
                    cisco_ios_decrypt7(spass)
                    rescue StandardError
                      spass
                  end
            print_good("#{thost}:#{tport} Wireless WPA-PSK Decrypted Password: #{spass}")
            cred[:private_data] = spass
            create_credential_and_login(cred) if framework.db.active
          end

          #
          # VPN Passwords
          #
        when /^\s*crypto isakmp key ([^\s]+) address ([^\s]+)/i
          spass = Regexp.last_match(1)
          shost = Regexp.last_match(2)

          print_good("#{thost}:#{tport} VPN IPSEC ISAKMP Key '#{spass}' Host '#{shost}'")
          if framework.db.active
            cred = credential_data.dup
            cred[:private_data] = spass
            cred[:private_type] = :nonreplayable_hash
            create_credential_and_login(cred)
          end

        when /^\s*interface tunnel(\d+)/i
          tuniface = Regexp.last_match(1)

        when /^\s*tunnel key ([^\s]+)/i
          spass = Regexp.last_match(1)
          siface = tuniface

          print_good("#{thost}:#{tport} GRE Tunnel Key #{spass} for Interface Tunnel #{siface}")
          if framework.db.active
            cred = credential_data.dup
            cred[:private_data] = spass
            cred[:private_type] = :nonreplayable_hash
            create_credential_and_login(cred)
          end

        when /^\s*ip nhrp authentication ([^\s]+)/i
          spass = Regexp.last_match(1)
          siface = tuniface

          print_good("#{thost}:#{tport} NHRP Authentication Key #{spass} for Interface Tunnel #{siface}")
          if framework.db.active
            cred = credential_data.dup
            cred[:private_data] = spass
            cred[:private_type] = :nonreplayable_hash
            create_credential_and_login(cred)
          end

          #
          # Various authentication secrets
          #
        when /^\s*username ([^\s]+) privilege (\d+) (secret|password) (\d+) ([^\s]+)/i
          user = Regexp.last_match(1)
          priv = Regexp.last_match(2)
          stype = Regexp.last_match(4).to_i
          spass = Regexp.last_match(5)

          if framework.db.active
            cred = credential_data.dup
            cred[:username] = user.to_s
            cred[:private_data] = spass
          else
            cred = {} # throw away
          end

          case stype
          when 5
            print_good("#{thost}:#{tport} Username '#{user}' with MD5 Encrypted Password: #{spass}")
            cred[:jtr_format] = 'md5'
            cred[:private_type] = :nonreplayable_hash
            create_credential_and_login(cred) if framework.db.active
          when 0
            print_good("#{thost}:#{tport} Username '#{user}' with Password: #{spass}")
            create_credential_and_login(cred) if framework.db.active
          when 7
            spass = begin
                    cisco_ios_decrypt7(spass)
                    rescue StandardError
                      spass
                  end
            print_good("#{thost}:#{tport} Username '#{user}' with Decrypted Password: #{spass}")
            cred[:private_data] = spass
            create_credential_and_login(cred) if framework.db.active
          end

          # This regex captures ephones from Cisco Unified Communications Manager Express (CUE) which come in forms like:
          # username "phonefour" password 444444
          # username test password test
          # This is used for the voicemail system
        when /^\s*username "?([\da-z]+)"? password ([^\s]+)/i
          user = Regexp.last_match(1)
          spass = Regexp.last_match(2)
          print_good("#{thost}:#{tport} ePhone Username '#{user}' with Password: #{spass}")
          if framework.db.active
            cred = credential_data.dup
            cred[:username] = user.to_s
            cred[:private_data] = spass
            create_credential_and_login(cred)
          end

        when /^\s*username ([^\s]+) (secret|password) (\d+) ([^\s]+)/i
          user = Regexp.last_match(1)
          stype = Regexp.last_match(3).to_i
          spass = Regexp.last_match(4)

          if framework.db.active
            cred = credential_data.dup
            cred[:username] = user.to_s
            cred[:private_data] = spass
          else
            cred = {}
          end

          case stype
          when 5
            print_good("#{thost}:#{tport} Username '#{user}' with MD5 Encrypted Password: #{spass}")
            cred[:jtr_format] = 'md5'
            cred[:private_type] = :nonreplayable_hash
            create_credential_and_login(cred) if framework.db.active
          when 0
            print_good("#{thost}:#{tport} Username '#{user}' with Password: #{spass}")
            create_credential_and_login(cred) if framework.db.active
          when 7
            spass = begin
                    cisco_ios_decrypt7(spass)
                    rescue StandardError
                      spass
                  end
            print_good("#{thost}:#{tport} Username '#{user}' with Decrypted Password: #{spass}")
            cred[:private_data] = spass
            create_credential_and_login(cred) if framework.db.active
          end

          # https://www.cisco.com/c/en/us/td/docs/voice_ip_comm/cucme/command/reference/cme_cr/cme_cr_chapter_010101.html#wp3722577363
        when /^\s*web admin (customer|system) name ([^\s]+) (secret [0|5]|password) ([^\s]+)/i
          login = Regexp.last_match(1)
          suser = Regexp.last_match(2)
          stype = Regexp.last_match(3)
          spass = Regexp.last_match(4)

          if framework.db.active
            cred = credential_data.dup
            cred[:username] = suser.to_s
            cred[:private_data] = spass
          else
            cred = {}
          end

          case stype
          when 'secret 5'
            print_good("#{thost}:#{tport} Web Admin Username: #{suser} Type: #{login} MD5 Encrypted Password: #{spass}")
            cred[:jtr_format] = 'md5'
            cred[:private_type] = :nonreplayable_hash
            create_credential_and_login(cred) if framework.db.active
          when 'secret 0', 'password'
            print_good("#{thost}:#{tport} Web Username: #{suser} Type: #{login} Password: #{spass}")
            create_credential_and_login(cred) if framework.db.active
          end

        when /^\s*ppp.*username ([^\s]+) (secret|password) (\d+) ([^\s]+)/i

          suser = Regexp.last_match(1)
          stype = Regexp.last_match(3).to_i
          spass = Regexp.last_match(4)

          if framework.db.active
            cred = credential_data.dup
            cred[:username] = suser.to_s
            cred[:private_data] = spass
          else
            cred = {}
          end

          case stype
          when 5
            print_good("#{thost}:#{tport} PPP Username #{suser} MD5 Encrypted Password: #{spass}")
            cred[:jtr_format] = 'md5'
            cred[:private_type] = :nonreplayable_hash
            create_credential_and_login(cred) if framework.db.active
          when 0
            print_good("#{thost}:#{tport} PPP Username: #{suser} Password: #{spass}")
            create_credential_and_login(cred) if framework.db.active
          when 7
            spass = begin
                    cisco_ios_decrypt7(spass)
                    rescue StandardError
                      spass
                  end
            print_good("#{thost}:#{tport} PPP Username: #{suser} Decrypted Password: #{spass}")
            cred[:private_data] = spass
            create_credential_and_login(cred) if framework.db.active
          end

        when /^\s*ppp chap (secret|password) (\d+) ([^\s]+)/i
          stype = Regexp.last_match(2).to_i
          spass = Regexp.last_match(3)

          if framework.db.active
            cred = credential_data.dup
            cred[:private_data] = spass
          else
            cred = {}
          end

          case stype
          when 5
            print_good("#{thost}:#{tport} PPP CHAP MD5 Encrypted Password: #{spass}")
            cred[:jtr_format] = 'md5'
            cred[:private_type] = :nonreplayable_hash
            create_credential_and_login(cred) if framework.db.active
          when 0
            print_good("#{thost}:#{tport} Password: #{spass}")
            create_credential_and_login(cred) if framework.db.active
          when 7
            spass = begin
                    cisco_ios_decrypt7(spass)
                    rescue StandardError
                      spass
                  end
            print_good("#{thost}:#{tport} PPP Decrypted Password: #{spass}")
            cred[:private_data] = spass
            create_credential_and_login(cred) if framework.db.active
          end
        end
      end
    end
  end
end
