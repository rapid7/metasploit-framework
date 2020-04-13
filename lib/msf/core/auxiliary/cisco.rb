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

    return nil if not inp[0,2] =~ /\d\d/

    seed  = nil
    clear = ""
    inp.scan(/../).each do |byte|
      if not seed
        seed = byte.to_i
        next
      end
      byte = byte.to_i(16)
      clear << [ byte ^ xlat[ seed ]].pack("C")
      seed += 1
    end
    clear
  end

  def cisco_ios_config_eater(thost, tport, config)

    credential_data = {
      address: thost,
      port: tport,
      protocol: 'tcp',
      workspace_id: myworkspace.id,
      origin_type: :service,
      private_type: :password,
      service_name: '',
      module_fullname: self.fullname,
      status: Metasploit::Model::Login::Status::UNTRIED
    }

    # Default SNMP to UDP
    if tport == 161
      credential_data[:protocol] = 'udp'
    end

    store_loot("cisco.ios.config", "text/plain", thost, config.strip, "config.txt", "Cisco IOS Configuration")

    tuniface = nil

    host_info = {
      :host => thost,
      :os_name => 'Cisco IOS',
    }
    report_host(host_info)

    config.each_line do |line|
      case line
#
# Cover host details
#
        when /^version (\d\d\.\d)/i
          host_info[:os_flavor] = $1.to_s
          report_host(host_info)
        when /^hostname (\S+)/i
          host_info[:name] = $1.to_s
          report_host(host_info)
#
# Enable passwords
#
        when /^\s*enable (password|secret) (\d+) (.*)/i
          stype = $2.to_i
          shash = $3.strip

          if stype == 5
            print_good("#{thost}:#{tport} MD5 Encrypted Enable Password: #{shash}")
            cred = credential_data.dup
            cred[:jtr_format] = 'md5'
            cred[:private_data] = shash
            cred[:private_type] = :nonreplayable_hash
            create_credential_and_login(cred)
          end

          if stype == 0 #unencrypted
            print_good("#{thost}:#{tport} Enable Password: #{shash}")
            cred = credential_data.dup
            cred[:private_data] = shash
            create_credential_and_login(cred)
          end

          if stype == 7
            shash = cisco_ios_decrypt7(shash) rescue shash
            print_good("#{thost}:#{tport} Decrypted Enable Password: #{shash}")
            cred = credential_data.dup
            cred[:private_data] = shash
            create_credential_and_login(cred)
          end

        when /^\s*enable password (.*)/i
          spass = $1.strip
          print_good("#{thost}:#{tport} Unencrypted Enable Password: #{spass}")

          cred = credential_data.dup
          cred[:private_data] = spass
          create_credential_and_login(cred)

#
# SNMP
#
        when /^\s*snmp-server community ([^\s]+) (RO|RW)/i
          stype = $2.strip
          scomm = $1.strip
          print_good("#{thost}:#{tport} SNMP Community (#{stype}): #{scomm}")

          cred = credential_data.dup
          if stype.downcase == "ro"
            cred[:access_level] = "RO"
          else
            cred[:access_level] = "RW"
          end
          cred[:protocol] = "udp"
          cred[:port] = 161
          cred[:private_data] = scomm
          create_credential_and_login(cred)
#
# VTY Passwords
#
        when /^\s*password 7 ([^\s]+)/i
          spass = $1.strip
          spass = cisco_ios_decrypt7(spass) rescue spass

          print_good("#{thost}:#{tport} Decrypted VTY Password: #{spass}")

          cred = credential_data.dup
          cred[:private_data] = spass
          create_credential_and_login(cred)


        when /^\s*(password|secret) 5 (.*)/i
          shash = $2.strip
          print_good("#{thost}:#{tport} MD5 Encrypted VTY Password: #{shash}")
          cred = credential_data.dup
          cred[:jtr_format] = 'md5'
          cred[:private_data] = shash
          cred[:private_type] = :nonreplayable_hash
          create_credential_and_login(cred)

        when /^\s*password (0 |)([^\s]+)/i
          spass = $2.strip
          print_good("#{thost}:#{tport} Unencrypted VTY Password: #{spass}")

          cred = credential_data.dup
          cred[:private_data] = spass
          create_credential_and_login(cred)

#
# WiFi Passwords
#
        when /^\s*encryption key \d+ size \d+bit (\d+) ([^\s]+)/
          spass = $2.strip
          print_good("#{thost}:#{tport} Wireless WEP Key: #{spass}")

        when /^\s*wpa-psk (ascii|hex) (\d+) ([^\s]+)/i

          stype = $2.to_i
          spass = $3.strip

          if stype == 5
            print_good("#{thost}:#{tport} Wireless WPA-PSK MD5 Password Hash: #{spass}")
            cred = credential_data.dup
            cred[:jtr_format] = 'md5'
            cred[:private_data] = spass
            cred[:private_type] = :nonreplayable_hash
            create_credential_and_login(cred)
          end

          if stype == 0
            print_good("#{thost}:#{tport} Wireless WPA-PSK Password: #{spass}")
            cred = credential_data.dup
            cred[:private_data] = spass
            create_credential_and_login(cred)
          end

          if stype == 7
            spass = cisco_ios_decrypt7(spass) rescue spass
            print_good("#{thost}:#{tport} Wireless WPA-PSK Decrypted Password: #{spass}")
            cred = credential_data.dup
            cred[:private_data] = spass
            create_credential_and_login(cred)
          end

#
# VPN Passwords
#
        when /^\s*crypto isakmp key ([^\s]+) address ([^\s]+)/i
          spass  = $1
          shost  = $2

          print_good("#{thost}:#{tport} VPN IPSEC ISAKMP Key '#{spass}' Host '#{shost}'")
          cred = credential_data.dup
          cred[:private_data] = spass
          cred[:private_type] = :nonreplayable_hash
          create_credential_and_login(cred)

        when /^\s*interface tunnel(\d+)/i
          tuniface = $1

        when /^\s*tunnel key ([^\s]+)/i
          spass = $1
          siface = tuniface

          print_good("#{thost}:#{tport} GRE Tunnel Key #{spass} for Interface Tunnel #{siface}")
          cred = credential_data.dup
          cred[:private_data] = spass
          cred[:private_type] = :nonreplayable_hash
          create_credential_and_login(cred)

        when /^\s*ip nhrp authentication ([^\s]+)/i
          spass = $1
          siface = tuniface

          print_good("#{thost}:#{tport} NHRP Authentication Key #{spass} for Interface Tunnel #{siface}")
          cred = credential_data.dup
          cred[:private_data] = spass
          cred[:private_type] = :nonreplayable_hash
          create_credential_and_login(cred)


#
# Various authentication secrets
#
        when /^\s*username ([^\s]+) privilege (\d+) (secret|password) (\d+) ([^\s]+)/i
          user  = $1
          priv  = $2
          stype = $4.to_i
          spass = $5

          if stype == 5
            print_good("#{thost}:#{tport} Username '#{user}' with MD5 Encrypted Password: #{spass}")
            cred = credential_data.dup
            cred[:jtr_format] = 'md5'
            cred[:username] = user.to_s
            cred[:private_data] = spass
            cred[:private_type] = :nonreplayable_hash
            create_credential_and_login(cred)
          end

          if stype == 0
            print_good("#{thost}:#{tport} Username '#{user}' with Password: #{spass}")
            cred = credential_data.dup
            cred[:username] = user.to_s
            cred[:private_data] = spass
            create_credential_and_login(cred)
          end

          if stype == 7
            spass = cisco_ios_decrypt7(spass) rescue spass
            print_good("#{thost}:#{tport} Username '#{user}' with Decrypted Password: #{spass}")
            cred = credential_data.dup
            cred[:username] = user.to_s
            cred[:private_data] = spass
            create_credential_and_login(cred)
          end

        # This regex captures ephones from Cisco Unified Communications Manager Express (CUE) which come in forms like:
        # username "phonefour" password 444444
        # username test password test
        # This is used for the voicemail system
        when /^\s*username "?([\da-z]+)"? password ([^\s]+)/i
          user  = $1
          spass = $2
          print_good("#{thost}:#{tport} ePhone Username '#{user}' with Password: #{spass}")
          cred = credential_data.dup
          cred[:username] = user.to_s
          cred[:private_data] = spass
          create_credential_and_login(cred)

        when /^\s*username ([^\s]+) (secret|password) (\d+) ([^\s]+)/i
          user  = $1
          stype = $3.to_i
          spass = $4

          if stype == 5
            print_good("#{thost}:#{tport} Username '#{user}' with MD5 Encrypted Password: #{spass}")
            cred = credential_data.dup
            cred[:jtr_format] = 'md5'
            cred[:username] = user.to_s
            cred[:private_data] = spass
            cred[:private_type] = :nonreplayable_hash
            create_credential_and_login(cred)
          end

          if stype == 0
            print_good("#{thost}:#{tport} Username '#{user}' with Password: #{spass}")
            cred = credential_data.dup
            cred[:username] = user.to_s
            cred[:private_data] = spass
            create_credential_and_login(cred)
          end

          if stype == 7
            spass = cisco_ios_decrypt7(spass) rescue spass
            print_good("#{thost}:#{tport} Username '#{user}' with Decrypted Password: #{spass}")
            cred = credential_data.dup
            cred[:username] = user.to_s
            cred[:private_data] = spass
            create_credential_and_login(cred)
          end

        # https://www.cisco.com/c/en/us/td/docs/voice_ip_comm/cucme/command/reference/cme_cr/cme_cr_chapter_010101.html#wp3722577363
        when /^\s*web admin (customer|system) name ([^\s]+) (secret [0|5]|password) ([^\s]+)/i
          login = $1
          suser = $2
          stype = $3
          spass = $4
          if stype == 'secret 5'
            print_good("#{thost}:#{tport} Web Admin Username: #{suser} Type: #{login} MD5 Encrypted Password: #{spass}")
            cred = credential_data.dup
            cred[:jtr_format] = 'md5'
            cred[:username] = suser.to_s
            cred[:private_data] = spass
            cred[:private_type] = :nonreplayable_hash
            create_credential_and_login(cred)
          end

          if stype == 'secret 0' || stype == 'password'
            print_good("#{thost}:#{tport} Web Username: #{suser} Type: #{login} Password: #{spass}")
            cred = credential_data.dup
            cred[:username] = suser.to_s
            cred[:private_data] = spass
            create_credential_and_login(cred)
          end

        when /^\s*ppp.*username ([^\s]+) (secret|password) (\d+) ([^\s]+)/i

          suser = $1
          stype = $3.to_i
          spass = $4

          if stype == 5
            print_good("#{thost}:#{tport} PPP Username #{suser} MD5 Encrypted Password: #{spass}")
            cred = credential_data.dup
            cred[:jtr_format] = 'md5'
            cred[:username] = suser.to_s
            cred[:private_data] = spass
            cred[:private_type] = :nonreplayable_hash
            create_credential_and_login(cred)
          end

          if stype == 0
            print_good("#{thost}:#{tport} PPP Username: #{suser} Password: #{spass}")
            cred = credential_data.dup
            cred[:username] = suser.to_s
            cred[:private_data] = spass
            create_credential_and_login(cred)
          end

          if stype == 7
            spass = cisco_ios_decrypt7(spass) rescue spass
            print_good("#{thost}:#{tport} PPP Username: #{suser} Decrypted Password: #{spass}")
            cred = credential_data.dup
            cred[:username] = suser.to_s
            cred[:private_data] = spass
            create_credential_and_login(cred)
          end

        when /^\s*ppp chap (secret|password) (\d+) ([^\s]+)/i
          stype = $2.to_i
          spass = $3

          if stype == 5
            print_good("#{thost}:#{tport} PPP CHAP MD5 Encrypted Password: #{spass}")
            cred = credential_data.dup
            cred[:jtr_format] = 'md5'
            cred[:private_data] = spass
            cred[:private_type] = :nonreplayable_hash
            create_credential_and_login(cred)
          end

          if stype == 0
            print_good("#{thost}:#{tport} Password: #{spass}")
            cred = credential_data.dup
            cred[:private_data] = spass
            create_credential_and_login(cred)
          end

          if stype == 7
            spass = cisco_ios_decrypt7(spass) rescue spass
            print_good("#{thost}:#{tport} PPP Decrypted Password: #{spass}")
            cred = credential_data.dup
            cred[:private_data] = spass
            create_credential_and_login(cred)
          end
      end
    end
  end

end
end

