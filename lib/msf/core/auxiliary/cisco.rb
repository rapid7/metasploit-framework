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

    #
    # Create a template hash for cred reporting
    #
    cred_info = {
      :host  => thost,
      :port  => tport,
      :user  => "",
      :pass  => "",
      :type  => "",
      :collect_type => "",
      :active => true
    }

    # Default SNMP to UDP
    if tport == 161
      cred_info[:proto] = 'udp'
    end

    store_loot("cisco.ios.config", "text/plain", thost, config.strip, "config.txt", "Cisco IOS Configuration")

    tuniface = nil

    config.each_line do |line|
      case line
#
# Enable passwords
#
        when /^\s*enable (password|secret) (\d+) (.*)/i
          stype = $2.to_i
          shash = $3.strip

          if stype == 5
            print_good("#{thost}:#{tport} MD5 Encrypted Enable Password: #{shash}")
            store_loot("cisco.ios.enable_hash", "text/plain", thost, shash, "enable_password_hash.txt", "Cisco IOS Enable Password Hash (MD5)")
          end

          if stype == 0
            print_good("#{thost}:#{tport} Enable Password: #{shash}")
            store_loot("cisco.ios.enable_pass", "text/plain", thost, shash, "enable_password.txt", "Cisco IOS Enable Password")

            cred = cred_info.dup
            cred[:pass] = shash
            cred[:type] = "password"
            cred[:collect_type] = "password"
            store_cred(cred)
          end

          if stype == 7
            shash = cisco_ios_decrypt7(shash) rescue shash
            print_good("#{thost}:#{tport} Decrypted Enable Password: #{shash}")
            store_loot("cisco.ios.enable_pass", "text/plain", thost, shash, "enable_password.txt", "Cisco IOS Enable Password")

            cred = cred_info.dup
            cred[:pass] = shash
            cred[:type] = "password"
            cred[:collect_type] = "password"
            store_cred(cred)
          end

        when /^\s*enable password (.*)/i
          spass = $1.strip
          print_good("#{thost}:#{tport} Unencrypted Enable Password: #{spass}")

          cred = cred_info.dup
          cred[:pass] = spass
          cred[:type] = "password"
          cred[:collect_type] = "password"
          store_cred(cred)

#
# SNMP
#
        when /^\s*snmp-server community ([^\s]+) (RO|RW)/i
          stype = $2.strip
          scomm = $1.strip
          print_good("#{thost}:#{tport} SNMP Community (#{stype}): #{scomm}")

          if stype.downcase == "ro"
            ptype = "password_ro"
          else
            ptype = "password"
          end

          cred = cred_info.dup
          cred[:sname] = "snmp"
          cred[:pass] = scomm
          cred[:type] = ptype
          cred[:collect_type] = ptype
          cred[:proto] = "udp"
          cred[:port]  = 161
          store_cred(cred)

#
# VTY Passwords
#
        when /^\s*password 7 ([^\s]+)/i
          spass = $1.strip
          spass = cisco_ios_decrypt7(spass) rescue spass

          print_good("#{thost}:#{tport} Decrypted VTY Password: #{spass}")
          cred = cred_info.dup

          cred[:pass] = spass
          cred[:type] = "password"
          cred[:collect_type] = "password"
          store_cred(cred)

        when /^\s*(password|secret) 5 (.*)/i
          shash = $1.strip
          print_good("#{thost}:#{tport} MD5 Encrypted VTY Password: #{shash}")
          store_loot("cisco.ios.vty_password", "text/plain", thost, shash, "vty_password_hash.txt", "Cisco IOS VTY Password Hash (MD5)")

        when /^\s*password (0 |)([^\s]+)/i
          spass = $2.strip
          print_good("#{thost}:#{tport} Unencrypted VTY Password: #{spass}")
          cred = cred_info.dup
          cred[:pass] = spass
          cred[:type] = "password"
          cred[:collect_type] = "password"
          store_cred(cred)

#
# WiFi Passwords
#
        when /^\s*encryption key \d+ size \d+bit (\d+) ([^\s]+)/
          spass = $2.strip
          print_good("#{thost}:#{tport} Wireless WEP Key: #{spass}")
          store_loot("cisco.ios.wireless_wep", "text/plain", thost, spass, "wireless_wep.txt", "Cisco IOS Wireless WEP Key")

        when /^\s*wpa-psk (ascii|hex) (\d+) ([^\s]+)/i

          stype = $2.to_i
          spass = $3.strip

          if stype == 5
            print_good("#{thost}:#{tport} Wireless WPA-PSK MD5 Password Hash: #{spass}")
            store_loot("cisco.ios.wireless_wpapsk_hash", "text/plain", thost, spass, "wireless_wpapsk_hash.txt", "Cisco IOS Wireless WPA-PSK Password Hash (MD5)")
          end

          if stype == 0
            print_good("#{thost}:#{tport} Wireless WPA-PSK Password: #{spass}")
            cred = cred_info.dup
            cred[:pass] = spass
            cred[:type] = "password"
            cred[:collect_type] = "password"
            store_cred(cred)

            store_loot("cisco.ios.wireless_wpapsk", "text/plain", thost, spass, "wireless_wpapsk.txt", "Cisco IOS Wireless WPA-PSK Password")
          end

          if stype == 7
            spass = cisco_ios_decrypt7(spass) rescue spass
            print_good("#{thost}:#{tport} Wireless WPA-PSK Decrypted Password: #{spass}")
            cred = cred_info.dup
            cred[:pass] = spass
            cred[:type] = "password"
            cred[:collect_type] = "password"
            store_cred(cred)

            store_loot("cisco.ios.wireless_wpapsk", "text/plain", thost, spass, "wireless_wpapsk.txt", "Cisco IOS Wireless WPA-PSK Decrypted Password")
          end

#
# VPN Passwords
#
        when /^\s*crypto isakmp key ([^\s]+) address ([^\s]+)/i
          spass  = $1
          shost  = $2

          print_good("#{thost}:#{tport} VPN IPSEC ISAKMP Key '#{spass}' Host '#{shost}'")
          store_loot("cisco.ios.vpn_ipsec_key", "text/plain", thost, "#{spass}", "vpn_ipsec_key.txt", "Cisco VPN IPSEC Key")

          cred = cred_info.dup
          cred[:pass] = spass
          cred[:type] = "password"
          cred[:collect_type] = "password"
          store_cred(cred)
        when /^\s*interface tunnel(\d+)/i
          tuniface = $1

        when /^\s*tunnel key ([^\s]+)/i
          spass = $1
          siface = tuniface

          print_good("#{thost}:#{tport} GRE Tunnel Key #{spass} for Interface Tunnel #{siface}")
          store_loot("cisco.ios.gre_tunnel_key", "text/plain", thost, "tunnel#{siface}_#{spass}", "gre_tunnel_key.txt", "Cisco GRE Tunnel Key")

          cred = cred_info.dup
          cred[:pass] = spass
          cred[:type] = "password"
          cred[:collect_type] = "password"
          store_cred(cred)

        when /^\s*ip nhrp authentication ([^\s]+)/i
          spass = $1
          siface = tuniface

          print_good("#{thost}:#{tport} NHRP Authentication Key #{spass} for Interface Tunnel #{siface}")
          store_loot("cisco.ios.nhrp_tunnel_key", "text/plain", thost, "tunnel#{siface}_#{spass}", "nhrp_tunnel_key.txt", "Cisco NHRP Authentication Key")

          cred = cred_info.dup
          cred[:pass] = spass
          cred[:type] = "password"
          cred[:collect_type] = "password"
          store_cred(cred)

#
# Various authentication secretss
#
        when /^\s*username ([^\s]+) privilege (\d+) (secret|password) (\d+) ([^\s]+)/i
          user  = $1
          priv  = $2
          stype = $4.to_i
          shash = $5

          if stype == 5
            print_good("#{thost}:#{tport} Username '#{user}' with MD5 Encrypted Password: #{shash}")
            store_loot("cisco.ios.username_password_hash", "text/plain", thost, "#{user}_level#{priv}:#{shash}", "username_password_hash.txt", "Cisco IOS Username and Password Hash (MD5)")
          end

          if stype == 0
            print_good("#{thost}:#{tport} Username '#{user}' with Password: #{shash}")
            store_loot("cisco.ios.username_password", "text/plain", thost, "#{user}_level#{priv}:#{shash}", "username_password.txt", "Cisco IOS Username and Password")

            cred = cred_info.dup
            cred[:user] = user
            cred[:pass] = shash
            cred[:type] = "password"
            cred[:collect_type] = "password"
            store_cred(cred)
          end

          if stype == 7
            shash = cisco_ios_decrypt7(shash) rescue shash
            print_good("#{thost}:#{tport} Username '#{user}' with Decrypted Password: #{shash}")
            store_loot("cisco.ios.username_password", "text/plain", thost, "#{user}_level#{priv}:#{shash}", "username_password.txt", "Cisco IOS Username and Password")

            cred = cred_info.dup
            cred[:user] = user
            cred[:pass] = shash
            cred[:type] = "password"
            cred[:collect_type] = "password"
            store_cred(cred)
          end

        when /^\s*username ([^\s]+) (secret|password) (\d+) ([^\s]+)/i
          user  = $1
          stype = $3.to_i
          shash = $4

          if stype == 5
            print_good("#{thost}:#{tport} Username '#{user}' with MD5 Encrypted Password: #{shash}")
            store_loot("cisco.ios.username_password_hash", "text/plain", thost, "#{user}:#{shash}", "username_password_hash.txt", "Cisco IOS Username and Password Hash (MD5)")
          end

          if stype == 0
            print_good("#{thost}:#{tport} Username '#{user}' with Password: #{shash}")
            store_loot("cisco.ios.username_password", "text/plain", thost, "#{user}:#{shash}", "username_password.txt", "Cisco IOS Username and Password")

            cred = cred_info.dup
            cred[:user] = user
            cred[:pass] = shash
            cred[:type] = "password"
            cred[:collect_type] = "password"
            store_cred(cred)
          end

          if stype == 7
            shash = cisco_ios_decrypt7(shash) rescue shash
            print_good("#{thost}:#{tport} Username '#{user}' with Decrypted Password: #{shash}")
            store_loot("cisco.ios.username_password", "text/plain", thost, "#{user}:#{shash}", "username_password.txt", "Cisco IOS Username and Password")

            cred = cred_info.dup
            cred[:user] = user
            cred[:pass] = shash
            cred[:type] = "password"
            cred[:collect_type] = "password"
            store_cred(cred)
          end

        when /^\s*ppp.*username ([^\s]+) (secret|password) (\d+) ([^\s]+)/i

          suser = $1
          stype = $3.to_i
          shash = $4

          if stype == 5
            print_good("#{thost}:#{tport} PPP Username #{suser} MD5 Encrypted Password: #{shash}")
            store_loot("cisco.ios.ppp_username_password_hash", "text/plain", thost, "#{suser}:#{shash}", "ppp_username_password_hash.txt", "Cisco IOS PPP Username and Password Hash (MD5)")
          end

          if stype == 0
            print_good("#{thost}:#{tport} PPP Username: #{suser} Password: #{shash}")
            store_loot("cisco.ios.ppp_username_password", "text/plain", thost, "#{suser}:#{shash}", "ppp_username_password.txt", "Cisco IOS PPP Username and Password")

            cred = cred_info.dup
            cred[:pass] = shash
            cred[:user] = suser
            cred[:type] = "password"
            cred[:collect_type] = "password"
            store_cred(cred)
          end

          if stype == 7
            shash = cisco_ios_decrypt7(shash) rescue shash
            print_good("#{thost}:#{tport} PPP Username: #{suser} Decrypted Password: #{shash}")
            store_loot("cisco.ios.ppp_username_password", "text/plain", thost, "#{suser}:#{shash}", "ppp_username_password.txt", "Cisco IOS PPP Username and Password")

            cred = cred_info.dup
            cred[:pass] = shash
            cred[:user] = suser
            cred[:type] = "password"
            cred[:collect_type] = "password"
            store_cred(cred)
          end

        when /^\s*ppp chap (secret|password) (\d+) ([^\s]+)/i
          stype = $2.to_i
          shash = $3

          if stype == 5
            print_good("#{thost}:#{tport} PPP CHAP MD5 Encrypted Password: #{shash}")
            store_loot("cisco.ios.ppp_password_hash", "text/plain", thost, shash, "ppp_password_hash.txt", "Cisco IOS PPP Password Hash (MD5)")
          end

          if stype == 0
            print_good("#{thost}:#{tport} Password: #{shash}")
            store_loot("cisco.ios.ppp_password", "text/plain", thost, shash, "ppp_password.txt", "Cisco IOS PPP Password")

            cred = cred_info.dup
            cred[:pass] = shash
            cred[:type] = "password"
            cred[:collect_type] = "password"
            store_cred(cred)
          end

          if stype == 7
            shash = cisco_ios_decrypt7(shash) rescue shash
            print_good("#{thost}:#{tport} PPP Decrypted Password: #{shash}")
            store_loot("cisco.ios.ppp_password", "text/plain", thost, shash, "ppp_password.txt", "Cisco IOS PPP Password")

            cred = cred_info.dup
            cred[:pass] = shash
            cred[:type] = "password"
            cred[:collect_type] = "password"
            store_cred(cred)
          end
      end
    end
  end

end
end
