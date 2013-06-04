-# -*- coding: binary -*-
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

				when /^set (password|enablepass) (.*)/i
					stype = $1.strip
					spass = $2.strip

					if stype == "password" and spass.count("$") == 3
						print_good("#{thost}:#{tport} MD5 Encrypted Login Password: #{shash}")
						store_loot("cisco.ios.login_hash", "text/plain", thost, shash, "login_password_hash.txt", "Cisco CatOS Login Password Hash (MD5)")
					end

					if stype == "enablepass" and spass.count("$") == 3
						print_good("#{thost}:#{tport} MD5 Encrypted Enable Password: #{shash}")
						store_loot("cisco.ios.enable_hash", "text/plain", thost, shash, "enable_password_hash.txt", "Cisco CatOS Enable Password Hash (MD5)")
					end

#
# SNMP IOS
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
# SNMP CatOS
#
				when /^\s*set snmp community (read-only|read-write|read-write-all) ([^\s]+)/i
					stype = $1.strip
					scomm = $2.strip
					print_good("#{thost}:#{tport} SNMP Community (#{stype}): #{scomm}")

					if stype.downcase == "read-only"
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

				# HSRP Authentication Key
				when /^standby \s* authentication md5 key-string ([^\s]+) ([^\s]+)/i
					stype = $1
					shash = $2

					if stype == 0
						print_good("#{thost}:#{tport} HSRP Authentication Key: #{shash}")
						store_loot("cisco.ios.hsrp_password", "text/plain", thost, shash, "hsrp_password.txt", "Cisco IOS HSRP Password")

						cred = cred_info.dup
						cred[:pass] = shash
						cred[:type] = "password"
						cred[:collect_type] = "password"
						store_cred(cred)
					end

					if stype == 7
						shash = cisco_ios_decrypt7(shash) rescue shash
						print_good("#{thost}:#{tport} HSRP Decrypted Key: #{shash}")
						store_loot("cisco.ios.hsrp_password", "text/plain", thost, shash, "hsrp_password.txt", "Cisco IOS HSRP Password")

						cred = cred_info.dup
						cred[:pass] = shash
						cred[:type] = "password"
						cred[:collect_type] = "password"
						store_cred(cred)
					end

				# CatOS/IOS TACACS Server Key Method 1
				when /^(set tacacs|tacacs-server) key ([^\s]+)$/i
					shash = $1

					print_good("#{thost}:#{tport} TACACS Server Key: #{shash}")
					store_loot("cisco.ios.tacacs_server_key", "text/plain", thost, shash, "tacacs_server_key.txt", "Cisco TACACS Server Key")

					cred = cred_info.dup
					cred[:pass] = shash
					cred[:type] = "password"
					cred[:collect_type] = "password"

				# CatOS/IOS TACACS Server Key Method 2
				when /^tacacs-server host ([^\s]+) key 7 ([^\s]+)$/i
					shost = $1
					shash = $2

					print_good("#{thost}:#{tport} TACACS Host #{shost} Key: #{shash}")
					store_loot("cisco.ios.tacacs_server_key", "text/plain", thost, "#{shost}:#{shash}", "tacacs_server_key.txt", "Cisco TACACS Server Key")

					cred = cred_info.dup
					cred[:pass] = shost
					cred[:pass] = shash
					cred[:type] = "password"
					cred[:collect_type] = "password"

				# CatOS/IOS RADIUS Server Key Method 1
				when /^(set radius|radius-server) key ([^\s]+)$/i
					shash = $1

					print_good("#{thost}:#{tport} RADIUS Server Key: #{shash}")
					store_loot("cisco.ios.radius_server_key", "text/plain", thost, shash, "radius_server_key.txt", "Cisco RADIUS Server Key")

					cred = cred_info.dup
					cred[:pass] = shash
					cred[:type] = "password"
					cred[:collect_type] = "password"

				# CatOS/IOS RADIUS Server Key Method 2
				when /^radius-server host ([^\s]+) key 7 ([^\s]+)$/i
					shash = $1

					print_good("#{thost}:#{tport} RADIUS Host #{shost} Key: #{shash}")
					store_loot("cisco.ios.radius_server_key", "text/plain", thost, "#{shost}:#{shash}", "radius_server_key.txt", "Cisco RADIUS Server Key")

					cred = cred_info.dup
					cred[:user] = shost
					cred[:pass] = shash
					cred[:type] = "password"
					cred[:collect_type] = "password"

				# IOS EIGRP Neighbor Password
				when /\s*key-string ([^\s]+)$/i
					shash = $1

					print_good("#{thost}:#{tport} EIGRP Neighbor Password: #{shash}")
					store_loot("cisco.ios.eigrp_neighbor_password", "text/plain", thost, shash, "eigrp_neighbor_password.txt", "Cisco IOS EIGRP Neighbor Password")

					cred = cred_info.dup
					cred[:pass] = shash
					cred[:type] = "password"
					cred[:collect_type] = "password"

				# NXOS HSRP Neighbor Password
				when /\s*key-string ([^\s]+) ([^\s]+)$/i
					stype = $1
					shash = $2

					if stype == 1
						print_good("#{thost}:#{tport} HSRP Authentication Key: #{shash}")
						store_loot("cisco.ios.hsrp_password", "text/plain", thost, shash, "hsrp_password.txt", "Cisco NXOS HSRP Password")

						cred = cred_info.dup
						cred[:pass] = shash
						cred[:type] = "password"
						cred[:collect_type] = "password"
					end

					if stype == 7
						shash = cisco_ios_decrypt7(shash) rescue shash
						print_good("#{thost}:#{tport} HSRP Decrypted Key: #{shash}")
						store_loot("cisco.ios.hsrp_password", "text/plain", thost, shash, "hsrp_password.txt", "Cisco NXOS HSRP Password")

						cred = cred_info.dup
						cred[:pass] = shash
						cred[:type] = "password"
						cred[:collect_type] = "password"
						store_cred(cred)
					end

				# IOS OSPF Neighbor Password
				when /^\s*ip ospf authentication-key ([^\s]+)$/i
					shash = $1

					print_good("#{thost}:#{tport} OSPF Neighbor Password: #{shash}")
					store_loot("cisco.ios.ospf_neighbor_password", "text/plain", thost, shash, "ospf_neighbor_password.txt", "Cisco IOS OSPF Neighbor Password")

					cred = cred_info.dup
					cred[:pass] = shash
					cred[:type] = "password"
					cred[:collect_type] = "password"

				when /^\s*ip ospf message-digest-key ([^\d]+) 1 md5 ([^\s]+)$/i
					sid = $1
					shash = $2

					print_good("#{thost}:#{tport} OSPF Neighbor Key #{sid} Password: #{shash}")
					store_loot("cisco.ios.ospf_neighbor_password", "text/plain", thost, "#{sid}:#{shash}", "ospf_neighbor_password.txt", "Cisco IOS OSPF Neighbor Password")

					cred = cred_info.dup
					cred[:user] = sid
					cred[:pass] = shash
					cred[:type] = "password"
					cred[:collect_type] = "password"

				# IOS BGP Neighbor Password
				when /^neighbor ([^\s]+) password ([^\s]+)$/i
					neighbor = $1
					shash = $2

					print_good("#{thost}:#{tport} BGP Neighbor '#{neighbor}' with Password: #{shash}")
					store_loot("cisco.ios.bgp_neighbor_password", "text/plain", thost, "#{neighbor}:#{shash}", "bgp_neighbor_password.txt", "Cisco IOS BGP Neighbor Password")

					cred = cred_info.dup
					cred[:user] = neighbor
					cred[:pass] = shash
					cred[:type] = "password"
					cred[:collect_type] = "password"

				# NXOS BGP Neighbor Password
				when /^password ([^\s]+) ([^\s]+)$/i
					stype = $1
					shash = $2

					if stype == 0
						print_good("#{thost}:#{tport} BGP Neighbor Password: #{shash}")
						store_loot("cisco.ios.bgp_neighbor_password", "text/plain", thost, shash, "bgp_neighbor_password.txt", "Cisco NXOS BGP Neighbor Password")

						cred = cred_info.dup
						cred[:user] = neighbor
						cred[:pass] = shash
						cred[:type] = "password"
						cred[:collect_type] = "password"
					end

					if stype == 3
						print_good("#{thost}:#{tport} BGP Neighbor 3DES Hash: #{shash}")
						store_loot("cisco.ios.bgp_neighbor_3des_hash", "text/plain", thost, shash, "bgp_neighbor_password.txt", "Cisco NXOS BGP Neighbor 3DES Hash")
					end

					if stype == 7
						shash = cisco_ios_decrypt7(shash) rescue shash
						print_good("#{thost}:#{tport} BGP Neighbor Decrypted Password: #{shash}")
						store_loot("cisco.ios.bgp_neighbor_password", "text/plain", thost, shash, "bgp_neighbor_password.txt", "Cisco NXOS BGP Neighbor Password")

						cred = cred_info.dup
						cred[:pass] = shash
						cred[:type] = "password"
						cred[:collect_type] = "password"
					end

			end
		end
	end

end
end
