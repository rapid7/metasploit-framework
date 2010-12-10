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

		store_loot("cisco.ios.config", "text/plain", thost, config.strip, "config.txt", "Cisco IOS Configuration")

		config.each_line do |line|
			case line
				when /^\s*enable secret (\d+) (.*)/i
					stype = $1.to_i
					shash = $2.strip
				
					if stype == 5
						print_good("MD5 Encrypted Enable Password: #{shash}")
						store_loot("cisco.ios.enable_hash", "text/plain", thost, shash, "enable_password_hash.txt", "Cisco IOS Enable Password Hash (MD5)")
					end

					if stype == 7
						shash = cisco_decrypt7(shash) rescue shash
						print_good("Decrypted Enable Password: #{shash}")
						store_loot("cisco.ios.enable_pass", "text/plain", thost, shash, "enable_password.txt", "Cisco IOS Enable Password")
					
						cred = cred_info.dup
						cred[:pass] = shash
						cred[:type] = "cisco_enable"
						cred[:collect_type] = "cisco_enable"
						store_cred(cred)		
					end		
				
				when /^\s*enable password (.*)/i
					spass = $1.strip
					print_good("Unencrypted Enable Password: #{spass}")
			
					cred = cred_info.dup
					cred[:pass] = spass
					cred[:type] = "cisco_enable"
					cred[:collect_type] = "cisco_enable"
					store_cred(cred)
							
				when /\s*snmp-server community ([^\s]+) (RO|RW)/i
					stype = $2.strip
					scomm = $1.strip
					print_good("SNMP Community (#{stype}): #{scomm}")
			
					cred = cred_info.dup
					cred[:sname] = "snmp"
					cred[:pass] = scomm
					cred[:type] = "password"
					cred[:collect_type] = "password"
					cred[:proto] = "udp"
					cred[:port]  = 161
					store_cred(cred)	
					
				when /\s*password ([^\s]+)/i
					spass = $1.strip
					print_good("Unencrypted VTY Password: #{spass}")
					cred = cred_info.dup
					cred[:pass] = spass
					cred[:type] = "password"
					cred[:collect_type] = "password"
					store_cred(cred)			
			end
		end
	end

end
end
