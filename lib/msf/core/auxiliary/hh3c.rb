# -*- coding: binary -*-
module Msf

###
#
# This module provides methods for working with Huawei/HP/H3C equipment
#
# Currently is supports only the basic locally configured users, super
# password and SNMP community strings.
#
###

module Auxiliary::HH3C
	include Msf::Auxiliary::Report

	def h3c_config_eater(thost, tport, config)

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

		store_loot("hh3c.config", "text/plain", thost, config.strip, "config.txt", "Huawei/H3C Configuration")

		# since configuration sections span multiple lines we use a hash
		# to keep track of what we're looking for:
		#   sect = { local-user, con, vty }
		#   uname = "username"
		#   level = { 0, 1, 2, 3 }
		# some commands are single-line like routing auth, vpn, etc

		confhash = {
			:sect => "",
			:uname => "",
			:level => "",
		}

		config.each_line do |line|
			case line
				when /^#/i
					# comment / end of section
					confhash['sect'] = ""
					confhash['uname'] = ""
					confhash['level'] = ""

				when /^\ssuper password level (\d) (simple|cipher) (.*)/i
					# super password
					level = $1
					pwtype = $2
					pwval = $3.strip

					print_good("#{thost}:#{tport} super-password: #{pwval}")
					cred = cred_info.dup
					cred[:pass] = pwval
					cred[:type] = "password"
					cred[:collect_type] = "password"
					store_cred(cred)

				when /^local user (.*)/i
					# local-users section
					confhash['sect'] = 'local-user'
					confhash['uname'] = $2.strip

				when /^\suser-interface (con|vty) (.*)/i
					# console/vty password section
					confhash['sect'] = $1.strip
					confhash['uname'] = ""

				when /^\spassword (simple|cipher|sha256) (.*)/i
					# an actual password entry, could be in multiple sections
					pwtype = $1
					pwval = $2.strip

					print_good("#{thost}:#{tport} Local user: #{confhash['uname']} password: #{pwval}")
					cred = cred_info.dup
					cred[:user] = confhash['uname']
					cred[:pass] = pwval
					cred[:type] = "password"
					cred[:collect_type] = "password"
					store_cred(cred)

				# SNMP community strings
				when /^\ssnmp-agent community (read|write) (.*)/i
					stype = $1.strip
					scomm = $2.strip
					print_good("#{thost}:#{tport} SNMP Community (#{stype}): #{scomm}")

					if stype.downcase == "read"
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

			end
		end
	end

end
end
