##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/framework/
##


require 'msf/core'


class Metasploit3 < Msf::Auxiliary

	include Msf::Exploit::Remote::Tcp
	include Msf::Auxiliary::Scanner
	include Msf::Auxiliary::Report

	def initialize
		super(
			'Name'        => 'Finger Service User Enumerator',
			'Version'     => '$Revision$',
			'Description' => 'Identify valid users through the finger service using a variety of tricks',
			'Author'      => 'hdm',
			'License'     => MSF_LICENSE
		)
		register_options([
			Opt::RPORT(79),
			OptString.new('USERS_FILE',
				[ true, 'The file that contains a list of default UNIX accounts.',
					File.join(Msf::Config.install_root, 'data', 'wordlists', 'unix_users.txt')
				]
			)], self.class)
	end

	def run_host(ip)
		@users = {}

		begin
			finger_empty
			finger_zero
			finger_dot
			finger_chars
			finger_list

		rescue ::Rex::ConnectionError
		rescue ::Exception => e
			print_error("#{e} #{e.backtrace}")
		end

		print_status("#{ip} #{@users.keys.sort.join(", ")}") if not @users.empty?
	end


	def finger_empty
		connect
		sock.put("\r\n")
		buff = finger_slurp_data
		parse_users(buff)
	end

	def finger_zero
		connect
		sock.put("0\r\n")
		buff = finger_slurp_data
		parse_users(buff)
	end

	def finger_dot
		connect
		sock.put(".\r\n")
		buff = finger_slurp_data
		parse_users(buff)
	end

	def finger_chars
		connect
		sock.put("m m m m m m m m\r\n")
		buff = finger_slurp_data
		parse_users(buff)
	end

	def finger_list
		finger_user_common.each do |user|
			next if @users[user]
			connect
			sock.put("#{user}\r\n")
			buff = finger_slurp_data
			parse_users(buff)
		end
	end

	def finger_slurp_data
		buff = ""
		begin
			while(res = sock.get_once(-1, 5))
				buff << res
				break if buff.length > (1024*1024)
			end
		rescue ::Interrupt
			raise $!
		rescue ::Exception
		end
		buff
	end

	def finger_user_common
		if(! @common)
			File.open(datastore['USERS_FILE'], "r") do |fd|
				data = fd.read(fd.stat.size)
				@common = data.split(/\n/)
			end
		end
		@common
	end

	def parse_users(buff)
		buff.each_line do |line|
			next if line.strip.empty?

			# Ignore Cisco systems
			break if line =~ /Line.*User.*Host.*Location/

			next if line =~ /user not found/i
			next if line =~ /no such user/i
			next if line =~ /must provide username/
			next if line =~ /real life: \?\?\?/
			next if line =~ /No one logged on/
			next if line =~ /^Login\s+Name\s+TTY/

			# print_status(">> #{line}")

			# No such file or directory == valid user bad utmp

			# Solaris
			if(line =~ /^([a-z0-9\.\_]+)\s+([^\s]+)\s+([^\s]+)\s+([^\s]+)\s+([^\s]+)/)
				uid = $1
				if ($2 != "Name")
					@users[uid] ||= {}
					next
				end
			end

			# IRIX
			if(line =~ /^\s*Login name:\s*([^\s]+)\s+/i)
				@users[$1] ||= {}
				next
			end
		end
	end
end

