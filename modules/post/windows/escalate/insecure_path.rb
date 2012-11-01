##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'
require 'rex'

class Metasploit3 < Msf::Post

	include Msf::Post::File
	include Msf::Post::Windows::Priv
	include Msf::Post::Windows::Registry

	def initialize(info={})
		super( update_info( info,
			'Name'          => 'Current User Insecure Path Enumeration',
			'Description'   => %q{
				This module checks every directory in the system PATH for write permissions.
				This can be used to help escalate privileges through the process of binary planting
				due to the way DLLs are loaded within windows.
			},
			'License'       => MSF_LICENSE,
			'Author'        => [ 'Ben Campbell <eat_meatballs[at]hotmail.co.uk>' ],
			'Version'       => '$Revision$',
			'Platform'      => [ 'windows' ],
			'SessionTypes'  => [ 'meterpreter' ],
			'References'    => [
				[ 'URL', 'http://www.binaryplanting.com' ]
			]
		))

			register_options([
				OptBool.new("VERBOSE",   [ false, "Verbose", false])
			])
	end

	def run
		if is_uac_enabled?
			# write_file and file_exist? will return true as windows
			# returns a handle for files even though UAC popup is pending.
			print_error("Unable to process with UAC enabled.")
			return
		end

		if is_admin?
			print_error("Current user is an admin, aborting.")
			return
		end

		if is_system?
			print_error("Current user is SYSTEM, aborting.")
			return
		end

		print_status("Checking SYSTEM PATH folders for write access...")
		result  = registry_getvaldata('HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Environment', 'Path')
		paths = result.split(';')

		paths.each do |p|
			path = expand_path(p)
			if exist?(path)
				filename = "#{path}\\#{Rex::Text.rand_text_alpha(10)}"
				vprint_status("Creating file #{filename}")
				begin
					if write_file(filename, "") and file_exist?(filename) # This will not work against UAC
						print_good("Write permissions in #{path}")
						begin
								file_rm(filename)
								vprint_status("Deleted file #{filename}")
						rescue ::Exception => e
							print_error("Error deleting #{filename} : #{e}") # Warn users if cleanup fails
						end
					end
				rescue ::Exception => e
					vprint_status("Unable to create #{filename} : #{e}")
				end
			else
				# User may be able to create the path!
				# exist? appears to have some false positives
				print_good("Path #{path} does not exist...")
			end
		end
	end
end
