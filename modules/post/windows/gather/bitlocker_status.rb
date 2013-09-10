##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'
require 'msf/core/post/common'

class Metasploit4 < Msf::Post

	include Msf::Post::Common

	def initialize(info={})
		super(update_info(info,
			'Name'          => 'Windows Gather Show BitLocker Status',
			'Description'   => %q{This is a post module to show Windows BitLocker drive encryption status. This can be useful for compliance checking or reconnaissance before a physical pentest. It applies To: Windows 7, Windows 8, Windows Server 2008 R2, Windows Server 2012},
			'License'       => MSF_LICENSE,
			'Author'        => [ 'Sam Gaudet <msf[at]sgaudet.com>'],
			'Platform'      => [ 'win'],
			'SessionTypes'  => [ "shell", "meterpreter" ]
		))
	end

	# Checking Administrator status. The command "manage-bde" requires Admin privileges.
  def check_admin
    status = client.railgun.shell32.IsUserAnAdmin()
    return status['return']
  end
	
	#
	# This post module runs BitLocker Drive Encryption status check command and returns the output.
	#
	def run
    #Make sure we are on a Windows host
    if client.platform !~ /win32|win64/
        print_status "This module is designed for Windows hosts."
        return
    end

    # Check admin status
    admin = check_admin
    if admin == false
      print_error("Must be an admin to run manage-bde.exe, exiting")
      return
    end

		print_status("Checking BitLocker Drive Encryption")
		output = cmd_exec("manage-bde -status")
		print_status(output)
	end

end
