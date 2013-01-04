##
# ## This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'
require 'rex'
require 'msf/core/post/common'
require 'msf/core/post/file'
require 'msf/core/post/solaris/priv'

class Metasploit3 < Msf::Post

	include Msf::Post::Common
	include Msf::Post::File
	include Msf::Post::Solaris::Priv


	def initialize(info={})
		super( update_info( info,
				'Name'          => 'Solaris Gather Virtual Environment Detection',
				'Description'   => %q{
					This module attempts to determine whether the system is running
					inside of a virtual environment and if so, which one. This
					module supports detectoin of Solaris Zone, VMWare, VirtualBox, Xen,
					and QEMU/KVM.},
				'License'       => MSF_LICENSE,
				'Author'        => [ 'Carlos Perez <carlos_perez[at]darkoperator.com>'],
				'Platform'      => [ 'solaris' ],
				'SessionTypes'  => [ 'shell' ]
			))
	end

	# Run Method for when run command is issued
	def run
		print_status("Gathering System info ....")
		vm = nil
		kernel_type = cmd_exec("uname -v")

		if kernel_type =~ /Generic_Virtual/i
			vm = "Solaris Zone"
		end

		if not vm

			prt_diag = cmd_exec("/usr/sbin/prtdiag -v").gsub("\n"," ")

			case prt_diag
			when /virtualbox/i
				vm = "VirtualBox"
			when /vmware/i
				vm = "VMware"
			when /xen/i
				vm =  "Xen"
			when /qemu/i
				vm = "Qemu/KVM"
			end
		end

		if vm
			print_good("This appears to be a #{vm} Virtual Machine")
		else
			print_status("This appears to be a Physical Machine")
		end

	end



end
