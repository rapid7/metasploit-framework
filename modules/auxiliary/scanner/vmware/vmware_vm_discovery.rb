##
# $Id$
##

##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/framework/
##


require 'msf/core'
require 'msf/core/exploit/vim_soap'


class Metasploit3 < Msf::Auxiliary

	include Msf::Exploit::Remote::HttpClient
	include Msf::Auxiliary::Report
	include Msf::Exploit::Remote::VIMSoap
	include Msf::Auxiliary::Scanner

	def initialize
		super(
			'Name'           => 'VMWare Enumerate Virtual Machines',
			'Version'        => '$Revision$',
			'Description'    => %Q{
							This module attempts to discover virtual machines on any VMWare instance
							running the web interface. This would include ESX/ESXi and VMWare Server.},
			'Author'         => ['TheLightCosine <thelightcosine[at]metasploit.com>'],
			'License'        => MSF_LICENSE
		)

		register_options(
			[
				Opt::RPORT(443),
				OptString.new('USERNAME', [ true, "The username to Authenticate with.", 'root' ]),
				OptString.new('PASSWORD', [ true, "The password to Authenticate with.", 'password' ]),
				OptBool.new('SCREENSHOT', [true, "Wheter or not to try to take a screenshot", true])
			], self.class)
	end

	def run_host(ip)

		if vim_do_login(datastore['USERNAME'], datastore['PASSWORD']) == :success
			virtual_machines = vim_get_vms
			virtual_machines.each do |vm| 
				print_good YAML.dump(vm)
				report_note(
					:host  => rhost,
					:type  => "vmware.esx.vm",
					:data  => vm,
					:port  => rport,
					:proto => 'tcp',
					:update => :unique_data
				)
			end
			store_loot('ESX_virtualmachines', "text/plain", datastore['RHOST'], YAML.dump(virtual_machines) , "#{datastore['RHOST']}_esx_vms.txt", "VMWare ESX Virtual Machines")
		else
			print_error "Login Failure on #{ip}"
			return
		end
	end





end

