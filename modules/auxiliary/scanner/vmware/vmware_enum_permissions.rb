##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##


require 'msf/core'
require 'rex/proto/ntlm/message'


class Metasploit3 < Msf::Auxiliary
	include Msf::Exploit::Remote::VIMSoap
	include Msf::Exploit::Remote::HttpClient
	include Msf::Auxiliary::Report
	include Msf::Auxiliary::Scanner

	def initialize
		super(
			'Name'           => 'VMWare Enumerate Permissions',
			'Description'    => %Q{
				This module will log into the Web API of VMWare and try to enumerate
				all the user/group permissions. Unlike enum suers this is only
				users and groups that specifically have permissions defined within
				the VMware product
			},
			'Author'         => ['theLightCosine'],
			'License'        => MSF_LICENSE
		)

		register_options(
			[
				Opt::RPORT(443),
				OptString.new('USERNAME', [ true, "The username to Authenticate with.", 'root' ]),
				OptString.new('PASSWORD', [ true, "The password to Authenticate with.", 'password' ])
			], self.class)

		register_advanced_options([OptBool.new('SSL', [ false, 'Negotiate SSL for outgoing connections', true]),])
	end


	def run_host(ip)
		if vim_do_login(datastore['USERNAME'], datastore['PASSWORD']) == :success
			role_map = {}
			esx_roles = vim_get_roles
			case esx_roles
			when :noresponse
				print_error "Recieved no Response from #{ip}"
			when :expired
				print_error "The login session appears to have expired on #{ip}"
			when :error
				print_error "An error occured while trying to enumerate the roles on #{ip}"
			else
				esx_roles.each do |role|
					role_map[role['roleId']] = {
						"name" => role['name'],
						"system" => role['system'],
						"summary" => role['info']['summary']
					}
				end
			end

			esx_permissions = vim_get_all_permissions
			case esx_permissions
			when :noresponse
				print_error "Recieved no Response from #{ip}"
			when :expired
				print_error "The login session appears to have expired on #{ip}"
			when :error
				print_error "An error occured while trying to enumerate the permissions on #{ip}"
			else
				tmp_perms = Rex::Ui::Text::Table.new(
						'Header'  => "Permissions for VMWare #{ip}",
						'Indent'  => 1,
						'Columns' => ['Name', 'IsAGroup', 'Role', 'Role Summary']
					)
				esx_permissions.each do |perm|
					role_name = role_map[perm['roleId']]['name']
					role_summary = role_map[perm['roleId']]['summary']
					tmp_perms << [perm['principal'], perm['group'], role_name , role_summary]
				end
				print_good tmp_perms.to_s

				f = store_loot('host.vmware.permissions', "text/plain", datastore['RHOST'], tmp_perms.to_csv , "#{datastore['RHOST']}_esx_permissions.txt", "VMWare ESX Permissions")
				vprint_status("Permission info stored in: #{f}")
			end
		else
			print_error "Login Failure on #{ip}"
			return
		end
	end

end
