##
# ## This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'
require 'rex'

# Multi platform requiere
require 'msf/core/post/common'
require 'msf/core/post/file'

require 'msf/core/post/windows/registry'

class Metasploit3 < Msf::Post

	include Msf::Post::Common
	include Msf::Post::File

	include Msf::Post::Windows::Registry

	def initialize(info={})
		super( update_info( info,
				'Name'         => 'Windows Gather AD Enumerate Computers',
				'Description'  => %q{
						This module will enumerate computers included in the primary Domain.
				},
				'License'      => MSF_LICENSE,
				'Author'       => [ 'Ben Campbell <eat_meatballs[at]hotmail.co.uk>'],
				'Platform'     => [ 'win'],
				'SessionTypes' => [ 'meterpreter' ]
			))
	end
	
	def read_value(addr)
		val_size = client.railgun.memread(addr-4,4).unpack('V*')[0]
		value = client.railgun.memread(addr, val_size)
		return value.strip
	end

	def run
	
		attributes = [ 'dNSHostName', 'distinguishedName', 'description', 'operatingSystem', 'operatingSystemServicePack', 'serverReferenceBL', 'userAccountControl']
		#attributes = [	'objectClass','cn', 'description', 'distinguishedName','instanceType','whenCreated',
		#				'whenChanged','uSNCreated','uSNChanged','name','objectGUID',
		#				'userAccountControl','badPwdCount','codePage','countryCode',
		#				'badPasswordTime','lastLogoff','lastLogon','localPolicyFlags',
		#				'pwdLastSet','primaryGroupID','objectSid','accountExpires',
		#				'logonCount','sAMAccountName','sAMAccountType','operatingSystem',
		#				'operatingSystemVersion','operatingSystemServicePack','serverReferenceBL',
		#				'dNSHostName','rIDSetPreferences','servicePrincipalName','objectCategory',
		#				'netbootSCPBL','isCriticalSystemObject','frsComputerReferenceBL',
		#				'lastLogonTimestamp','msDS-SupportedEncryptionTypes'
		#			]
					
		print_status("Running module against #{sysinfo['Computer']}") if not sysinfo.nil?

		wldap32 = client.railgun.wldap32
		
		print_status ("Initialize LDAP connection.")
		ldap_handle = wldap32.ldap_sslinitA(nil, 389, 0)['return']
		vprint_status("LDAP Handle: #{ldap_handle}")

		print_status ("Bindings to LDAP server.")
		bind = wldap32.ldap_bind_sA(ldap_handle, nil, nil, 0x0486) #LDAP_AUTH_NEGOTIATE
		
		print_status ("Searching LDAP directory.")

		base = "DC=test,DC=lab"
		scope = 2 #LDAP_SCOPE_SUBTREE

		search = wldap32.ldap_search_sA(ldap_handle, base, scope, "(objectClass=computer)", nil, 0, 4) 
		vprint_status("search: #{search}")
		
		if search['return'] != 0
			print_error("No results")
			wldap32.ldap_msgfree(search['res'])
			return
		end

		search_count = wldap32.ldap_count_entries(ldap_handle, search['res'])['return']
		print_status("Entries retrieved: #{search_count}")
	
		
		print_status("Retrieving results...")
		
		entries = {}
		for i in 0..(search_count-1)
			print_line "-"*46
			if i==0
				entries[i] = wldap32.ldap_first_entry(ldap_handle, search['res'])['return']
			else
				entries[i] = wldap32.ldap_next_entry(ldap_handle, entries[i-1])['return']
			end
			vprint_status("Entry #{i}: #{entries[i]}")
			
			attributes.each do |attr|
				print_status("Attr: #{attr}")
				
				pp_value = wldap32.ldap_get_values(ldap_handle, entries[i], attr)['return']
				vprint_status("ppValue: 0x#{pp_value.to_s(16)}")
				
				if pp_value == 0
					vprint_error("No attribute value returned.")
				else						
					count = wldap32.ldap_count_values(pp_value)['return']
					vprint_status "Value count: #{count}"
				
					if count < 1
						vprint_error("Bad Value List")
					else
						for j in 0..(count-1)
							p_value = client.railgun.memread(pp_value+(j*4), 4).unpack('V*')[0]
							vprint_status "p_value: 0x#{p_value.to_s(16)}"
							value = read_value(p_value)
							print_status "Value: #{value}"
						end
					end
				end

				if pp_value != 0
					vprint_status("Free value memory.")
					wldap32.ldap_value_free(pp_value)
				end
			end
		end
	end
end
