##
# ## This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'rex'
require 'msf/core'
require 'msf/core/auxiliary/report'

class Metasploit3 < Msf::Post

	include Msf::Auxiliary::Report

	def initialize(info={})
		super( update_info( info,
				'Name'	       => 'Windows Gather Enumerate Active Directory Computers',
				'Description'  => %q{
						This module will enumerate computers in the default AD directory.

						Optional Attributes to use in ATTRIBS:
						objectClass, cn, description, distinguishedName, instanceType, whenCreated,
						whenChanged, uSNCreated, uSNChanged, name, objectGUID,
						userAccountControl, badPwdCount, codePage, countryCode,
						badPasswordTime, lastLogoff, lastLogon, localPolicyFlags,
						pwdLastSet, primaryGroupID, objectSid, accountExpires,
						logonCount, sAMAccountName, sAMAccountType, operatingSystem,
						operatingSystemVersion, operatingSystemServicePack, serverReferenceBL,
						dNSHostName, rIDSetPreferences, servicePrincipalName, objectCategory,
						netbootSCPBL, isCriticalSystemObject, frsComputerReferenceBL,
						lastLogonTimestamp, msDS-SupportedEncryptionTypes
				},
				'License'      => MSF_LICENSE,
				'Author'       => [ 'Ben Campbell <eat_meatballs[at]hotmail.co.uk>' ],
				'Platform'     => [ 'win' ],
				'SessionTypes' => [ 'meterpreter' ]
			))

		register_options([
			OptInt.new('MAX_SEARCH', [true, 'Maximum values to retrieve, 0 for all.', 0]),
			OptBool.new('STORE', [true, 'Store file in loot.', false]),
			OptString.new('ATTRIBS', [true, 'Attributes to retrieve.', 'dNSHostName,distinguishedName,description,operatingSystem'])
		], self.class)
	end

	def run
		print_status("Connecting to default LDAP server")
		session_handle = bind_default_ldap_server

		return false unless session_handle

		print_status("Querying default naming context")

		query_result = query_ldap(session_handle, "", 0, "(objectClass=computer)", ["defaultNamingContext"])
		first_entry_attributes = query_result[0]['attributes']
		defaultNamingContext = first_entry_attributes[0]['values'] # Value from First Attribute of First Entry

		print_status("Default Naming Context #{defaultNamingContext}")

		attributes = datastore['ATTRIBS'].split(',')

		print_status("Querying computer objects - Please wait...")
		results = query_ldap(session_handle, defaultNamingContext, 2, "(objectClass=computer)", attributes)

		print_status("Unbinding from LDAP service.")
		wldap32.ldap_unbind(session_handle)

		if results.nil? or results.empty?
			return
		end

		results_table = Rex::Ui::Text::Table.new(
				'Header'     => 'AD Computers',
				'Indent'     => 1,
				'SortIndex'  => -1,
				'Columns'    => attributes
			)

		results.each do |result|
			row = []

			result['attributes'].each do |attr|
				if attr['values'].nil?
					row << ""
				else
					row << attr['values']
				end
			end

			results_table << row

		end

		print_line results_table.to_s
		if datastore['STORE']
			stored_path = store_loot('ad.computers', 'text/plain', session, results_table.to_csv)
			print_status("Results saved to: #{stored_path}")
		end
	end

	def wldap32
		return client.railgun.wldap32
	end

	def bind_default_ldap_server
		vprint_status ("Initializing LDAP connection.")
		session_handle = wldap32.ldap_sslinitA("\x00\x00\x00\x00", 389, 0)['return']
		vprint_status("LDAP Handle: #{session_handle}")

		if session_handle == 0
			print_error("Unable to connect to LDAP server")
			wldap32.ldap_unbind(session_handle)
			return false
		end

		vprint_status ("Binding to LDAP server.")
		bind = wldap32.ldap_bind_sA(session_handle, nil, nil, 0x0486)['return'] #LDAP_AUTH_NEGOTIATE 0x0486

		if bind != 0
			print_error("Unable to bind to LDAP server")
			wldap32.ldap_unbind(session_handle)
			return false
		end

		return session_handle
	end

	# Get BERElement data structure from LDAPMessage
	def get_ber(pEntry)
		msg = client.railgun.memread(pEntry,41).unpack('LLLLLLLLLSCCC')
		ber = client.railgun.memread(msg[2],60).unpack('L*')
		ber_data = client.railgun.memread(ber[3], ber[0]+1)
		return ber_data
	end

	# Search through the BER for our Attr string. Pull the values.
	def get_values_from_ber(ber_data, attr)
		attr_offset = ber_data.index(attr)

		if attr_offset.nil?
			vprint_status("Attribute not found in BER.")
			return nil
		end

		# Value starts after our attribute string
		values_offset = attr_offset + attr.length
		values_start_offset = values_offset + 8
		values_len_offset = values_offset + 5
		curr_len_offset = values_offset + 7

		values_length =  ber_data[values_len_offset].unpack('C')[0]
		values_end_offset = values_start_offset + values_length

		curr_length = ber_data[curr_len_offset].unpack('C')[0]
		curr_start_offset = values_start_offset
		curr_end_offset = curr_start_offset + curr_length

		values = []
		while (curr_end_offset < values_end_offset)
			values << ber_data[curr_start_offset..curr_end_offset]

			break unless ber_data[curr_end_offset] == "\x04"

			curr_len_offset = curr_end_offset + 1
			curr_length = ber_data[curr_len_offset].unpack('C')[0]
			curr_start_offset = curr_end_offset + 2
			curr_end_offset = curr_end_offset + curr_length + 2
		end

		# Strip trailing 0 or \x04 which is used to delimit values
		values.map! {|x| x[0..x.length-2]}

		return values
	end

	def query_ldap(session_handle, base, scope, filter, attributes)
		vprint_status ("Searching LDAP directory.")
		search = wldap32.ldap_search_sA(session_handle, base, scope, filter, nil, 0, 4)
		vprint_status("search: #{search}")

		if search['return'] != 0
			print_error("No results")
			wldap32.ldap_msgfree(search['res'])
			return
		end

		search_count = wldap32.ldap_count_entries(session_handle, search['res'])['return']

		if(search_count == 0)
			print_error("No entries retrieved")
			wldap32.ldap_msgfree(search['res'])
			return
		end

		print_status("Entries retrieved: #{search_count}")

		vprint_status("Retrieving results...")

		entries = {}
		entry_results = []

		if datastore['MAX_SEARCH'] == 0
			max_search = search_count
		else
			max_search = [datastore['MAX_SEARCH'], search_count].min
		end

		0.upto(max_search - 1) do |i|

			if(i==0)
				entries[0] = wldap32.ldap_first_entry(session_handle, search['res'])['return']
			else
				entries[i] = wldap32.ldap_next_entry(session_handle, entries[i-1])['return']
			end

			if(entries[i] == 0)
				print_error("Failed to get entry.")
				wldap32.ldap_unbind(session_handle)
				wldap32.ldap_msgfree(search['res'])
				return
			end

			vprint_status("Entry #{i}: 0x#{entries[i].to_s(16)}")
			ber = get_ber(entries[i])

			attribute_results = []
			attributes.each do |attr|
				vprint_status("Attr: #{attr}")
				value_results = ""

				values = get_values_from_ber(ber, attr)

				values_result = ""
				values_result = Rex::Text.to_hex_ascii(values.join(',')) unless values.nil?
				vprint_status("Values #{values}")

				attribute_results << {"name" => attr, "values" => values_result}
			end

			entry_results << {"id" => i, "attributes" => attribute_results}
		end

		return entry_results
	end
end

