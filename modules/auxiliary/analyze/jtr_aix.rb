##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
#
##


require 'msf/core'

class Metasploit3 < Msf::Auxiliary

	include Msf::Auxiliary::JohnTheRipper

	def initialize
		super(
			'Name'            => 'John the Ripper AIX Password Cracker',
			'Description'     => %Q{
					This module uses John the Ripper to identify weak passwords that have been
				acquired from passwd files on AIX systems.
			},
			'Author'          =>
				[
					'theLightCosine',
					'hdm'
				] ,
			'License'         => MSF_LICENSE  # JtR itself is GPLv2, but this wrapper is MSF (BSD)
		)

	end

	def run
		wordlist = Rex::Quickfile.new("jtrtmp")

		wordlist.write( build_seed().join("\n") + "\n" )
		wordlist.close

		hashlist = Rex::Quickfile.new("jtrtmp")

		myloots = myworkspace.loots.find(:all, :conditions => ['ltype=?', 'aix.hashes'])
		unless myloots.nil? or myloots.empty?
			myloots.each do |myloot|
				begin
					usf = File.open(myloot.path, "rb")
				rescue Exception => e
					print_error("Unable to read #{myloot.path} \n #{e}")
					next
				end
				usf.each_line do |row|
					row.gsub!(/\n/, ":#{myloot.host.address}\n")
					hashlist.write(row)
				end

				usf.close
			end
			hashlist.close

			print_status("HashList: #{hashlist.path}")

			print_status("Trying Format:des Wordlist: #{wordlist.path}")
			john_crack(hashlist.path, :wordlist => wordlist.path, :rules => 'single', :format => 'des')
			print_status("Trying Format:des Rule: All4...")
			john_crack(hashlist.path, :incremental => "All4", :format => 'des')
			print_status("Trying Format:des Rule: Digits5...")
			john_crack(hashlist.path, :incremental => "Digits5", :format => 'des')

			cracked = john_show_passwords(hashlist.path)


			print_status("#{cracked[:cracked]} hashes were cracked!")

			cracked[:users].each_pair do |k,v|
				if v[0] == "NO PASSWORD"
					passwd=""
				else
					passwd=v[0]
				end
				print_good("Host: #{v.last}  User: #{k} Pass: #{passwd}")
				report_auth_info(
					:host  => v.last,
					:port => 22,
					:sname => 'ssh',
					:user => k,
					:pass => passwd
				)
			end
		end

	end

end
