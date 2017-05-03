##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
#   http://metasploit.com/framework/
##

require 'msf/core'
require 'rex'
require 'msf/core/post/common'
require 'msf/core/post/file'
require 'msf/core/post/linux/system'
require 'msf/core/post/linux/priv'

class Metasploit3 < Msf::Post

	include Msf::Post::Common
	include Msf::Post::File
	include Msf::Post::Linux::System


	def initialize(info={})
		super( update_info( info,
				'Name'          => 'Linux Upload File',
				'Description'   => %q{
					This module uploads a file.
				},
				'License'       => MSF_LICENSE,
				'Author'        =>
					[
						'Joshua D. Abraham <jabra[at]praetorian.com>',
					],
				'Platform'      => [ 'linux' ],
				'SessionTypes'  => [ 'shell' ]
			))
			register_options(
			[
				OptString.new('LOCALFILE', [true, 'Local file to upload.']),
				OptString.new('REMOTEFILE', [true, 'Remote file location to write.']),
				OptBool.new('REPLACE', [true, 'Replace the file if it exists.',true]),
			], self.class)
	end

	def run
		if file?(datastore['REMOTEFILE'])
			if datastore['REPLACE']
				file_rm(datastore['REMOTEFILE'])
			else
				print_error("File already exists")
				return
			end
		end

		data = ""
		file = File.new(datastore['LOCALFILE'],'r')
		while (line = file.gets)
			data << line.to_s
		end
		file.close

		if write_file(datastore['REMOTEFILE'],data)
			print_good("File uploaded!")
		else
			print_error("Error with file upload")
		end
	end
end
