##
# $Id$
##

##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/framework/
##

require 'rex'
require 'msf/core'
require 'msf/core/post/file'
require 'msf/core/post/windows/registry'

class Metasploit3 < Msf::Post

	include Msf::Auxiliary::Report
	include Msf::Post::File
	include Msf::Post::Windows::Registry
	
	def initialize(info={})
		super( update_info( info,
			'Name'          => 'Windows File and Registry Artifacts Enumeration',
			'Description'   => %q{ This module will check the file system and registry for particular artifacts. The 
								   list of artifacts is read from data/post/artifacts or a user specified file. Any
								   matches are written to the loot. },
			'License'       => MSF_LICENSE,
			'Author'        => [ 'averagesecurityguy <stephen[at]averagesecurityguy.info>' ],
			'Version'       => '$Revision$',
			'Platform'      => [ 'windows' ],
			'SessionTypes'  => [ 'meterpreter' ]
		))
		register_options(
			[
				OptPath.new('ARTIFACTS', [false, 'Full path to artifacts file.', nil]),
			], self.class)

	end

	def run
		# Store any found artifacts so they can be written to loot
		found = Array.new

		if datastore['ARTIFACTS']
			filename = datastore['ARTIFACTS']
		else
			filename = ::File.join(Msf::Config.data_directory, 'post',  'artifacts')
			print_line(filename)
		end
		
		if ::File.exists?(filename)
			print_status("Processing artifacts file...")
			
			file = ::File.open(filename, "r")
			file.each_line do |line|
			    line.strip!
				next if line.length < 1
				next if line[0,1] == "#"
				
				if line =~ /^reg/
					type, reg_key, val, data = line.split("|")
					reg_data = registry_getvaldata(reg_key, val)
			        if reg_data.to_s == data
						found << "Matching registry entry: #{reg_key}\\#{val}"
					end
				end
				
				if line =~ /^file/
					type, file, hash = line.split("|")
					digest = file_remote_digestmd5(file)
					if digest == hash then found << "Matching file entry: #{file}" end
				end
			end

			print_status("Artifacts file processed successfully.")
		else
			print_error("Artifacts file does not exist!")
		end

		if found.length > 0
			print_status("Artifacts found, saving to loot")

			# Store artifacts in the loot.
			loot_file = store_loot( 'enumerated.artifacts',
									'text/plain', 
									session, 
									found.join("\n"), 
									nil,
									'Enumerated Artifacts')
									
			print_status("Enumerated artifacts stored in #{loot_file}")

		else
			print_status("No artifacts found.")
		end
	end

end

