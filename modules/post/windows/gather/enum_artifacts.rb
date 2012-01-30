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
			'Description'   => %q{
				This module will check the file system and registry for particular artifacts. The
				list of artifacts is read from data/post/artifacts or a user specified file. Any
				matches are written to the loot. },
			'License'       => MSF_LICENSE,
			'Author'        => [ 'averagesecurityguy <stephen[at]averagesecurityguy.info>' ],
			'Platform'      => [ 'windows' ],
			'SessionTypes'  => [ 'meterpreter' ]
		))

		register_options(
			[
				OptPath.new( 'ARTIFACTS',
					[
						true,
						'Full path to artifacts file.',
						::File.join(Msf::Config.data_directory, 'post', 'enum_artifacts_list.txt')
					])
			], self.class)
	end

	def run
		# Store any found artifacts so they can be written to loot
		files_found = []
		reg_found   = []

		# Check artifacts file path
		filename = datastore['ARTIFACTS']
		if not ::File.exists?(filename)
			print_error("Artifacts file does not exist!")
			return
		end

		# Start enumerating
		print_status("Processing artifacts file...")
		file = ::File.open(filename, "rb")
		file.each_line do |line|
			line.strip!
			next if line.length < 1
			next if line[0,1] == "#"

			# Check registry
			if line =~ /^reg/
				type, reg_key, val, data = line.split("|")
				reg_data = registry_getvaldata(reg_key, val)
				if reg_data.to_s == data
					reg_found << "#{reg_key}\\#{val}"
				end
			end

			# Check file
			if line =~ /^file/
				type, file, hash = line.split("|")
				digest = file_remote_digestmd5(file)
				if digest == hash
					files_found << file
				end
			end
		end

		# Reporting.  In case the user wants to separte artifact types (file vs registry),
		# we've already done it at this point.
		if files_found.empty?
			print_status("No file artifacts found")
		else
			save(files_found, "Enumerated File Artifacts")
		end

		if reg_found.empty?
			print_status("No registry artifacts found")
		else
			save(reg_found, "Enumerated Registry Artifacts")
		end
	end

	def save(data, name)
		f = store_loot('enumerated.artifacts', 'text/plain', session, data.join("\n"), name)
		print_status("#{name} stored in: #{f}")
	end

end

=begin
To-do: Use CSV or yaml format to store enum_artifacts_list.txt
=end
