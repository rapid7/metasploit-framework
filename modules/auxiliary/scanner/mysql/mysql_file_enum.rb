##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'
require 'yaml'

class Metasploit3 < Msf::Auxiliary

	include Msf::Exploit::Remote::MYSQL
	include Msf::Auxiliary::Report
	include Msf::Auxiliary::Scanner

	def initialize
		super(
			'Name'           => 'MYSQL File/Directory Enumerator',
			'Description'    => %Q{
					Enumerate files and directories using the MySQL load_file feature, for more information see the URL in the references.
			},
			'Author'         => [ 'Robin Wood <robin[at]digininja.org>' ],
			'References'  => [
								[ 'URL', 'http://pauldotcom.com/2013/01/mysql-file-system-enumeration.html' ],
								[ 'URL', 'http://www.digininja.org/projects/mysql_file_enum.php' ]
							],
			'License'        => MSF_LICENSE
		)

		register_options([
			OptPath.new('FILE_LIST', [ true, "List of directories to enumerate", '' ]),
			OptString.new('DATABASE_NAME', [ true, "Name of database to use", 'test' ]),
			OptString.new('TABLE_NAME', [ true, "Name of table to use - Warning, if the table already exists its contents will be corrupted", Rex::Text.rand_text_alpha(8) ]),
			OptString.new('USERNAME', [ true, 'The username to authenticate as', "root" ])
			])

	end

	def run_host(ip)
		print_status("Checking " + ip)

		if (not mysql_login_datastore)
			return
		end

		begin
			mysql_query_no_handle("USE " + datastore['DATABASE_NAME'])
		rescue ::RbMysql::Error => e
			print_error("MySQL Error: #{e.class} #{e.to_s}")
			return
		rescue Rex::ConnectionTimeout => e
			print_error("Timeout: #{e.message}")
			return
		end

		res = mysql_query("SELECT * FROM information_schema.TABLES WHERE TABLE_SCHEMA = '" + datastore['DATABASE_NAME'] + "' AND TABLE_NAME = '" + datastore['TABLE_NAME'] + "';")
		table_exists = (res.size == 1)

		if !table_exists
			print_status("Table doesn't exist so creating it")
			mysql_query("CREATE TABLE " + datastore['TABLE_NAME'] + " (brute int);")
		end

		file = File.new(datastore['FILE_LIST'], "r")
		file.each_line do |line|
			check_dir(line.chomp)
		end

		if !table_exists
			print_status("Cleaning up the temp table")
			mysql_query("DROP TABLE " + datastore['TABLE_NAME'])
		end
	end

	def check_dir dir
		begin
			res = mysql_query_no_handle("LOAD DATA INFILE '" + dir + "' INTO TABLE " + datastore['TABLE_NAME'])
		rescue ::RbMysql::TextfileNotReadable
			print_good(dir + " is a directory and exists")
		rescue ::RbMysql::ServerError
			print_warning(dir + " does not exist")
		rescue ::RbMysql::Error => e
			print_error("MySQL Error: #{e.class} #{e.to_s}")
			return
		rescue Rex::ConnectionTimeout => e
			print_error("Timeout: #{e.message}")
			return
		else
			print_good(dir + " is a file and exists")
		end
		#puts res.inspect

		return
	end

end
