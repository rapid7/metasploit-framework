##
# $Id$
##

##
# ## This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'
require 'rex'
require 'msf/core/post/windows/registry'
require 'msf/core/post/file'


class Metasploit3 < Msf::Post

	include Msf::Post::File
	include Msf::Post::Windows::Registry
	include Msf::Auxiliary::Report
	

	def initialize(info={})
		super( update_info( info,
				'Name'          => 'Windows Gather Database Instance Enumeration',
				'Description'   => %q{ This module will enumerate a windows system for installed database instances },
				'License'       => MSF_LICENSE,
				'Author'        => [ 'Barry Shteiman <barry[at]sectorix.com>'],
				'Version'       => '$Revision$',
				'Platform'      => [ 'windows' ],
				'SessionTypes'  => [ 'meterpreter' ]
			))
	end

	# method called when command run is issued
	def run
		print_status("=============================================")
		print_status(" Database Enumeration Module")
		print_status("=============================================")
		print_status("Running module against #{sysinfo['Computer']}")
		print_status("Checking for Database Server installations.")
		found = false
		if check_mssql
			enumerate_mssql
			found = true
		end
		if check_oracle
			enumerate_oracle
			found = true
		end
		if check_db2
			enumerate_db2
			found = true
		end 
		if check_mysql
			enumerate_mysql
			found = true
		end
		if check_sybase
			enumerate_sybase
			found = true
		end
		
		print_status("=============================================")
		if found
			print_status("Enumeration Complete, Databases Found.")
		else
			print_status("Enumeration Complete, No Databases were found")
		end
		print_status("=============================================")
	end

	##### initial identification methods #####
	
	# method for Checking if database instances are installed on host - mssql
	def check_mssql
		key = "HKLM\\SOFTWARE\\Microsoft"
		if registry_enumkeys(key).include?("Microsoft SQL Server")
			print_status("\tMicrosoft SQL Server found.")
			return true
		end
	return false
	rescue
		return false
	end

	# method for Checking if database instances are installed on host - oracle
	def check_oracle
		key = "HKLM\\SOFTWARE\\Oracle"
		if registry_enumkeys(key).include?("ALL_HOMES")
			print_status("\tOracle Server found.")
			return true
		elsif registry_enumkeys(key).include?("SYSMAN")
			print_status("\tOracle Server found.")
			return true
		end
	return false
	rescue
		return false
	end
	
	# method for Checking if database instances are installed on host - db2
	def check_db2
		key = "HKLM\\SOFTWARE\\IBM\\DB2"
		if registry_enumkeys(key).include?("GLOBAL_PROFILE")
			print_status("\tDB2 Server found.")
			return true
		end
	return false
	rescue
		return false
	end	
	
	# method for Checking if database instances are installed on host - mysql
	def check_mysql
		key = "HKLM\\SOFTWARE"
		if registry_enumkeys(key).include?("MySQL AB")
			print_status("\tMySQL Server found.")
			return true
		end
	return false
	rescue
		return false
	end		
	
	# method for Checking if database instances are installed on host - sybase
	def check_sybase
		key = "HKLM\\SOFTWARE\\Sybase"
		if registry_enumkeys(key).include?("SQLServer")
			print_status("\tSybase Server found.")
			return true
		elsif registry_enumkeys(key).include?("Server")
			print_status("\tSybase Server found.")
			return true
		end
	return false
	rescue
		return false
	end

	##### deep analysis methods #####
	
	# method to identify mssql instances
	def enumerate_mssql
		key = "HKLM\\SOFTWARE\\Microsoft\\Microsoft SQL Server\\Instance Names\\SQL"
		instances = registry_enumvals(key)
		if not instances.nil? and not instances.empty?
			instances.each do |i|
				tcpkey = "HKLM\\SOFTWARE\\Microsoft\\Microsoft SQL Server\\#{registry_getvaldata(key,i)}\\MSSQLServer\\SuperSocketNetLib\\Tcp\\IPAll"
				tcpport = registry_getvaldata(tcpkey,"TcpPort")
				print_good("\t\t+ #{registry_getvaldata(key,i)} (Port:#{tcpport})")
				
			end
		end
	rescue
	end
	
	# method to identify oracle instances
	def enumerate_oracle
		basekey = "HKLM\\SOFTWARE\\Oracle\\SYSMAN"
		instances = registry_enumkeys(basekey)
		if not instances.nil? and not instances.empty?
			instances.each do |i|
				key = "#{basekey}\\#{i}"
				val_ORACLE_SID = registry_getvaldata(key,"ORACLE_SID")
				val_ORACLE_HOME = registry_getvaldata(key,"ORACLE_HOME")
								
				if session.fs.file.exists?(val_ORACLE_HOME + "\\NETWORK\\ADMIN\\tnsnames.ora")
					data_TNSNAMES = read_file(val_ORACLE_HOME + "\\NETWORK\\ADMIN\\tnsnames.ora")
					ports = data_TNSNAMES.scan(/PORT\ \=\ (\d+)/)
					port = 0
					ports.each do |p|
						if port == 0
							port = $1
						end
					end
					print_good("\t\t+ #{val_ORACLE_SID} (Port:#{port})")				
					
				else
					print_error("\t\t+ #{val_ORACLE_SID} (No Listener Found)")				
				end
			end
		end
	rescue
	end

	# method to identify mysql instances
	def enumerate_mysql
		basekey = "HKLM\\SOFTWARE\\MySQL AB"
		instances = registry_enumkeys(basekey)
		if not instances.nil? and not instances.empty?
			instances.each do |i|
				found = false
				key = "#{basekey}\\#{i}"
				val_Location = registry_getvaldata(key,"Location")
				if session.fs.file.exists?(val_Location + "\\my.ini")
					found = true
					data = read_file(val_Location + "\\my.ini")
				elsif session.fs.file.exists?(val_Location + "\\my.cnf")
					found = true
					data = read_file(val_Location + "\\my.cnf")
				end
				if found
					port = data.scan(/port\=(\d+)/)
					port = 0
					ports.each do |p|
						if port == 0
							port = $1
						end
					end
					print_good("\t\t+ MYSQL (Port:#{port})")
				else
					print_error("\t\t+couldnt locate file.")
				end
				
			end
		end
	rescue
	end
	
	# method to identify mysql instances
	def enumerate_sybase
		basekey = "HKLM\\SOFTWARE\\Sybase\\SQLServer"
		instance = registry_getvaldata(basekey,"DSLISTEN")
		location = registry_getvaldata(basekey,"RootDir")
		if session.fs.file.exists?(location + "\\ini\\sql.ini")
			data = read_file(location + "\\ini\\sql.ini")
			segments = data.scan(/\[#{instance}\]([^\[]*)/)
			segment = ""
			segments.each do |s|
				if segment == ""
					segment = $1
				end
			end
			port = segment.scan(/master\=\w+\,0.0.0.0\,(\d+)/)
			print_good("\t\t+ #{instance} (Port:#{port})")
		else
			print_error("\t\t+couldnt locate file.")
		end
	rescue
		print_error("\t\t+ couldnt locate information.")
	end
	
	# method to identify db2 instances
	def enumerate_db2
		key = "HKLM\\SOFTWARE\\IBM\\DB2\\GLOBAL_PROFILE"
		instance = registry_getvaldata(key,"DB2INSTDEF")
		tcpkey = "HKLM\\SOFTWARE\\IBM\\DB2\\PROFILES\\#{instance}"
		tcpport = registry_getvaldata(tcpkey,"DB2PORTRANGE")
		account = registry_getvaldata(tcpkey,"DB2ACCOUNTNAME")
		owner = registry_getvaldata(tcpkey,"DB2INSTOWNER")
		print_good("\t\t+ #{instance} (Port:#{tcpport} , User:#{account}, Owner:#{owner})")
	rescue
		print_error("\t\t+#{instance}, couldnt identify instance information.")
	end
	

	
end