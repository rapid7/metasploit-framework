#
# = nessus-xmlrpc.rb: communicate with Nessus(4.2+) over XML RPC interface
#
# Author:: Vlatko Kosturjak
#
# (C) Vlatko Kosturjak, Kost. Distributed under GPL and BSD license (dual).
# 
# == What is this library? 
# 
# This library is used for communication with Nessus over XML RPC interface. 
# You can start, stop, pause and resume scan. Watch progress and status of scan, 
# download report, etc.
#
# == Requirements
# 
# Required libraries are standard Ruby libraries: uri, net/https and rexml/document. 
#
# == Usage:
# 
#  require 'nessus-xmlrpc'
#  n=NessusXMLRPC::NessusXMLRPC.new('https://localhost:8834','user','pass');
#  if n.logged_in
# 	id,name = n.policy_get_first
# 	puts "using policy ID: " + id + " with name: " + name
# 	uid=n.scan_new(id,"textxmlrpc","127.0.0.1")
#	puts "status: " + n.scan_status(uid)
# 	while not n.scan_finished(uid)
# 		sleep 10
# 	end
#	content=n.report_file_download(uid)
# 	File.open('report.xml', 'w') {|f| f.write(content) }
#  end

require 'uri'
require 'net/https'
require 'rexml/document'

# NessusXMLRPC module
# 
# Usage:
# 
#  require 'nessus-xmlrpc'
#  n=NessusXMLRPC::NessusXMLRPC.new('https://localhost:8834','user','pass');
#  if n.logged_in
# 	id,name = n.policy_get_first
# 	uid=n.scan_new(id,"textxmlrpc","127.0.0.1")
#	puts "status: " + n.scan_status(uid)
#  end
#
# Check NessusXMLRPCrexml for description of methods implemented 
# (for both NessusXMLRPCnokogiri and NessusXMLRPCrexml).

module NessusXMLRPC 

# Class which uses standard REXML to parse nessus XML RPC replies. 
class NessusXMLRPC
	# initialize object: try to connect to Nessus Scanner using URL, user and password
	#
	# Usage: 
	# 
	#  n=NessusXMLRPC::NessusXMLRPC.new('https://localhost:8834','user','pass');
	def initialize(url,user,password)
		if url == ''
			@nurl="https://localhost:8834/"
		else
			if url =~ /\/$/
				@nurl=url
			else
				@nurl=url + "/"
			end
		end
		@token=''
		#login(user,password)
	end

	# checks if we're logged in correctly
	#
	# returns: true if logged in, false if not
	#
	# Usage: 
	# 
	#  n=NessusXMLRPC::NessusXMLRPC.new('https://localhost:8834','user','pass');
	#  if n.logged_in
	#	puts "Logged in"
	#  else
	#	puts "Error"
	#  end

	def logged_in
		if @token == ''
			return false
		else
			return true
		end
	end	

	# send standard Nessus XML request and check
	# 
	# returns: rexml/document root
	def nessus_request(uri, post_data) 
		body=nessus_http_request(uri, post_data)
		# puts response.body
		docxml = REXML::Document.new(body)
		begin 
		status = docxml.root.elements['status'].text
		rescue
			print("Error connecting/logging to the server!")
		end
		if status == "OK"
			return docxml 
		else 
			return ''
		end
	end

	# send standard Nessus HTTP request and check
	#
	# returns: body of response
	def nessus_http_request(uri, post_data) 
		url = URI.parse(@nurl + uri) 
		request = Net::HTTP::Post.new( url.path )
		request.set_form_data( post_data )
		if not defined? @https	
			@https = Net::HTTP.new( url.host, url.port )
			@https.use_ssl = true
			@https.verify_mode = OpenSSL::SSL::VERIFY_NONE
		end
		# puts request
		begin
			response = @https.request( request )
		rescue 
			#"[e] error connecting to server: "+ @nurl + " with URI: " + uri
			@error = "stuff"
			exit
		end
		# puts response.body
		return response.body
	end
	
	# login with user & password and sets object-wide @token, @name and @admin
	def login(user, password)
		post = { "login" => user, "password" => password }
		docxml=nessus_request('login', post)
		if docxml == '' 
			@token=''
		else
			@token = docxml.root.elements['contents'].elements['token'].text
			@name = docxml.root.elements['contents'].elements['user'].elements['name'].text
			@admin = docxml.root.elements['contents'].elements['user'].elements['admin'].text
			# puts "Got token:" + @token
			return @token
		end
			
	end
	
	#checks to see if the user is an admin
	def is_admin
		if @admin == "TRUE"
			return true
		end
		return false
	end
	
	# initiate new scan with policy id, descriptive name and list of targets
	# 
	# returns: uuid of scan
	# 
	# Usage: 
	# 
	#  n=NessusXMLRPC::NessusXMLRPC.new('https://localhost:8834','user','pass');
	#  if n.logged_in
	# 	id,name = n.policy_get_first
	# 	puts "using policy ID: " + id + " with name: " + name
	# 	uid=n.scan_new(id,"textxmlrpc","127.0.0.1")
	#  end
	def scan_new(policy_id,scan_name,target)
		post= { "token" => @token, "policy_id" => policy_id, "scan_name" => scan_name, "target" => target } 
		docxml=nessus_request('scan/new', post)
		if docxml == '' 
			return ''
		else
			uuid=docxml.root.elements['contents'].elements['scan'].elements['uuid'].text
			return uuid
		end	
	end

	# get uids of scans
	#
	# returns: array of uids of active scans
	def scan_list_uids
		post= { "token" => @token } 
		docxml=nessus_request('scan/list', post)
		uuids=Array.new
		docxml.root.elements['contents'].elements['scans'].elements['scanList'].each_element('//scan') {|scan| uuids.push(scan.elements['uuid'].text) }
		return uuids
	end

	# get hash of active scan data
	# 
	# returns: array of hash of active scans
	def scan_list_hash
		post= { "token" => @token } 
		docxml=nessus_request('scan/list', post)
		scans=Array.new
		docxml.root.elements['contents'].elements['scans'].elements['scanList'].each_element('//scan') {|scan| 
			entry=Hash.new
			entry['id']=scan.elements['uuid'].text
			entry['name']=scan.elements['readableName'].text
			entry['owner']=scan.elements['owner'].text
			entry['start']=scan.elements['start_time'].text
			entry['status']=scan.elements['status'].text
			entry['current']=scan.elements['completion_current'].text;
			entry['total']=scan.elements['completion_total'].text;		
			scans.push(entry) 
		}
		return scans
	end
	
	# get hash of policies
	# 
	# returns: array of hash of policies
	def policy_list_hash
		post= { "token" => @token } 
		docxml=nessus_request('scan/list', post)
		scans=Array.new
		docxml.root.elements['policies'].elements['policies'].each_element('//policy') {|scan| 
			entry=Hash.new
			entry['id']=scan.elements['uuid'].text
			entry['name']=scan.elements['readableName'].text
			entry['current']=scan.elements['completion_current'].text;
			entry['total']=scan.elements['completion_total'].text;		
			scans.push(entry) 
		}
		return scans
	end
	
	# get hash of templates
	# 
	# returns: array of hash of templates
	def template_list_hash
		post= { "token" => @token } 
		docxml=nessus_request('scan/list', post)
		scans=Array.new
		docxml.root.elements['contents'].elements['scans'].elements['scanList'].each_element('//scan') {|scan| 
			entry=Hash.new
			entry['id']=scan.elements['uuid'].text
			entry['name']=scan.elements['readableName'].text
			entry['current']=scan.elements['completion_current'].text;
			entry['total']=scan.elements['completion_total'].text;		
			scans.push(entry) 
		}
		return scans
	end
	
	# get hash of templates
	# 
	# returns: array of hash of templates
	def report_list_hash
		post= { "token" => @token } 
		docxml=nessus_request('report/list', post)
		#puts docxml
		reports=Array.new
		docxml.root.elements['contents'].elements['reports'].each_element('//report') {|report| 
			entry=Hash.new
			entry['id']=report.elements['name'].text
			entry['name']=report.elements['readableName'].text
			entry['status']=report.elements['status'].text;
			entry['timestamp']=report.elements['timestamp'].text;		
			reports.push(entry) 
		}
		return reports
	end

	# get policy by textname and return policyID
	# 
	# returns: policyID
	def policy_get_id(textname) 
		post= { "token" => @token } 
		docxml=nessus_request('policy/list', post)
		docxml.root.elements['contents'].elements['policies'].each_element('//policy') {|policy|
			if policy.elements['policyName'].text == textname
				return policy.elements['policyID'].text 
			end
		}
		return ''
	end	

	# get first policy from server and returns: policyID, policyName
	#
	# returns: policyID, policyName
	def policy_get_first
		post= { "token" => @token } 
		docxml=nessus_request('policy/list', post)
		docxml.root.elements['contents'].elements['policies'].each_element('//policy') {|policy|
				return policy.elements['policyID'].text, policy.elements['policyName'].text
		}
	end	

	# get list of policy IDs
	#
	# returns: array of all policy uids
	def policy_list_uids
		post= { "token" => @token } 
		docxml=nessus_request('policy/list', post)
		pids=Array.new
		docxml.root.elements['contents'].elements['policies'].each_element('//policy') { |policy| 
			pids.push(policy.elements['policyID'].text) }
		return pids
	end

	# stop scan identified by scan_uuid
	def scan_stop(uuid)
		post= { "token" => @token, "scan_uuid" => uuid } 
		docxml=nessus_request('scan/stop', post)
		return docxml
	end
	
	# stop all active scans 
	# 
	# Usage: 
	# 
	#  n=NessusXMLRPC::NessusXMLRPC.new('https://localhost:8834','user','pass');
	#  if n.logged_in
	#	n.scan_stop_all
	#  end
	def scan_stop_all
		b=scan_list_uids
		b.each {|uuid|
			scan_stop(uuid)
		}
		return b
	end
	
	# pause scan identified by scan_uuid
	def scan_pause(uuid)
		post= { "token" => @token, "scan_uuid" => uuid } 
		docxml=nessus_request('scan/pause', post)
		return docxml
	end
	
	# pause all active scans 
	# 
	# Usage: 
	# 
	#  n=NessusXMLRPC::NessusXMLRPC.new('https://localhost:8834','user','pass');
	#  if n.logged_in
	#	n.scan_pause_all
	#  end
	def scan_pause_all
		b=scan_list_uids
		b.each {|uuid|
			scan_pause(uuid)
		}
		return b
	end
	
	# remove scan identified by uuid
	def scan_resume(uuid)
		post= { "token" => @token, "scan_uuid" => uuid } 
		docxml=nessus_request('scan/resume', post)
		return docxml
	end
	# resume all active scans 
	# 
	# Usage: 
	# 
	#  n=NessusXMLRPC::NessusXMLRPC.new('https://localhost:8834','user','pass');
	#  if n.logged_in
	#	n.scan_resume_all
	#  end
	def scan_resume_all
		b=scan_list_uids
		b.each {|uuid|
			scan_resume(uuid)
		}
		return b
	end

	# check status of scan identified by uuid
	def scan_status(uuid)
		post= { "token" => @token, "report" => uuid } 
		docxml=nessus_request('report/list', post)
		docxml.root.elements['contents'].elements['reports'].each_element('//report') { |report|
			if report.elements['name'].text == uuid
				return (report.elements['status'].text)
			end
		}
		return ''
	end

	# check if scan is finished (completed to be exact) identified by uuid
	def scan_finished(uuid)
		status=scan_status(uuid)
		if status == "completed"
			return true
		else
			return false
		end
	end
	
	# get report by reportID and return XML file
	# 
	# returns: XML file of report (nessus v2 format)
	def report_file_download(report)
		post= { "token" => @token, "report" => report } 
		file=nessus_http_request('file/report/download', post)
		return file
	end

	# get report by reportID and return XML file (version 1)
	# 
	# returns: XML file of report (nessus v1 format)
	def report_file1_download(report)
		post= { "token" => @token, "report" => report, "v1" => "true" } 
		file=nessus_http_request('file/report/download', post)
		return file
	end
	
	# delete report by report ID
	def report_delete(id)
		post= { "token" => @token, "report" => id } 
		docxml=nessus_request('report/delete', post)
		return docxml
	end

	# get list of names of policies
	#
	# returns: array of names
	def policy_list_names
		post= { "token" => @token } 
		docxml=nessus_request('policy/list', post)
		list = Array.new
		docxml.root.elements['contents'].elements['policies'].each_element('//policy') {|policy|
				list.push policy.elements['policyName'].text
		}
		return list
	end

	# get data for each host for a particular report
	#
	#
	# returns: array of hashes:
	#		hostname
	#		severity
	#		severityCount0
	#		severityCount1
	#		severityCount2
	#		severityCount3
	#		scanProgressCurrent
	#		scanprogressTotal
	def report_hosts(report_id)
		post= { "token" => @token, "report" => report_id } 
		docxml=nessus_request('report/hosts', post)
		hosts=Array.new
		docxml.elements.each('/reply/contents/hostList/host') do |host|
			entry=Hash.new
			entry['hostname'] = host.elements['hostname'].text
			entry['severity'] = host.elements['severity'].text
			sevs=Array.new
			host.elements.each('severityCount/item') do |item|
				sevs.push item.elements['count'].text
			end
			entry['sev0'] = sevs[0]
			entry['sev1'] = sevs[1]
			entry['sev2'] = sevs[2]
			entry['sev3'] = sevs[3]
			entry['current'] = host.elements['scanProgressCurrent'].text
			entry['total'] = host.elements['scanProgressTotal'].text
			hosts.push(entry)
		end
		return hosts
	end
	
	def report_host_ports(report_id,host)
		post= { "token" => @token, "report" => report_id, "hostname" => host } 
		docxml=nessus_request('report/ports', post)
		ports=Array.new
		docxml.elements.each('/reply/contents/portList/port') do |port|
			entry=Hash.new
			entry['portnum'] = port.elements['portNum'].text
			entry['protocol'] = port.elements['protocol'].text
			entry['severity'] = port.elements['severity'].text
			entry['svcname'] = port.elements['svcName'].text
			sevs=Array.new
			port.elements.each('severityCount/item') do |item|
				sevs.push item.elements['count'].text
			end
			entry['sev0'] = sevs[0]
			entry['sev1'] = sevs[1]
			entry['sev2'] = sevs[2]
			entry['sev3'] = sevs[3]
			ports.push(entry)
		end
		return ports
	end
	
	def report_host_port_details(report_id,host,port,protocol)
		post= { "token" => @token, "report" => report_id, "hostname" => host, "port" => port, "protocol" => protocol } 
		docxml=nessus_request('report/details', post)
		reportitems=Array.new
		docxml.elements.each('/reply/contents/portDetails/ReportItem') do |rpt|
			entry=Hash.new
			entry['port'] = rpt.elements['port'].text
			entry['severity'] = rpt.elements['severity'].text
			entry['pluginID'] = rpt.elements['pluginID'].text
			entry['pluginName'] = rpt.elements['pluginName'].text
			if rpt.elements['data'].elements['cvss_base_score']
				entry['cvss_base_score'] = rpt.elements['data'].elements['cvss_base_score'].text
			end
			if rpt.elements['data'].elements['exploit_available']
				entry['exploit_available'] = rpt.elements['data'].elements['exploit_available'].text
			end
			if rpt.elements['data'].elements['cve']
				entry['cve'] = rpt.elements['data'].elements['cve'].text
			end
			if rpt.elements['data'].elements['risk_factor']
				entry['risk_factor'] = rpt.elements['data'].elements['risk_factor'].text
			end
			if rpt.elements['data'].elements['cvss_vector']
				entry['cvss_vector'] = rpt.elements['data'].elements['cvss_vector'].text
			end
			
			#entry['solution'] = rpt.elements['data/solution'].text #not important right now
			#entry['description'] = rpt.elements['data/description'].text #not important right now
			#entry['synopsis'] = rpt.elements['data/synopsis'].text #not important right now
			#entry['see_also'] = rpt.elements['data/see_also'].text # multiple of these
			#entry['bid'] = rpt.elements['data/bid'].text multiple of these
			#entry['xref'] = rpt.elements['data/xref'].text # multiple of these
			#entry['plugin_output'] = rpt.elements['data/plugin_output'].text #not important right now
			reportitems.push(entry)
		end
		return reportitems
	end

	# get host details for particular host identified by report id
	#
	# returns: severity, current, total
	def report_get_host(report_id,host)
		post= { "token" => @token, "report" => report_id } 
		docxml=nessus_request('report/hosts', post)
		docxml.root.elements['contents'].elements['hostList'].each_element('//host') { |host| 
			if host.elements['hostname'].text == host
				severity = host.elements['severity'].text
				current = host.elements['scanProgressCurrent'].text
				total = host.elements['scanProgressTotal'].text
				return severity, current, total
			end
		}
	end
	
	# gets a list of each plugin family and the number of plugins for that family.
	def plugins_list
		post= { "token" => @token } 
		docxml=nessus_request('plugins/list', post)
		plugins=Array.new
		docxml.root.elements['contents'].elements['pluginFamilyList'].each_element('//family') { |plugin|
			entry=Hash.new
			entry['name']=plugin.elements['familyName'].text
			entry['num']=plugin.elements['numFamilyMembers'].text;		
			plugins.push(entry) 	
		}
		return plugins	
	end
	
	#returns a list of users, if they are an admin and their last login time.
	def users_list
		post= { "token" => @token } 
		docxml=nessus_request('users/list', post)
		users=Array.new
		docxml.root.elements['contents'].elements['users'].each_element('//user') { |user|
			entry=Hash.new
			entry['name']=user.elements['name'].text
			entry['admin']=user.elements['admin'].text;
			entry['lastlogin']=user.elements['lastlogin'].text;		
			users.push(entry) 	
		}
		return users		
		

	end
	
	# returns basic data about the feed type and versions.
	def feed
		post = { "token" => @token }
		docxml = nessus_request('feed', post)
		feed = docxml.root.elements['contents'].elements['feed'].text
		version = docxml.root.elements['contents'].elements['server_version'].text
		web_version = docxml.root.elements['contents'].elements['web_server_version'].text
		return feed, version, web_version
	end
	
	def user_add(user,pass)
		post= { "token" => @token, "login" => user, "password" => pass }
		docxml = nessus_request('users/add', post)
		return docxml
	end
	
	def user_del(user)
		post= { "token" => @token, "login" => user }
		docxml = nessus_request('users/delete', post)
		return docxml
	end
	
	def user_pass(user,pass)
		post= { "token" => @token, "login" => user, "password" => pass }
		docxml = nessus_request('users/chpasswd', post)
		return docxml
	end
	
	def plugin_family(fam)
		post = { "token" => @token, "family" => fam }
		docxml = nessus_request('plugins/list/family', post)
		family=Array.new
		docxml.elements.each('/reply/contents/pluginList/plugin') { |plugin|
			entry=Hash.new
			entry['filename'] = plugin.elements['pluginFileName'].text
			entry['id'] = plugin.elements['pluginID'].text
			entry['name'] = plugin.elements['pluginName'].text
			family.push(entry)
		}
		return family
	end
end # end of NessusXMLRPC::Class

end # of Module

