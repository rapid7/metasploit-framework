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
# == Optional
# 
# Library is able to use nokogiri if available, but nokogiri is not required.
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
# It is adviseable to use NessusXMLRPC class, not this class directly.
# As NessusXMLRPC class will use nokogiri or rexml, depending on availability.
class NessusXMLRPCrexml
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
		login(user,password)
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
			puts "[e] error in XML parsing"
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
			puts "[e] error connecting to server: "+ @nurl + " with URI: " + uri

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
		end
			
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
			entry['current']=scan.elements['completion_current'].text;
			entry['total']=scan.elements['completion_total'].text;		
			scans.push(entry) 
		}
		return scans
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

	# get hosts for particular report
	#
	# returns: array of hosts
	def report_hosts(report_id)
		post= { "token" => @token, "report" => report_id } 
		docxml=nessus_request('report/hosts', post)
		list = Array.new
		docxml.root.elements['contents'].elements['hostList'].each_element('//host') { |host| 
			list.push host.elements['hostname'].text
		}
		return list
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
	#-- ToDo items
	def plugins_list
		post= { "token" => @token } 
		docxml=nessus_request('plugins/list', post)
		return docxml
	end
	def users_list
		post= { "token" => @token } 
		docxml=nessus_request('users/list', post)
		return docxml
	end
end # end of NessusXMLRPC::Class

# use nokogiri if available (it's faster!)
nokogiri=true
begin
	require 'nokogiri'
rescue LoadError
	nokogiri=false
end

# if found nokogiri
if nokogiri
# Class which uses nokogiri to parse nessus XML RPC replies. 
# It is adviseable to use NessusXMLRPC class, not this class directly.
# As NessusXMLRPC class will use nokogiri or rexml, depending on availability.
# 
# Documentation for this class documents only differences from NessusXMLRPCrexml.
# <b> So, check NessusXMLRPCrexml for method documentation </b>
class NessusXMLRPCnokogiri < NessusXMLRPCrexml
	# send standard Nessus XML request and check
	#
	# return: nokogiri XML file
	def nessus_request(uri, post_data) 
		body=nessus_http_request(uri, post_data)
		docxml = Nokogiri::XML.parse(body)
		begin 
		status = docxml.xpath("/reply/status").collect(&:text)[0]
		rescue
			puts "[e] error in XML parsing"
		end
		if status == "OK"
			return docxml 
		else 
			return ''
		end
	end

	def login(user, password)
		post = { "login" => user, "password" => password }
		docxml=nessus_request('login', post)
		if docxml == '' 
			@token=''
		else
			@token = docxml.xpath("/reply/contents/token").collect(&:text)[0]
			@name = docxml.xpath("/reply/contents/user/name").collect(&:text)[0]
			@admin = docxml.xpath("/reply/contents/user/admin").collect(&:text)[0]
		end
			
	end

	def scan_new(policy_id,scan_name,target)
		post= { "token" => @token, "policy_id" => policy_id, "scan_name" => scan_name, "target" => target } 
		docxml=nessus_request('scan/new', post)
		if docxml == '' 
			return ''
		else
			uuid=docxml.xpath("/reply/contents/scan/uuid").collect(&:text)[0]
			return uuid
		end	
	end

	def scan_status(uuid)
		post= { "token" => @token, "report" => uuid } 
		docxml=nessus_request('report/list', post)
		return docxml.xpath("/reply/contents/reports/report/name[text()='"+uuid+"']/../status").collect(&:text)[0]
	end

	def scan_list_uids
		post= { "token" => @token } 
		docxml=nessus_request('scan/list', post)
		return docxml.xpath("/reply/contents/scans/scanList/scan/uuid").collect(&:text)
	end

	def scan_list_hash
		post= { "token" => @token } 
		docxml=nessus_request('scan/list', post)
		scans=Array.new
		# any better way of doing this?
		scans = Array.new
		docxml.xpath("/reply/contents/scans/scanList/scan/uuid").collect(&:text).each { |uuid|
			entry=Hash.new	
			entry['id'] = uuid
			scans.push entry
		}

		i=0;
		docxml.xpath("/reply/contents/scans/scanList/scan/readableName").collect(&:text).each { |name|
			scans[i]['name']= name
			i= i + 1
		}

		i=0;
		docxml.xpath("/reply/contents/scans/scanList/scan/completion_current").collect(&:text).each { |current|
			scans[i]['current']= current
			i= i + 1
		}

		i=0;
		docxml.xpath("/reply/contents/scans/scanList/scan/completion_total").collect(&:text).each { |total|
			scans[i]['total']= total
			i= i + 1
		}
		return scans
	end

	def policy_get_id(textname) 
		post= { "token" => @token } 
		docxml=nessus_request('policy/list', post)
		return docxml.xpath("/reply/contents/policies/policy/policyName[text()='"+textname+"']/..policyID").collect(&:text)[0]
	end	

	def policy_list_uids
		post= { "token" => @token } 
		docxml=nessus_request('policy/list', post)
		return docxml.xpath("/reply/contents/policies/policy/policyID").collect(&:text)
	end

	def policy_get_first
		post= { "token" => @token } 
		docxml=nessus_request('policy/list', post)
		id=docxml.xpath("/reply/contents/policies/policy/policyID").collect(&:text)[0]
		name=docxml.xpath("/reply/contents/policies/policy/policyName").collect(&:text)[0]
		return id, name
	end	

	def policy_list_names
		post= { "token" => @token } 
		docxml=nessus_request('policy/list', post)
		return docxml.xpath("/reply/contents/policies/policy/policyName").collect(&:text)
	end

	def report_hosts(report_id)
		post= { "token" => @token, "report" => report_id } 
		docxml=nessus_request('report/hosts', post)
		return docxml.xpath("/reply/contents/hostList/host/hostname").collect(&:text)
	end

	def report_get_host(report_id,host)
		post= { "token" => @token, "report" => report_id } 
		docxml=nessus_request('report/hosts', post)
		severity=docxml.xpath("/reply/contents/hostList/host/hostname[text()='"+host+"']/../severity").collect(&:text)[0]
		current=docxml.xpath("/reply/contents/hostList/host/hostname[text()='"+host+"']/../scanProgressCurrent").collect(&:text)[0]
		total=docxml.xpath("/reply/contents/hostList/host/hostname[text()='"+host+"']/../scanProgressTotal").collect(&:text)[0]
		return severity, current, total
	end
		
end # end of NessusXMLRPCnokogiri::Class
	# Main class which controls Nessus using XMLRPC. 
	# It is adviseable to use this NessusXMLRPC class, and not NessusXMLRPCnokogiri or NessusXMLRPCrexml,
	# As NessusXMLRPC class will use nokogiri or rexml, depending on availability. 
	# Of course, choosing nokogiri first because of speed.
	# 
	# Example:
	# 
	#  n=NessusXMLRPC::NessusXMLRPC.new('https://localhost:8834','user','pass');
	#  if n.logged_in
	# 	id,name = n.policy_get_first
	# 	uid=n.scan_new(id,"textxmlrpc","127.0.0.1")
	#	puts "status: " + n.scan_status(uid)
	#  end
	# 
	# Check NessusXMLRPCrexml for description of methods implemented 
	# (for both NessusXMLRPCnokogiri and NessusXMLRPCrexml).
	class NessusXMLRPC < NessusXMLRPCnokogiri
	end
else # nokogiri not found, use REXML
	class NessusXMLRPC < NessusXMLRPCrexml
	end
end # if nokogiri

end # of Module

