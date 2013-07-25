#!/usr/bin/env ruby
#
# This plugin provides integration with OpenVAS. Written by kost and
# averagesecurityguy.
#
# Distributed under MIT license: 
# http://www.opensource.org/licenses/mit-license.php
#

require 'socket' 
require 'timeout'
require 'openssl'
require 'rexml/document'
require 'rexml/text'
require 'base64'

# OpenVASOMP module
# 
# Usage: require 'openvas-omp'

module OpenVASOMP

#------------------------------
# Error Classes
#------------------------------
	class OMPError < :: RuntimeError
		attr_accessor :reason
		def initialize(reason = '')
			self.reason = reason
		end
		def to_s
			"OpenVAS OMP: #{self.reason}"
		end
	end

	class OMPConnectionError < OMPError
		def initialize
			self.reason = "Could not connect to server"
		end
	end

	class OMPResponseError < OMPError
		def initialize
			self.reason = "Error in OMP request/response"
		end
	end

	class OMPAuthError < OMPError
		def initialize
			self.reason = "Authentication failed"
		end
	end

	class XMLParsingError < OMPError
		def initialize
			self.reason = "XML parsing failed"
		end
	end


#------------------------------
# Connection Class
#------------------------------
	class OpenVASConnection
		attr_accessor :socket, :bufsize, :debug

		def initialize(host="127.0.0.1", port=9390, debug=false)
			@host = host
			@port = port
			@socket = nil
			@bufsize = 16384
			@debug = debug
		end

		def connect
			if @debug then puts "Connecting to server #{@host} on port #{@port}" end
			plain_socket = TCPSocket.open(@host, @port)
			ssl_context = OpenSSL::SSL::SSLContext.new()
			@socket = OpenSSL::SSL::SSLSocket.new(plain_socket, ssl_context)
			@socket.sync_close = true
			@socket.connect
		end
			
		def disconnect
			if @debug then
				puts "Closing connection to server #{@host} on port #{@port}" end
			if @socket then @socket.close end
		end

		def sendrecv(data)
			# Send the data
			if @debug then puts "Preparing to send data" end
			if not @socket then connect end
			if @debug then puts "SENDING: " + data end
			@socket.puts(data)

			# Receive the response
			resp = ''
			size = 0
			begin	
				begin
					timeout(@read_timeout) {
			    		a = @socket.sysread(@bufsize)
			    		size = a.length
			    		resp << a
					}
				rescue Timeout::Error
					size = 0
				rescue EOFError
					raise OMPResponseError
				end
			end while size >= @bufsize
			
			if @debug then puts "RECEIVED: " + resp end
			return resp
		end
	end
		

#------------------------------
# OpenVASOMP class
#------------------------------
	class OpenVASOMP
		# initialize object: try to connect to OpenVAS using URL, user and password
		attr_reader :targets, :tasks, :configs, :formats, :reports

		def initialize(user="openvas", pass="openvas", host="localhost", port=9392, debug=false)
			@debug = debug
			@token = ''
			@server = OpenVASConnection.new(host, port, debug)
			@server.connect
			login(user, pass)
			@configs = nil
			@tasks = nil
			@targets = nil
			@formats = nil
			@reports = nil
			config_get_all
			task_get_all
			target_get_all
			format_get_all
			report_get_all
		end

	#--------------------------
	# Low level commands. Only
	# used by OpenVASOMP class.
	#--------------------------
		# Nests a string inside an XML tag specified by root
		def xml_str(root, str)
			return "<#{root}>#{str}</#{root}>"
		end

		# Creates an XML root with child elements specified by a hash
		def xml_elems(root, elems)
			xml = REXML::Element.new(root)
			elems.each do |key, val|
				e = xml.add_element(key)
				e.text = val
			end
			return xml.to_s
		end

		# Creates and XML element with attributes specified by a hash
		def xml_attrs(elem, attribs)
			xml = REXML::Element.new(elem)
			attribs.each do |key, val|
				xml.attributes[key] = val
			end
			return xml.to_s
		end

		# Send authentication string and return an XML object (authentication token)
		def auth_request_xml(request)
			if @debug
				puts "Sending Request: #{request}"
			end
			resp = @server.sendrecv(request)
			begin
				docxml = REXML::Document.new(resp)
				status = docxml.root.attributes['status'].to_i
				status_text = docxml.root.attributes['status_text']
				if @debug
					puts "Status: #{status}"
					puts "Status Text: #{status_text}"
				end
			rescue
				raise XMLParsingError
			end

			return status, status_text
		end

		# Send string request wrapped with authentication XML and return 
		# an XML object
		def omp_request_xml(request)
			if @debug
				puts "Sending Request: #{request}"
			end
			resp = @server.sendrecv(@token + request)
			begin
				# Wrap the response in XML tags to use next_element properly.
				docxml = REXML::Document.new("<response>" + resp + "</response>")
				resp = docxml.root.elements['authenticate_response'].next_element
				status = resp.attributes['status'].to_i
				status_text = resp.attributes['status_text']	
				if @debug
					puts "Status: #{status}"
					puts "Status Text: #{status_text}"
				end
			rescue
				raise XMLParsingError
			end

			return status, status_text, resp
		end

	#--------------------------
	# Class API methods.
	#--------------------------
		# Sets debug level
		def debug(value)
			if value == 0
				@debug = false
				@server.debug = false
				return "Debug is deactivated."
			else
				@debug = true
				@server.debug = true
				return "Debug is activated."
			end
		end

		# get OMP version (you don't need to be authenticated)
		def get_version
			status, status_text, resp = omp_request_xml("<get_version/>")
			begin
				version = resp.elements['version'].text
				return version
			rescue
				raise XMLParsingError 
			end
		end

		# login to OpenVAS server. 
		# if successful returns authentication XML for further usage
		# if unsuccessful returns empty string
		def login(user, pass)
			creds = xml_elems("credentials", {"username"=> user, "password" => pass})
			req = xml_str("authenticate", creds)
			status, status_text = auth_request_xml(req)

			if status == 200
				@token = req
			else
				raise OMPAuthError	
			end
		end

		# Logout by disconnecting from the server and deleting the
		# authentication string. There are no sessions in OMP, must
		# send the credentials every time.
		def logout
			@server.disconnect()
			@token = ''
		end

#------------------------------
# Target Functions
#------------------------------

		# OMP - Get all targets for scanning and returns array of hashes
		# with following keys: id,name,comment,hosts,max_hosts,in_use
		#
		# Usage:
		# array_of_hashes = target_get_all()
		# 
		def target_get_all()
			begin
				status, status_text, resp = omp_request_xml("<get_targets/>")

				list = Array.new
				resp.elements.each('//get_targets_response/target') do |target|
					td = Hash.new
					td["id"] = target.attributes["id"]
					td["name"] = target.elements["name"].text
					td["comment"] = target.elements["comment"].text
					td["hosts"] = target.elements["hosts"].text
					td["max_hosts"] = target.elements["max_hosts"].text
					td["in_use"] = target.elements["in_use"].text
					list.push td
				end
				@targets = list
				return list
			rescue 
				raise OMPResponseError
			end
		end

		# OMP - Create target for scanning
		#
		# Usage:
		#
		# target_id = ov.target_create("name"=>"localhost",
		# 	"hosts"=>"127.0.0.1","comment"=>"yes")
		# 
		def target_create(name, hosts, comment)
			req = xml_elems("create_target", {"name"=>name, "hosts"=>hosts, "comment"=>comment})

			begin
				status, status_text, resp = omp_request_xml(req)
				target_get_all
				return "#{status_text}: #{resp.attributes['id']}"
			rescue 
				raise OMPResponseError
			end
		end

		# OMP - Delete target 
		#
		# Usage:
		#
		# ov.target_delete(target_id)
		# 
		def target_delete(id) 
			target = @targets[id.to_i]
			if not target
				raise OMPError.new("Invalid target id.")
			end
			req = xml_attrs("delete_target",{"target_id" => target["id"]})
			begin
				status, status_text, resp = omp_request_xml(req)
				target_get_all
				return status_text
			rescue 
				raise OMPResponseError
			end
		end

	#--------------------------
	# Task Functions
	#--------------------------
		# In short: Create a task.
		#
		# The client uses the create_task command to create a new task. 
		# 
		def task_create(name, comment, config_id, target_id)
			config = @configs[config_id.to_i]
			target = @targets[target_id.to_i]
			config = xml_attrs("config", {"id"=>config["id"]})
			target = xml_attrs("target", {"id"=>target["id"]})
			namestr = xml_str("name", name)
			commstr = xml_str("comment", comment)
			
			req = xml_str("create_task", namestr + commstr + config + target)

			begin
				status, status_text, resp = omp_request_xml(req)
				task_get_all
				return "#{status_text}: #{resp.attributes['id']}"
			rescue 
				raise OMPResponseError
			end
		end

		# In short: Delete a task.
		#
		# The client uses the delete_task command to delete an existing task,
		# including all reports associated with the task. 
		# 
		def task_delete(task_id) 
			task = @tasks[task_id.to_i]
			if not task
				raise OMPError.new("Invalid task id.")
			end
			req = xml_attrs("delete_task",{"task_id" => task["id"]})
			begin
				status, status_text, resp = omp_request_xml(req)
				task_get_all
				return status_text
			rescue 
				raise OMPResponseError
			end
		end

		# In short: Get all tasks.
		#
		# The client uses the get_tasks command to get task information. 
		# 
		def task_get_all()
			begin
				status, status_text, resp = omp_request_xml("<get_tasks/>")
				
				list = Array.new
				resp.elements.each('//get_tasks_response/task') do |task|
					td = Hash.new
					td["id"] = task.attributes["id"]
					td["name"] = task.elements["name"].text
					td["comment"] = task.elements["comment"].text
					td["status"] = task.elements["status"].text
					td["progress"] = task.elements["progress"].text
					list.push td	
				end
				@tasks = list
				return list
			rescue
				raise OMPResponseError
			end
		end

		# In short: Manually start an existing task.
		#
		# The client uses the start_task command to manually start an existing
		# task.
		#
		def task_start(task_id)
			task = @tasks[task_id.to_i]
			if not task
				raise OMPError.new("Invalid task id.")
			end
			req = xml_attrs("start_task",{"task_id" => task["id"]})
			begin
				status, status_text, resp = omp_request_xml(req)
				return status_text
			rescue 
				raise OMPResponseError
			end
		end

		# In short: Stop a running task.
		#
		# The client uses the stop_task command to manually stop a running
		# task.
		#
		def task_stop(task_id) 
			task = @tasks[task_id.to_i]
			if not task
				raise OMPError.new("Invalid task id.")
			end
			req = xml_attrs("stop_task",{"task_id" => task["id"]})
			begin
				status, status_text, resp = omp_request_xml(req)
				return status_text
			rescue 
				raise OMPResponseError
			end
		end 

		# In short: Pause a running task.
		#
		# The client uses the pause_task command to manually pause a running
		# task.
		#
		def task_pause(task_id) 
			task = @tasks[task_id.to_i]
			if not task
				raise OMPError.new("Invalid task id.")
			end
			req = xml_attrs("pause_task",{"task_id" => task["id"]})
			begin
				status, status_text, resp = omp_request_xml(req)
				return status_text
			rescue 
				raise OMPResponseError
			end
		end

		# In short: Resume task if stopped, else start task.
		#
		# The client uses the resume_or_start_task command to manually start
		# an existing task, ensuring that the task will resume from its
		# previous position if the task is in the Stopped state.
		# 
		def task_resume_or_start(task_id) 
			task = @tasks[task_id.to_i]
			if not task
				raise OMPError.new("Invalid task id.")
			end
			req = xml_attrs("resume_or_start_task",{"task_id" => task["id"]})
			begin
				status, status_text, resp = omp_request_xml(req)
				return status_text
			rescue 
				raise OMPResponseError
			end
		end

		# In short: Resume a puased task
		#
		# The client uses the resume_paused_task command to manually resume
		# a paused task.
		# 
		def task_resume_paused(task_id) 
			task = @tasks[task_id.to_i]
			if not task
				raise OMPError.new("Invalid task id.")
			end
			req = xml_attrs("resume_paused_task",{"task_id" => task["id"]})
			begin
				status, status_text, resp = omp_request_xml(req)
				return status_text
			rescue 
				raise OMPResponseError
			end
		end

	#--------------------------
	# Config Functions
	#--------------------------
		# OMP - get configs and returns hash as response
		# hash[config_id]=config_name
		#
		# Usage:
		#
		# array_of_hashes=ov.config_get_all()
		# 
		def config_get_all()
			begin
				status, status_text, resp = omp_request_xml("<get_configs/>")

				list = Array.new
				resp.elements.each('//get_configs_response/config') do |config|
					c = Hash.new
					c["id"] = config.attributes["id"]
					c["name"] = config.elements["name"].text
					list.push c
				end
				@configs = list
				return list
			rescue 
				raise OMPResponseError
			end
		end	


	#--------------------------
	# Format Functions
	#--------------------------
		# Get a list of report formats
		def format_get_all()
			begin
				status, status_text, resp = omp_request_xml("<get_report_formats/>")
				if @debug then print resp end
				
				list = Array.new
				resp.elements.each('//get_report_formats_response/report_format') do |report|
					td = Hash.new
					td["id"] = report.attributes["id"]
					td["name"] = report.elements["name"].text
					td["extension"] = report.elements["extension"].text
					td["summary"] = report.elements["summary"].text
					list.push td	
				end
				@formats = list
				return list
			rescue
				raise OMPResponseError
			end
		end


	#--------------------------
	# Report Functions
	#--------------------------
		# Get a list of reports
		def report_get_all()
			begin
				status, status_text, resp = omp_request_xml("<get_reports/>")
				
				list = Array.new
				resp.elements.each('//get_reports_response/report') do |report|
					td = Hash.new
					td["id"] = report.attributes["id"]
					td["task"] = report.elements["report/task/name"].text
					td["start_time"] = report.elements["report/scan_start"].text
					td["stop_time"] = report.elements["report/scan_end"].text
					list.push td	
				end
				@reports = list
				return list
			rescue
				raise OMPResponseError
			end
		end

		def report_delete(report_id) 
			report = @reports[report_id.to_i]
			if not report
				raise OMPError.new("Invalid report id.")
			end
			req = xml_attrs("delete_report",{"report_id" => report["id"]})
			begin
				status, status_text, resp = omp_request_xml(req)
				report_get_all
				return status_text
			rescue 
				raise OMPResponseError
			end
		end

		# Get a report by id. Must also specify the format_id
		def report_get_by_id(report_id, format_id)
			report = @reports[report_id.to_i]
			if not report
				raise OMPError.new("Invalid report id.")
			end

			format = @formats[format_id.to_i]
			if not format
				raise OMPError.new("Invalid format id.")
			end

			req = xml_attrs("get_reports", {"report_id"=>report["id"], "format_id"=>format["id"]})
			begin
				status, status_text, resp = omp_request_xml(req)
			rescue
				raise OMPResponseError
			end

			if status == "404"
				raise OMPError.new(status_text)
			end

			content_type = resp.elements["report"].attributes["content_type"]
			report = resp.elements["report"].to_s

			if report == nil
				raise OMPError.new("The report is empty.")
			end

			# XML reports are in XML format, everything else is base64 encoded.
			if content_type == "text/xml"
				return report
			else
				return Base64.decode64(report)
			end
		end

    end
end
