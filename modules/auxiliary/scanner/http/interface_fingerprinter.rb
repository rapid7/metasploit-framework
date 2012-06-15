##
# $
##

##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/framework/
##


require 'msf/core'
require 'yaml'

class Metasploit3 < Msf::Auxiliary

	include Msf::Exploit::Remote::HttpClient
	include Msf::Auxiliary::AuthBrute
	include Msf::Auxiliary::Scanner

	def initialize
		super(
			'Name'           => 'Interface Fingerprinter',
			'Version'        => '',
			'Description'    => %q{This module attempts to identify known web
			application interfaces and login with default credentials or those
			provided through the normal means. The fingerprints to use are
			controlled by the CONFIG parameter. },
			'Author'         =>
				[
					'willis'
				],
			'References'     =>
				[
					[ 'www.metasploit.com' ],
				],
			'License'        => MSF_LICENSE
		)

		register_options(
			[ OptString.new('CONFIG', [false, 'Path to the Interface fingerprinter db', "#{Msf::Config.install_root}/data/interface_fingerprints/readme.yml"]),
			OptString.new('SingleInterface', [false, 'A single web interface to check for.', ""]),
			OptString.new('DIR', [false, 'To check in a non default directory (e.g. /admin/', ""]),
		], self.class)
		register_advanced_options(
			[OptBool.new('NoDefault', [false, 'Do not attempt the default credentials', false]),
			OptInt.new('Delay', [false, 'Wait n seconds between requests', 0]),
		], self.class)
	end

	def run_host(ip)
		print_status("#{target_url} Reading configuration file #{datastore['CONFIG']}...")

		# Load the Configuration file
		# It would be nice to support multiple configuration files at once
		@config = YAML.load_file(datastore['CONFIG'])

		# Initialize global vars
		@responses = {}
		@successful_login_responses = {}
		@fails = 0
		@success = false
		@hidden_params = ""

		# Load the URIs and attempt to connect
		init_responses()

		if (too_many_failed_attempts())
			print_error("#{target_url}: Aborting. #{@fails} or more failed connection attempts.")
			return nil
		end

		# Fingerprint the responses and authenticate if possible.
		fingerprinter()

		# Store all responses
		write_data()
	end

	def init_responses()
		# First we pull in all of the unique URIs from the configuration
		#	file.
		@config.each do |interface|
			interface['fingerprint_page'].each do |login|
				next if not login
				if (!@responses.include?(login))
					if (interface['title'].scan(datastore['SingleInterface']).length != 0)
						@responses["#{datastore['Dir']}#{login}"] = interface
					end
				end
			end
		end

		print_status("#{target_url}  #{@responses.size} unique login pages in scope, requesting each. Please wait.")

		# Make a request to each of the URIs and store the responses.
		@responses.each do |login,fingerprint_page|
			acquire_response(login,fingerprint_page)
		end
	end

	def acquire_response(login,fingerprint_page)

		# Adding a delay can be helpful not to overwhelm the target
		select(nil,nil,nil,datastore['Delay'])

		# Skip this server if there are too many failed attempts
		return if too_many_failed_attempts()

		vprint_status("#{target_url}#{login} - Attempting Connection")
		headers = {}

		if fingerprint_page
			if fingerprint_page.is_a?(Net::HTTPResponse)
				# This is needed in case the first request is a 302 and sets some values that
				#	the client needs in later requests.
				referrer =  fingerprint_page.headers["Referrer"] ? "http://www.google.com" : fingerprint_page.headers["Referrer"]
				cookie = fingerprint_page.headers["Set-Cookie"] ? "" : fingerprint_page.headers["Set-Cookie"]
				headers = {
					['Cookie'] => cookie,
					['Referrer'] => referrer
				}
			else
				# A user can add their own headers for the initial request and they will be respected
				#	with a 302.
				headers = fingerprint_page['fp_headers'] if fingerprint_page['fp_headers']
			end
		end

		begin
			# Request the URI
			res = send_request_raw({
				'uri'     => login,
				'method'  => 'GET',
				'headers' => headers,
			}, 20)
			return :abort if not res

			rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable
			rescue ::Rex::ConnectionTimeout
			rescue ::Timeout::Error, ::Errno::EPIPE
		end

		if not res
			print_error("#{target_url} Could not connect.")
			@fails = @fails + 1
			return
		end

		case res.code
		when 302
			# This will break if the page redirects from http to https.

			# Grab the new location form the header and follow the 302, wheeee
			rhost = res.headers["Location"].split("/")[2]
			location = "/#{res.headers["Location"].split("/").drop(3).join('/')}"

			# If we have already followed the 302, don't follow it
			#	again; delete the page and don't go to it again.
			if @responses.include?(location)
				@responses.delete(login)
			else
				vprint_status("#{target_url}#{login} Received 302 =>(unless visited) going to #{location}..")
				acquire_response(location,res) unless login == location
			end
		when 404
			vprint_status("#{target_url}#{login} - Found a 404, tossing it..")

			# Uncomment this to save 404 responses which are usually useless
			#	This will add overhead.
			#@responses[login] = res unless res.body == @last_response
			#@last_response = res.body
		else
			if (res.body != @last_response or (login == "/" or login == "/index.html"))
				vprint_status("#{target_url}#{login} - Storing response")
				@responses[login] = res
			else
				vprint_status("#{target_url}#{login} - Duplicate response, not storing.")
			end

			@last_response = res.body
		end
	end

	def fingerprinter()
		vprint_status("#{target_url} - Testing all responses against the fingerprints.")

		@responses.each do |login,response|
			next unless response
			# We only want to fingerprint Net::HTTPResponse
			next if response.class == Hash

			@response = response

			# Check if the response matches in the fingerprint list.
			@config.each do |interface|
				# In case a user only wants a single interface
				next unless interface['title'].include?(datastore['SingleInterface'])

				# An interface can have multiple fingerprints
				interface['fingerprint_page'].each do |fp|
					# Remove this next line if you want more responses, but more False P's
					next unless fp == login or response.code != 302
					@interface = interface
					@post_to = (not interface['post_to']) ? login : interface['post_to']

					login_response_actions(fp)
					return if @success
				end
			end
		end

	end

	def login_response_actions(fp)
		# If the interface has already been tested with creds
		#	don't retest creds against it.
		return if @interface['tested']

		case @response.code
			when 200
				if(check_fingerprint(@response,@interface['fingerprint']))

					print_status("#{target_url}#{@post_to} - Recieved a #{@response.code} from #{fp} and fingerprint matched, onward...")

					# Check for hidden_id's if it is part of the configuration file.
					#	VIEWSTATE is a common example.
					if(@interface['hidden_id'])
						@interface['hidden_id'].each{ |id|
							if(@response.body =~ /#{id}/)
								value = Rex::Text.uri_encode(@response.body.split("id=\"#{id}\" value=\"")[1].split("\"")[0])
								value = value.gsub('/','%2F')
								@hidden_params << "&#{id}=#{value}"
							end
						}
					end

					# It is very common for multiple pages to match the same fingerprint
					#	especially if a redirect is added to the URI (i.e &redir=...). To prevent this
					#	we mark the interface as previously tested. Create multiple interfaces
					#	if two pages matching the same fingerprint should be tested twice
					#	(e.g. Glassfish Authentication Bypass and Normal Auth Glassfish need
					#	two interfaces)
					@interface['tested'] = true

					# Exit if the user says not to test creds. A used may do this if they just want
					#	to identify target pages for later.
					return if datastore['NoDefault']

					# Skip if there are no default creds to test
					if @interface['creds']
						# First try the default credentials in the config file
						if @interface['basic_auth']
							@interface['creds'].each do |cred|
								do_login_basic(cred.split(":")[0],cred.split(":")[1])
							end
						else
							@interface['creds'].each do |cred|
								do_login(cred.split(":")[0],cred.split(":")[1])
							end
						end
					else
						vprint_error("#{target_url} - No default credentials were provided in the fingerprint, assuming user assigned.")
					end

					# Attempt the datastore usernames and passwords
					if @interface['basic_auth']
						each_user_pass do |user, pass|
								do_login_basic(user, pass)
							end
					else
						each_user_pass do |user, pass|
							do_login(user, pass)
						end
					end
				end
			when 401
				if(@interface['basic_auth'] and check_fingerprint(@response,@interface['fingerprint']))
					vprint_status("#{target_url} - Received 401 and interface requires basic auth, attempting login..")

					# It is very common for multiple pages to match the same fingerprint
					#	especially if a redirect is added to the URI. To prevent this
					#	we mark the interface as previously tested.
					@interface['tested'] = true

					# Skip login attempts if the user says so
					if @interface['creds'] and not datastore['NoDefault']
						# First try the default credentials in the config file
						@interface['creds'].each do |cred|
							do_login_basic(cred.split(":")[0],cred.split(":")[1])
						end
					end

					# Attempt the datastore usernames and passwords
					each_user_pass do |user, pass|
						do_login_basic(user, pass)
					end
				end
			end
	end

	def do_login(user=nil,pass=nil)
		# A user can provide a special response code, verb, or referrer in the configuration file
		res_code = (not @interface['res_code']) ? 200 : @interface['res_code'].to_i
		method = (not @interface['method']) ? 'POST' : @interface['method']
		referrer =  @response.headers["Referrer"] ? "http://www.google.com" : @response.headers["Referrer"]

		if (pass=="nocreds" and user=="nocreds")
			print_good("#{target_url}#{@interface['fingerprint_page']} - No creds are required for #{@interface['title']}")
			report_creds(nil,nil)
			@success = false
			return
		end

		# URI Encode the username and password from the POST params
		login_params = @interface['login_params'].gsub('$$$user$$$',Rex::Text.uri_encode(user.to_s))
		login_params = login_params.gsub('$$$pass$$$',Rex::Text.uri_encode(pass.to_s))
		login_params << @hidden_params

		# Some logins require the creds to be Base64 encoded
		if @interface['login_params'].include?("$$$base64:user$$$")
			login_params = login_params.gsub("$$$base64:user$$$",Rex::Text.uri_encode(Rex::Text.encode_base64(user.to_s)))
			login_params = login_params.gsub("$$$base64:pass$$$",Rex::Text.uri_encode(Rex::Text.encode_base64(pass.to_s)))
		end

		# Some logins include an AD Domain in the POST params
		if @interface['login_params'].include?("$$$domain$$$")
			login_params = login_params.gsub("$$$domain$$$",datastore['DOMAIN'])
		end

		# Some logins replace the vhost in login params
		if @interface['login_params'].include?("$$$vhost$$$")
			login_params = login_params.gsub("$$$vhost$$$",Rex::Text.uri_encode(datastore['VHOST']))
		end

		# Commonly a cookie value will require the vhost
		if @interface['cookie']
			set_cookie = @interface['cookie'].gsub("$$$vhost$$$",@datastore['vhost'])
		else
			set_cookie = ""
		end

		# Pull in cookie information after the first request
		cookie_headers = "#{@response.headers["Set-Cookie"]};#{set_cookie}"
		headers =
			{
				['Cookie'] => cookie_headers,
				['Referrer'] => referrer,
			}

		# A user can headers into the login process, useful for strange interfaces
		headers = headers.merge(@interface['login_headers']) if @interface['login_headers']

		user = "" if user == "null"
		pass = "" if pass == "null"

		print_status("#{target_url}#{@post_to} - #{@interface['title']} - Trying username:'#{user}' with password:'#{pass}'")

		begin
			# Attempt the login
			res = send_request_cgi({
				'method'  => method,
				'uri'     => @post_to,
				'headers' => headers,
				'data'    => login_params
			}, 20)

			print_error("#{target_url} Failed when connecting") if not res
			return :abort if not res

			if (@interface['follow_302'] and (res.code == 302 or res.code == 301))
				# Some success fingerprints depend on following a 302 or 301
				#  Follow and get the new result page to check for success fingerprint
				res = follow_302(res,headers)
			end

			if (res and res.code == res_code and (check_fingerprint(res,@interface['success'])))
				# BOOMY! FACE PUNCH!!
				print_good("#{target_url}#{@post_to} - #{@interface['title']} - SUCCESSFUL login for #{user}:#{pass}")
				@success = false
				# Autopwn here

				report_creds(user,pass)
			else
				print_error("#{target_url}#{@post_to} - #{@interface['title']} - Failed to login as #{user}:#{pass}")
			end
			@successful_login_responses["#{@post_to}-LOGIN-RESPONSE-#{user}:#{pass}"] = res

		rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout
		rescue ::Timeout::Error, ::Errno::EPIPE
		end
	end

	def follow_302(res,headers)
		# Some login responses use 302s to forward to the correct page, this method is
		#	a helper for that situation
		location = "#{res.headers["Location"].split("/").drop(3).join('/')}"

		# Grab the cookie info
		if (res.headers["Set-Cookie"])
			headers = {
				['Cookie'] => res.headers["Set-Cookie"]
			}
		end

		# This is for a strange bug where pulling set-cookie values can
		#	add in a , for new lines therefore mucking up the proper
		#	cookie value.
		headers.each{ |k,v|
			headers[k] = v.gsub(",",";")
		}

		vprint_status("#{target_url} - Following 302 to /#{location}/ after login attempt.")

		begin
			# Request the URI
			res = send_request_raw({
				'uri'     => "/#{location}/",
				'method'  => 'GET',
				'headers' => headers,
			}, 20)
			return :abort if not res

			rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable
			rescue ::Rex::ConnectionTimeout
			rescue ::Timeout::Error, ::Errno::EPIPE
		end

		case res.code
		when 200
			return res
		when 301
			follow_302(res,headers)
		when 302
			follow_302(res,headers)
		when 404
			vprint_status("Received a 404 after login seemed successful, proceeding as if it was a good thing.")
			return res
		else
			vprint_status("Unknown response code #{res.code} after login redirect, proceeding as if it's a good thing.")
			return res
		end
	end

	def do_login_basic(user=nil, pass=nil)
		# Attempt an http basic login
		user = "" if user == "null"
		pass = "" if pass == "null"

		success = (not @interface['success']) ? " " : @interface['success']

		print_status("#{target_url}#{@post_to} - #{@interface['title']} - Trying username:'#{user}' with password:'#{pass}'")

		begin
			res = send_request_raw({
				'method'  => 'GET',
				'uri'	  => @post_to,
				'basic_auth' => "#{user.to_s}:#{pass.to_s}"
				}, 20)
			rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout
			rescue ::Timeout::Error, ::Errno::EPIPE
		end

		print_error("#{target_url} Failed when connecting") if not res

		if res
			case res.code
				when 200
					if(check_fingerprint(res,success))
						print_good("#{target_url}#{@post_to} - #{@interface['title']} - Basic Auth SUCCESSFUL '#{user}':'#{pass}'")
						@success = false
						report_creds(user,pass)
					end
				when 302
					print_good("#{target_url}#{@post_to} - Received 302, assuming SUCCESSFUL #{title} login for '#{user}':'#{pass}'")
					report_creds(user,pass)
				when 401
					print_error("#{target_url}#{@post_to} - #{@interface['title']} - Failed to login as '#{user}'")
				when 404
					print_error("#{target_url}#{@post_to} - Received a 404, how odd.")
				else
					print_status("#{target_url}#{@post_to} - Response code #{res.code} undefined.")
			end
		end
	end

	def write_data()
		# The goal here is that page responses could be saved and could be parsed offline
		#	Successful responses (if they exist) are stored in an other hash and need
		#	to be merged.

		responses = @responses.merge(@successful_login_responses)

		responses.each do |login,res|
			next if not res
			next if res.class == Hash

			save_responses(login,res)
		end
	end

	def too_many_failed_attempts()
		return true if @fails > 2
	end

	def report_creds(user,pass)
		report_hash = {
				:host   => target_url.split(":")[0],
				:port   => datastore['RPORT'],
				:sname  => @interface['title'],
				:user   => user,
				:pass   => pass,
				:active => true,
				:source_type => "interface_fingerprinter",
				:type => 'password'
			}
		report_auth_info(report_hash)
	end

	def save_responses(login,res)
		# Below is stolen from crawler.rb

		info = {
			:web_site => "#{target_url}",
			:path     => login,
			:code     => res.code,
			:body     => res.body,
			:headers  => res.headers.to_s,
			:host => rhost,
			:port => rport
		}

		if res.headers['content-type']
			info[:ctype] = res.headers['content-type']
		end

		if res.headers['set-cookie']
			info[:cookie] = res.headers['set-cookie']
		end

		if res.headers['authorization']
			info[:auth] = res.headers['authorization']
		end

		if res.headers['location']
			info[:location] = res.headers['location']
		end

		if res.headers['last-modified']
			info[:mtime] = res.headers['last-modified']
		end

		# Report the web page to the database
		report_web_page(info)
	end

		def target_url
		vhost = rhost if not vhost
		"#{vhost}:#{rport}#{datastore['Dir']}"
	end

	def check_fingerprint(res,regex)
		# Check the server response against the configuration regex
		pattern = Regexp.new(regex,Regexp::IGNORECASE | Regexp::MULTILINE)

		if (res.body.to_s =~ pattern)
			vprint_status("#{target_url}#{@post_to} - Response matched #{pattern} in the body")
			return true
		elsif (res.headers.to_s =~ pattern)
			vprint_status("#{target_url}#{@post_to} - Response matched #{pattern} in the headers")
			return true
		end
		return false
	end

end
