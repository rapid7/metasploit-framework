##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary
	include Msf::Exploit::Remote::HttpClient
	include Msf::Auxiliary::Scanner

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

			register_advanced_options(
				[
					OptInt.new('NUM_REDIRECTS', [ true, "Number of HTTP redirects to follow", 10])
				], self.class)
	end

	def setup()
		# Check if database is active
		if db()
			@db_active = true
		else
			@db_active = false
		end
	end

	def get_xml_rpc_url(ip)
		# code to find the xmlrpc url when passed in IP
		vprint_status("Enumerating XML-RPC URI for #{ip}...")

		begin
			res = send_request_cgi(
			{
					'method'	=> 'HEAD',
			})
			# Check if X-Pingback exists and return value
			unless res.nil?
				unless res['X-Pingback'].nil?
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

	def get_blog_posts(xml_rpc, ip)
		# find all blog posts within IP and determine if pingback is enabled
		vprint_status("Enumerating Blog posts...")
		blog_posts = {}

		# make http request to feed url
		begin
			res = send_request_cgi({
				'uri'    => '/?feed=rss2',
				'method' => 'GET',
				})

			resolve = true
			count = datastore['NUM_REDIRECTS']
			while (res.code == 301 || res.code == 302) and count != 0
				if resolve
					print_status("Resolving #{ip}/?feed=rss2 to locate wordpress feed...")
					resolve = false
				else
					vprint_status("Web server returned a #{res.code}...following to #{res.headers['location']}")
				end
				uri = res.headers['location'].sub(/.*?#{ip}/, "")
				res = send_request_cgi({
					'uri'    => "#{uri}",
					'method' => 'GET',
					})

				if res.code == 200
					vprint_status("Feed located at http://#{ip}#{uri}")
				end
				count = count - 1
			end
		rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout
			return nil
		rescue ::Timeout::Error, ::Errno::EPIPE
			return nil
		end

		# parse out links and place in array
		links = res.to_s.scan(/<link>([^<]+)<\/link>/i)

		if res.code != 200 or links.nil? or links.empty?
			return blog_posts
		end

		links.each do |link|
			blog_post = link[0]
			pingback_request = get_pingback_request(xml_rpc, 'http://127.0.0.1', blog_post)

			pingback_disabled_match = pingback_request.body.match(/<value><int>33<\/int><\/value>/i)
			if pingback_request.code == 200 and pingback_disabled_match.nil?
				print_good("Pingback enabled: #{link.join}")
				blog_posts = link.join
				return blog_posts
			else
				vprint_status("Pingback disabled: #{link.join}")
			end
		end
		return blog_posts
	end

	# method to send xml-rpc requests
	def get_pingback_request(xml_rpc, target, blog_post)
		uri = xml_rpc.sub(/.*?#{ip}/,"")
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

	# Save data to vuln table
	def store_vuln(ip, blog)
		report_vuln(
			:host			=> ip,
			:name			=> self.name,
			:info			=> "Module #{self.fullname} found pingback at #{blog}"
		)
	end

	# main control method
	def run_host(ip)
		# call method to get xmlrpc url
		xmlrpc = get_xml_rpc_url(ip)

		# once xmlrpc url is found, get_blog_posts
		if xmlrpc.nil?
			print_error("#{ip} does not appear to be vulnerable")
		else
			hash = get_blog_posts(xmlrpc, ip)

			if hash
				store_vuln(ip, hash) if @db_active
			else
				print_status("X-Pingback enabled but no vulnerable blogs found on #{ip}...")
			end
		end
	end
end