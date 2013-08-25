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
	include Msf::Auxiliary::Report

	def initialize
		super(
			'Name'        => 'ColdFusion Version Scanner',
			'Description' => %q{
				This module attempts identify various flavors of ColdFusion up to version 10
				as well as the underlying OS.
			},
			'Author'      =>
				[
					'nebulus',  # Original
					'sinn3r'    # Fingerprint() patch for Cold Fusion 10
				],
			'License'     => MSF_LICENSE
		)
	end

	def fingerprint(response)

		if(response.headers.has_key?('Server') )
			if(response.headers['Server'] =~ /IIS/ or response.headers['Server'] =~ /\(Windows/)
				os = "Windows (#{response.headers['Server']})"
			elsif(response.headers['Server'] =~ /Apache\//)
				os = "Unix (#{response.headers['Server']})"
			else
				os = response.headers['Server']
			end
		end

		return nil if response.body.length < 100

		title = "Not Found"
		if(response.body =~ /<title.*\/?>(.+)<\/title\/?>/im)
			title = $1
			title.gsub!(/\s/, '')
		end

		return nil if( title == 'Not Found' or not title =~ /ColdFusionAdministrator/)

		out = nil

		if(response.body =~ />\s*Version:\s*(.*)<\/strong\><br\s\//)
			v = $1
			out = (v =~ /^6/) ? "Adobe ColdFusion MX6 #{v}" : "Adobe ColdFusion MX7 #{v}"
		elsif(response.body =~ /<meta name=\"Author\" content=\"Copyright 1995\-2012 Adobe/ and response.body =~ /Administrator requires a browser that supports frames/ )
			out = "Adobe ColdFusion MX7"
		elsif(response.body =~ /<meta name=\"Author\" content=\"Copyright \(c\) 1995\-2006 Adobe/)
			out = "Adobe ColdFusion 8"
		elsif(response.body =~ /<meta name=\"Author\" content=\"Copyright \(c\) 1995\-2010 Adobe/ and
			response.body =~ /1997\-2012 Adobe Systems Incorporated and its licensors/)
			out = "Adobe ColdFusion 10"
		elsif(response.body =~ /<meta name=\"Author\" content=\"Copyright \(c\) 1995\-2010 Adobe/ or
			response.body =~ /<meta name=\"Author\" content=\"Copyright \(c\) 1995\-2009 Adobe Systems\, Inc\. All rights reserved/ or
			response.body =~ /<meta name=\"Author\" content=\"Copyright \(c\) 1997\-2012 Adobe Systems\, Inc\. All rights reserved/)
			out = "Adobe ColdFusion 9"
		elsif(response.body =~ /<meta name=\"Keywords\" content=\"(.*)\">\s+<meta name/)
			out = $1.split(/,/)[0]
		else
			out = 'Unknown ColdFusion'
		end

		if(title.downcase == 'coldfusionadministrator')
			out << " (administrator access)"
		end

		out << " (#{os})"
		return out
	end

	def run_host(ip)

		url = '/CFIDE/administrator/index.cfm'

		res = send_request_cgi({
			'uri' => url,
			'method' => 'GET',
		})

		return if not res or not res.body or not res.code
		res.body.gsub!(/[\r|\n]/, ' ')

		if (res.code.to_i == 200)
			out = fingerprint(res)
			return if not out
			if(out =~ /^Unknown/)
				print_status("#{ip} " << out)
				return
			else
				print_good("#{ip}: " << out)
				report_note(
					:host  => ip,
					:port  => datastore['RPORT'],
					:proto => 'tcp',
					:ntype => 'cfversion',
					:data  => out
				)
			end
		elsif(res.code.to_i == 403 and datastore['VERBOSE'])
			if(res.body =~ /secured with Secure Sockets Layer/ or res.body =~ /Secure Channel Required/ or res.body =~ /requires a secure connection/)
				print_status("#{ip} denied access to #{url} (SSL Required)")
			elsif(res.body =~ /has a list of IP addresses that are not allowed/)
				print_status("#{ip} restricted access by IP")
			elsif(res.body =~ /SSL client certificate is required/)
				print_status("#{ip} requires a SSL client certificate")
			else
				print_status("#{ip} denied access to #{url} #{res.code} #{res.message}")
			end
		end

	rescue OpenSSL::SSL::SSLError
	rescue Errno::ENOPROTOOPT, Errno::ECONNRESET, ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout, ::ArgumentError
	rescue ::Timeout::Error, ::Errno::EPIPE
	end

end
