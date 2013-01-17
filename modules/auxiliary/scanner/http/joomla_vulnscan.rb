##
# $Id: joomla_vulnscan.rb
##
##
#Thanks to @zeroSteiner @kaospunk helping with examples and questions. Also thanks to Joomscan and various MSF modules for code examples.
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
			'Name'        => 'Joomla Scanner',
			'Version'     => '$Revision: 14774 $',
			'Description' => %q{
					This module scans the Joomla install for information and potential vulnerabilites.
			},
			'Author'      => [ 'f8lerror' ],
			'License'     => MSF_LICENSE
		)
	register_options(
			[
				OptString.new('PATH', [ true,  "The path to the Joomla install", '/']),
				OptBool.new('ENUMERATE', [ false, "Enumerate Plugins", true]),

				OptPath.new('PLUGINS',   [ false, "Path to list of plugins to enumerate",
						File.join(Msf::Config.install_root, "data", "wordlists", "pcheck.txt")
					]
				)

			], self.class)
	end

	def osfingerprint(response)
		if(response.headers.has_key?('Server') )
			if(response.headers['Server'] =~/Win32/ or response.headers['Server'] =~ /\(Windows/ or response.headers['Server'] =~ /IIS/)
				os = "Windows"
			elsif(response.headers['Server'] =~ /Apache\// and response.headers['Server'] !~/(Win32)/)
					os = "*Nix"
			else
				os = "Unknown Server Header Reporting: "+response.headers['Server']
			end
		end
		return os
		end
	def fingerprint(response, app)

		if(response.body =~ /<version.*\/?>(.+)<\/version\/?>/i)
			v = $1
			out = (v =~ /^6/) ? "Joomla #{v}" : " #{v}"
		elsif(response.body =~ /system\.css 20196 2011\-01\-09 02\:40\:25Z ian/ or
			response.body =~ /MooTools\.More\=\{version\:\"1\.3\.0\.1\"/ or
			response.body =~ /en-GB\.ini 20196 2011\-01\-09 02\:40\:25Z ian/ or
			response.body =~ /en-GB\.ini 20990 2011\-03\-18 16\:42\:30Z infograf768/ or
			response.body =~/20196 2011\-01\-09 02\:40\:25Z ian/)
			out = "1.6"
		elsif(response.body =~ /system\.css 21322 2011\-05\-11 01\:10\:29Z dextercowley / or
			response.body =~ /MooTools\.More\=\{version\:\"1\.3\.2\.1\"/ or response.body =~ /22183 2011\-09\-30 09\:04\:32Z infograf768/ or response.body =~ /21660 2011\-06\-23 13\:25\:32Z infograf768/)
			out = "1.7"
		elsif(response.body =~ /Joomla! 1.5/ or
			response.body =~ /MooTools\=\{version\:\'1\.12\'\}/ or response.body =~ /11391 2009\-01\-04 13\:35\:50Z ian/)
			out = "1.5"
		elsif(response.body =~ /Copyright \(C\) 2005 \- 2012 Open Source Matters/ or
			response.body =~ /MooTools.More\=\{version\:\"1\.4\.0\.1\"/ )
			out = "2.5"
		elsif(response.body =~ /<meta name=\"Keywords\" content=\"(.*)\">\s+<meta name/)
			out = $1.split(/,/)[0]
		elsif(response.body =~ /(Copyright \(C\) 2005 - 200(6|7))/ or
			response.body =~/47 2005\-09\-15 02\:55\:27Z rhuk/ or response.body =~/423 2005\-10\-09 18\:23\:50Z stingrey/ or
			response.body =~/1005 2005\-11\-13 17\:33\:59Z stingrey/ or response.body =~/1570 2005\-12\-29 05\:53\:33Z eddieajau/ or
			response.body =~/2368 2006\-02\-14 17\:40\:02Z stingrey/  or response.body =~/4085 2006\-06\-21 16\:03\:54Z stingrey/ or
			response.body =~/4756 2006\-08\-25 16\:07\:11Z stingrey/ or response.body =~/5973 2006\-12\-11 01\:26\:33Z robs/  or
			response.body =~/5975 2006\-12\-11 01\:26\:33Z robs/)
			out = "1.0"
		else
			out = 'Unknown Joomla'
		end
		return out
	end

	def run_host(ip)
		tpath = datastore['PATH']
			if tpath[-1,1] != '/'
			tpath += '/'
			end
		apps = [ 'language/en-GB/en-GB.xml',
				'templates/system/css/system.css',
				'media/system/js/mootools-more.js',
				'language/en-GB/en-GB.ini','htaccess.txt', 'language/en-GB/en-GB.com_media.ini']
		iapps = ['robots.txt','administrator/index.php','/admin/','index.php/using-joomla/extensions/components/users-component/registration-form',
				'index.php/component/users/?view=registration','htaccess.txt']
		print_status("Checking Host: #{ip} for version information")
		apps.each do |app|
			break if check_app(tpath,app,ip)
			end
		print_status("Scanning for interesting pages")
		iapps.each do |iapp|
			scan_pages(tpath,iapp,ip)
			end
		if datastore['ENUMERATE']
		print_status("Scanning for plugins")
		bres = send_request_cgi({
			'uri' => tpath,
			'method' => 'GET',
			}, 5)
		return if not bres or not bres.body or not bres.code
		bres.body.gsub!(/[\r|\n]/, ' ')
			File.open(datastore['PLUGINS'], 'rb').each_line do |bapp|
			papp = bapp.chomp
			plugin_search(tpath,papp,ip,bres)
			end
			end

		end
	def check_app(tpath, app, ip)
		res = send_request_cgi({
				'uri' => tpath+app,
				'method' => 'GET',
				}, 5)
		return if not res or not res.body or not res.code
		res.body.gsub!(/[\r|\n]/, ' ')
		os = osfingerprint(res)
		if (res.code.to_i == 200)
			out = fingerprint(res,app)
			return if not out
			if(out =~ /Unknown Joomla/)
				print_error("Unable to identify Joomla Version with this file #{app}")
				return false
			else
				print_good("Joomla Version:#{out} from: #{app} ")
				print_good("OS: #{os}")
				report_note(
					:host  => ip,
					:port  => datastore['RPORT'],
					:proto => 'http',
					:ntype => 'Joomla Version',
					:data  => out
				)
				return true
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
	def scan_pages(tpath,iapp, ip)
		res = send_request_cgi({
				'uri' => tpath+iapp,
				'method' => 'GET',
				}, 5)
		return if not res or not res.body or not res.code
		res.body.gsub!(/[\r|\n]/, ' ')
		if (res.code.to_i == 200)
			if(res.body =~ /Administration Login/ and res.body =~ /\(\'form-login\'\)\.submit/ or res.body =~/administration console/)
				sout = "Administrator Login Page"
			elsif(res.body =~/Registration/ and res.body =~/class="validate">Register<\/button>/)
				sout = "Registration Page"
			else
				sout = iapp
			end
			return if not sout
			if(sout == iapp)
				print_good("#{iapp}")
			elsif print_good("#{sout}: #{iapp}  ")
				report_note(
					:host  => ip,
					:port  => datastore['RPORT'],
					:proto => 'http',
					:ntype => 'Joomla Pages',
					:data  => sout
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
	def plugin_search(tpath,papp, ip, bres)
		res = send_request_cgi({
				'uri' => tpath+papp,
				'method' => 'GET',
				}, 5)
		return if not res or not res.body or not res.code
		res.body.gsub!(/[\r|\n]/, ' ')
		osize = bres.body.size
		nsize = res.body.size
		if (res.code.to_i == 200 and res.body !~/#404 Component not found/ and res.body !~/<h1>Joomla! Administration Login<\/h1>/ and osize != nsize)
			print_good("Found Plugin: #{papp} ")
			if (papp =~/passwd/ and res.body !~/root/)
						print_error("\tPasswd not found")
			elsif(papp =~/passwd/ and res.body =~/root/)
					print_good("\tPasswd file found in response")
			elsif(papp =~/'/ or papp =~/union/ or papp =~/sqli/ or papp =~/-\d/ and papp !~/alert/ and res.body =~/SQL syntax/)
					print_good("\tPossible SQL Injection")
			elsif(papp =~/'/ or papp =~/union/ or papp =~/sqli/ or papp =~/-\d/ and papp !~/alert/ and res.body !~/SQL syntax/)
					print_error("\tUnable to identify SQL injection")
			elsif(papp =~/>alert/ and res.body !~/>alert/)
				print_error("\tNo XSS")
			elsif(papp =~/>alert/ and res.body =~/>alert/)
				print_good("\tPossible XSS")
			elsif(res.body =~/SQL syntax/ )
				print_error("\tPossible SQL Injection")
			elsif(papp =~/com_/)
			blah = papp.split('_')
			blah1 = blah[1].gsub('/','')
			res1 = send_request_cgi({
				'uri' => tpath+"index.php?option=com_#{blah1}",
				'method' => 'GET',
				}, 5)
				if (res1.code.to_i == 200)
			print_status("\tFound_page: index.php?option=com_#{blah1}")
				end
				end
				report_note(
					:host  => ip,
					:port  => datastore['RPORT'],
					:proto => 'http',
					:ntype => 'Plugin Found',
					:data  => papp
				)
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
