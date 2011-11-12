##
# $Id$
##

##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/framework/
##

require 'rex/proto/http'
require 'msf/core'
require 'thread'


class Metasploit3 < Msf::Auxiliary

	include Msf::Exploit::Remote::HttpClient
	include Msf::Auxiliary::WMAPScanDir
	include Msf::Auxiliary::Scanner
	include Msf::Auxiliary::Report

	def initialize(info = {})
		super(update_info(info,
			'Name'   		=> 'HTTP private IP Scanner',
			'Description'	=> %q{
				This module identifies misconfigurations of Webservers which leak their 
				internal ip addresses.
			},
			'Author' 		=> [ 'Andurin' ],
			'License'		=> BSD_LICENSE,
			'References'     =>
                                [
                                        [ 'CVE', '2000-0649' ],
                                        [ 'OSVDB', '54159'],
                                        [ 'BID', '1499' ],
                                ],
			'Version'		=> '$Revision$'))

		register_options(
			[
				OptString.new('PATH', [ true,  "The path  to identify files", '/']),
				OptPath.new('DICTIONARY',   [ false, "Path of word dictionary to use",
						File.join(Msf::Config.install_root, "data", "wmap", "wmap_dirs.txt")
					]
				)

			], self.class)

		register_advanced_options(
			[
				OptInt.new('ErrorCode', [ true, "Error code for non existent directory", 404]),
				OptPath.new('HTTP404Sigs',   [ false, "Path of 404 signatures to use",
						File.join(Msf::Config.install_root, "data", "wmap", "wmap_404s.txt")
					]
				),
				OptBool.new('NoDetailMessages', [ false, "Do not display detailed test messages", true ]),
				OptInt.new('TestThreads', [ true, "Number of test threads", 25]),
				OptBool.new('DetectRedirect', [ false, "Try to detect HTTP redirects after found a DIR", true ])

			], self.class)

		deregister_options('VHOST')

	end

	def run_host(ip)
		conn = true
		ecode = nil
		emesg = nil

		tpath = datastore['PATH']
		if tpath[-1,1] != '/'
			tpath += '/'
		end

		ecode = datastore['ErrorCode'].to_i
		vhost = datastore['VHOST'] || wmap_target_host
		prot  = datastore['SSL'] ? 'https' : 'http'


		#
		# Detect error code
		#
		begin
			randdir = Rex::Text.rand_text_alpha(5).chomp + '/'
			res = send_request_cgi({
				'uri'  		=>  tpath+randdir,
				'method'   	=> 'GET',
				'ctype'		=> 'text/html'
			}, 20)

			return if not res

			tcode = res.code.to_i


			# Look for a string we can signature on as well
			if(tcode >= 200 and tcode <= 299)

				File.open(datastore['HTTP404Sigs'], 'rb').each do |str|
					if(res.body.index(str))
						emesg = str
						break
					end
				end

				if(not emesg)
					print_status("Using first 256 bytes of the response as 404 string for #{wmap_target_host}")
					emesg = res.body[0,256]
				else
					print_status("Using custom 404 string of '#{emesg}' for #{wmap_target_host}")
				end
			elsif(tcode >= 300 and tcode <= 399)
				ecode = "404"
				print_status("Detected redirect on random URI, using '#{ecode}' as not found for #{wmap_target_host}")
			else
				ecode = tcode
				print_status("Using code '#{ecode}' as not found for #{wmap_target_host}")
			end

		rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout
			conn = false
		rescue ::Timeout::Error, ::Errno::EPIPE
		end

		return if not conn

		nt = datastore['TestThreads'].to_i
		nt = 1 if nt == 0

		dm = datastore['NoDetailMessages']
		testredir = datastore['DetectRedirect']

		queue = []
		File.open(datastore['DICTIONARY'], 'rb').each_line do |testd|
			queue << testd.strip + '/'
		end

		while(not queue.empty?)
			t = []
			1.upto(nt) do
				t << Thread.new(queue.shift) do |testf|
					Thread.current.kill if not testf

					testfdir = testf
					res = send_request_cgi({
						'uri'  		=>  tpath+testfdir,
						'method'   	=> 'GET',
						'ctype'		=> 'text/html'
					}, 20)


					if(not res or ((res.code.to_i == ecode) or (emesg and res.body.index(emesg))))
						if dm == false
							print_status("NOT Found #{wmap_base_url}#{tpath}#{testfdir} #{res.code} (#{wmap_target_host})")
						end
					elsif (res.code.to_i >= 300 and res.code.to_i <=399)
						print_status("Found http redirect #{wmap_base_url}#{tpath}#{testfdir} #{res.code} (#{wmap_target_host})")
						if res.headers['Location']
							print_status("---> Found a Location Header in response: '#{res.headers["Location"]}'") if res.headers["Location"]
							report_note(
								:host	=> ip,
								:port	=> rport,
								:proto	=> (ssl ? 'https' : 'http'),
								:ntype  => 'web.internal_address',
								:data	=> "#{tpath}#{testfdir} Code: #{res.code} Location: #{res.headers['Location']}",
								:update => :unique_data
							)

							res2 = send_request_wo_hostheader(tpath, testfdir)
							priv_ip = check_ip(res2)
							if (priv_ip && (priv_ip != wmap_target_host))
								print_status("---> Found internal IP '#{priv_ip}' on #{wmap_base_url}#{tpath}#{testfdir} #{res2.code} (#{wmap_target_host})")
								report_note(
									:host   => ip,
									:port   => rport,
									:proto  => (ssl ? 'https' : 'http'),
									:ntype  => 'web.internal_address',
									:data   => "#{tpath}#{testfdir} Code: #{res2.code} Internal IP: #{priv_ip}",
									:update => :unique_data
									)
							end

						else
							report_note(
								:host	=> ip,
								:port	=> rport,
								:proto	=> (ssl ? 'https' : 'http'),
								:ntype  => 'web.internal_address',
								:data	=> "#{tpath}#{testfdir} Code: #{res.code}",
								:update => :unique_data
							)
						end
					else
						report_note(
							:host	=> ip,
							:port	=> rport,
							:proto	=> (ssl ? 'https' : 'http'),
							:type	=> 'DIRECTORY',
							:data	=> "#{tpath}#{testfdir} Code: #{res.code}",
							:update => :unique_data
						)

						print_status("Found #{wmap_base_url}#{tpath}#{testfdir} #{res.code} (#{wmap_target_host})")

						if testredir == true
							# Prepare second connect...
							if testfdir[-1,1] == '/'
								testfdir2 = testfdir
								testfdir2[-1,1] = ''
	                                                end
							res2 = send_request_wo_hostheader(tpath, testfdir2)
							if (res2.code.to_i >= 300 and res2.code.to_i <=399)
								print_status("Found http redirect #{wmap_base_url}#{tpath}#{testfdir2} #{res2.code} (#{wmap_target_host})")
								if res2.headers['Location']
									print_status("---> Found a Location Header in response: '#{res2.headers["Location"]}'")
									priv_ip = check_ip(res2)
									if (priv_ip && (priv_ip != wmap_target_host))
											print_status("---> Found internal IP '#{priv_ip}' on #{wmap_base_url}#{tpath}#{testfdir2} #{res2.code} (#{wmap_target_host})")
											report_note(
												:host   => ip,
												:port   => rport,
												:proto  => (ssl ? 'https' : 'http'),
												:ntype  => 'web.internal_address',
												:data   => "#{tpath}#{testfdir2} Code: #{res2.code} Internal IP: #{priv_ip}",
												:update => :unique_data
											)
											break
									end

									report_note(
										:host	=> ip,
										:port	=> rport,
										:proto	=> (ssl ? 'https' : 'http'),
										:ntype  => 'web.http_redirect',
										:data	=> "#{tpath}#{testfdir2} Code: #{res2.code} Location: #{res2.headers['Location']}",
										:update => :unique_data
									)
								else
									report_note(
										:host	=> ip,
										:port	=> rport,
										:proto	=> (ssl ? 'https' : 'http'),
										:ntype  => 'web.http_redirect',
										:data	=> "#{tpath}#{testfdir2} Code: #{res2.code}",
										:update => :unique_data
									)
								end
							end
						end
						if res.code.to_i == 401
							print_status("#{wmap_base_url}#{tpath}#{testfdir} requires authentication: #{res.headers['WWW-Authenticate']}")

							report_note(
								:host	=> ip,
								:port	=> rport,
								:proto	=> (ssl ? 'https' : 'http'),
								:type	=> 'WWW_AUTHENTICATE',
								:data	=> "#{tpath}#{testfdir} Auth: #{res.headers['WWW-Authenticate']}",
								:update => :unique_data
							)
						end
					end

				end
			end
			t.map{|x| x.join }
		end
	end

	def check_ip(res)
		if res.headers['Location']
			ip_regex = [
				/\/\/((10)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?))/,
				/\/\/(172\.1[6-9]\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?))/,
				/\/\/(172\.2[0-9]\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?))/,
				/\/\/(172\.3[0-1]\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?))/,
				/\/\/((192\.168)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?))/
				]
			priv_ip = nil
			ip_regex.each do |regex|
				priv_ip = regex.match(res.headers.to_s)
				if (priv_ip && (priv_ip[1] != wmap_target_host))
					return priv_ip[1]
					break
				end
			end
			return nil
		end
	end

	def send_request_wo_hostheader(tpath,testfdir)
		conn = connect()
		req = conn.request_raw({
			'uri'  		=>  tpath+testfdir,
			'method'   	=> 'GET',
			'version'	=> '1.0',
			'ctype'		=> 'text/html'
			})
		# Remove Host Header from request
		req = req.sub(/Host: .+\r\n/,'')
		res = conn.send_recv(req)
		return res
	end
end

