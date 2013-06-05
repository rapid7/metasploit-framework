##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary

	# Exploit mixins should be called first
	include Msf::Exploit::Remote::HttpClient
	include Msf::Auxiliary::WmapScanServer
	# Scanner mixin should be near last
	include Msf::Auxiliary::Scanner
	include Msf::Auxiliary::Report

	def initialize
		super(
			'Name'        => 'HTTP Subversion Scanner',
			'Description' => 'Detect subversion directories and files and analize its content. Only SVN Version > 7 supported',
			'Author'       => ['et'],
			'License'     => MSF_LICENSE
		)

		register_options(
			[
				OptString.new('PATH', [ true,  "The test path to .svn directory", '/']),
				OptBool.new('GET_SOURCE', [ false, "Attempt to obtain file source code", true ]),
				OptBool.new('SHOW_SOURCE', [ false, "Show source code", true ])

			], self.class)

		register_advanced_options(
			[
				OptInt.new('ErrorCode', [ true, "Error code for non existent directory", 404]),
				OptPath.new('HTTP404Sigs',   [ false, "Path of 404 signatures to use",
						File.join(Msf::Config.install_root, "data", "wmap", "wmap_404s.txt")
					]
				),
				OptBool.new('NoDetailMessages', [ false, "Do not display detailed test messages", true ])

			], self.class)
	end

	def run_host(target_host)
		conn = true
		ecode = nil
		emesg = nil

		tpath = normalize_uri(datastore['PATH'])
		if tpath[-1,1] != '/'
			tpath += '/'
		end

		ecode = datastore['ErrorCode'].to_i
		vhost = datastore['VHOST'] || wmap_target_host

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
					print_status("Using first 256 bytes of the response as 404 string")
					emesg = res.body[0,256]
				else
					print_status("Using custom 404 string of '#{emesg}'")
				end
			else
				ecode = tcode
				print_status("Using code '#{ecode}' as not found.")
			end

		rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout
			conn = false
		rescue ::Timeout::Error, ::Errno::EPIPE
		end

		return if not conn

		dm = datastore['NoDetailMessages']

		begin
			turl = tpath+'.svn/entries'

			res = send_request_cgi({
				'uri'          => turl,
				'method'       => 'GET',
				'version' => '1.0',
			}, 10)

			if(not res or ((res.code.to_i == ecode) or (emesg and res.body.index(emesg))))
				if dm == false
					print_status("[#{target_host}] NOT Found. #{tpath} #{res.code}")
				end
			else
				print_good("[#{target_host}:#{rport}] SVN Entries file found.")

				report_web_vuln(
					:host	=> target_host,
					:port	=> rport,
					:vhost  => vhost,
					:ssl    => ssl,
					:path	=> turl,
					:method => 'GET',
					:pname  => "",
					:proof  => "Res code: #{res.code.to_s}",
					:risk   => 0,
					:confidence   => 100,
					:category     => 'file',
					:description  => 'SVN Entry found.',
					:name   => 'file'
				)

				vers = res.body[0..1].chomp.to_i
				if vers <= 6
					print_error("[#{target_host}] Version #{vers} not supported")
					return
				end
				n = 0
				res.body.split("\f\n").each do |record|
					resarr = []
					resarr = record.to_s.split("\n")

					if n==0
						#first record
						version = resarr[0]
						sname = "CURRENT"
						skind = resarr[2]
						srevision = resarr[3]
						surl = resarr[4]
						slastauthor = resarr[11]

					else
						sname = resarr[0]
						skind = resarr[1]
						srevision = resarr[2]
						surl = resarr[3]
						slastauthor = resarr[10]
					end

					print_status("[#{target_host}] #{skind} #{sname} [#{slastauthor}]")

					if slastauthor and slastauthor.length > 0
						report_note(
							:host	=> target_host,
							:proto => 'tcp',
							:sname => (ssl ? 'https' : 'http'),
							:port	=> rport,
							:type	=> 'USERNAME',
							:data	=> slastauthor,
							:update => :unique_data
						)

					end

					if skind
						if skind == 'dir'
							report_note(
								:host	=> target_host,
								:proto => 'tcp',
								:sname => (ssl ? 'https' : 'http'),
								:port	=> rport,
								:type	=> 'DIRECTORY',
								:data	=> sname,
								:update => :unique_data
							)
						end

						if skind == 'file'
							report_note(
								:host	=> target_host,
								:proto => 'tcp',
								:sname => (ssl ? 'https' : 'http'),
								:port	=> rport,
								:type	=> 'FILE',
								:data	=> sname,
								:update => :unique_data
							)

							if datastore['GET_SOURCE']
								print_status("- Trying to get file #{sname} source code.")

								begin
									turl = tpath+'.svn/text-base/'+sname+'.svn-base'
									print_status("- Location: #{turl}")

									srcres = send_request_cgi({
										'uri'          => turl,
										'method'       => 'GET',
										'version' => '1.0',
									}, 10)

									if srcres and srcres.body.length > 0
										if datastore['SHOW_SOURCE']
											print_status(srcres.body)
										end

										report_note(
											:host	=> target_host,
											:proto => 'tcp',
											:sname => (ssl ? 'https' : 'http'),
											:port	=> rport,
											:type	=> 'SOURCE_CODE',
											:data	=> "#{sname} Code: #{srcres.body}",
											:update => :unique_data
										)
									end
								rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout
								rescue ::Timeout::Error, ::Errno::EPIPE
								end
							end
						end
					end
					n += 1
				end
				print_status("Done. #{n} records.")
			end

		rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout
		rescue ::Timeout::Error, ::Errno::EPIPE
		end
	end
end
