##
# Some of this code was taken from the "jboss_vulnscan" module by: Tyler Krpata
##

require 'rex/proto/http'
require 'msf/core'

class Metasploit3 < Msf::Auxiliary

	include Msf::Exploit::Remote::HttpClient
	include Msf::Auxiliary::Scanner
	include Msf::Auxiliary::Report

	def initialize(info = {})
		super(update_info(info,
			'Name'                  => 'Jenkins Vulnerability Scanner',
			'Description'   => %q{
				This module scans a Jenkins installation for a few vulnerablities.
			},
			'Author'                => 'Jeff McCutchan',
			'License'               => MSF_LICENSE
			))

		register_options(
			[
				OptString.new('TARGETURI',  [ true,  "Path to Jenkins instance", "/jenkins/"]),
			], self.class)
	end

	def run_host(ip)
		res = send_request_cgi(
			{
			'uri'       => target_uri.path, #wanted to use a random path but Jenkins headers were not returned
			'method'    => 'GET',
			'ctype'     => 'text/plain',
		})
		if res
			#check to see if we are dealing with a Jenkins installation
			if not res.headers.include?('X-Jenkins')
				print_status("#{rhost}:#{rport} responded with #{res.code} but does not seem to be Jenkins") if res.code != 404
				return
			end
		end
		version = res.headers['X-Jenkins']
		vprint_status("#{rhost}:#{rport} Jenkins Version - #{version}")
		apps = [ 'script', #exploit module for this
				'view/All/newJob', #possible to exploit manually maybe there will be a module in the future
				'systemInfo', #can disclose some useful information about the system
		]
		apps.each do |app|
			check_app(app, version)
		end
	end

	def check_app(app, version)
		uri_path = normalize_uri(target_uri.path, app)
		res = send_request_cgi({
			'uri'       => uri_path,
			'method'    => 'GET',
			'ctype'     => 'text/plain',
		}, 20)
		case (res.code)
		when 200
			print_good("#{rhost}:#{rport} /#{app} does not require authentication (200)")
			case app
				when "systemInfo"
					parse_system_info(res.body, version)
				when "script"
					report_vuln(
						:host        => rhost,
						:port        => rport,
						:proto       => 'tcp',
						:sname       => (ssl ? 'https' : 'http'),
						:name        => self.name,
						:info        => "Module #{self.fullname} confirmed access to the Jenkins Script Console with no authentication"
					)
			end
		when 403
			vprint_status("#{rhost}:#{rport} #{app} restricted (403)")
		when 401
			vprint_status("#{rhost}:#{rport} #{app} requires authentication (401): #{res.headers['WWW-Authenticate']}")
		when 404
			vprint_status("#{rhost}:#{rport} #{app} not found (404)")
		when 301
			vprint_status("#{rhost}:#{rport} #{app} is redirected (#{res.code}) to #{res.headers['Location']} (not following)")
		when 302
			vprint_status("#{rhost}:#{rport} #{app} is redirected (#{res.code}) to #{res.headers['Location']} (not following)")
		else
			vprint_status("#{rhost}:#{rport} Don't know how to handle response code #{res.code}")
		end
	end


	def parse_system_info(body, version)
		vprint_status("#{rhost}:#{rport} getting useful information from /systemInfo")
		infos = ["os.name", "sun.os.patch.level", "os.arch", "user.name", "USERDOMAIN", "SHELL"]
		out = []
		if version.to_f < 1.526 #html parsing is version dependent
			lines = body.split('</tr>')
			infos.each do |info|
				lines.each do |line|
					next if not line.include? info
					line = line.sub('<tr><td class="pane">', '')
					line = line.sub(info, '')
					line = line.sub('</td><td class="pane">', '')
					line = line.sub('</td>', '')
					out.push(info)
					out.push(line)
				end
			end
		elsif version.to_f >= 1.526
			lines = body.split('</td></tr><tr><td class="pane">')
			infos.each do |info|
				lines.each do |line|
					next if not line.include? info
					line = line.sub('</td><td class="pane" style="white-space: normal">', '')
					line = line.sub(info, '')
					line = line.strip
					out.push(info)
					out.push(line)
				end
			end
		end
		#print out the goodies
		out = out.uniq
		out.each do |o|
			dex = out.index(o)
			case o
				when "os.name"
					print_line("   OS: " + out[dex+1])
				when "sun.os.patch.level"
					print_line("   Patch Level: " + out[dex+1])
				when "os.arch"
					print_line("   Arch: " + out[dex+1])
				when "user.name"
					print_line("   User: " + out[dex+1])
				when "USERDOMAIN"
					print_line("   Domain: " + out[dex+1])
				when "SHELL"
					print_line("   Shell: " + out[dex+1])
			end
		end
		print_line('')
	end
end
