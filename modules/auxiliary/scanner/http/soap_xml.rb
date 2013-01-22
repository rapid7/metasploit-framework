##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary

	# Exploit mixins should be called first
	include Msf::Exploit::Remote::HttpClient
	include Msf::Auxiliary::Report
	include Msf::Auxiliary::WmapScanDir
	# Scanner mixin should be near last
	include Msf::Auxiliary::Scanner

	def initialize(info = {})
		super(update_info(info,
			'Name'        => 'HTTP SOAP Verb/Noun Brute Force Scanner',
			'Description' => %q{
				This module attempts to brute force SOAP/XML requests to uncover
				hidden methods.
			},
			'Author'      => [ 'patrick' ],
			'License'     => MSF_LICENSE))

		register_options(
			[
				OptString.new('PATH', [ true,  "The path to test", '/']),
				OptString.new('XMLNAMESPACE', [ true,  "XML Web Service Namespace", 'http://tempuri.org/']),
				OptString.new('XMLINSTANCE', [ true,  "XML Schema Instance", 'http://www.w3.org/2001/XMLSchema-instance']),
				OptString.new('XMLSCHEMA', [ true,  "XML Schema", 'http://www.w3.org/2001/XMLSchema']),
				OptString.new('XMLSOAP', [ true,  "XML SOAP", 'http://schemas.xmlsoap.org/soap/envelope/']),
				OptString.new('CONTENTTYPE', [ true,  "The HTTP Content-Type Header", 'application/x-www-form-urlencoded']),
				OptInt.new('SLEEP', [true, "Sleep this many seconds between requests", 0 ]),
				OptBool.new('DISPLAYHTML', [ true,  "Display HTML response", false ]),
				OptBool.new('SSL', [ true,  "Use SSL", false ]),
				OptBool.new('VERB_DELETE', [ false,  "Enable 'delete' verb", 'false'])
			], self.class)
	end

	# Fingerprint a single host
	def run_host(ip)

		verbs = [
				'get',
				'active',
				'activate',
				'create',
				'change',
				'set',
				'put',
				'do',
				'go',
				'resolve',
				'start',
				'recover',
				'initiate',
				'negotiate',
				'define',
				'stop',
				'begin',
				'end',
				'manage',
				'administer',
				'modify',
				'register',
				'log',
				'add',
				'list',
				'query',
			]

		if (datastore['VERB_DELETE'])
			verbs << 'delete'
		end

		nouns = [
				'password',
				'task',
				'tasks',
				'pass',
				'administration',
				'account',
				'accounts',
				'admin',
				'login',
				'logins',
				'token',
				'tokens',
				'credential',
				'credentials',
				'key',
				'keys',
				'guid',
				'message',
				'messages',
				'user',
				'users',
				'username',
				'usernames',
				'load',
				'list',
				'name',
				'names',
				'file',
				'files',
				'path',
				'paths',
				'directory',
				'directories',
				'configuration',
				'configurations',
				'config',
				'configs',
				'setting',
				'settings',
				'registry',
				'on',
				'off',
			]

		target_port = datastore['RPORT']
		vhost = datastore['VHOST'] || wmap_target_host || ip

		# regular expressions for common rejection messages
		reject_regexen = []
		reject_regexen << Regexp.new("method \\S+ is not valid", true)
		reject_regexen << Regexp.new("Method \\S+ not implemented", true)
		reject_regexen << Regexp.new("unable to resolve WSDL method name", true)

		begin
			verbs.each do |v|
				nouns.each do |n|
					data_parts = []
					data_parts << "<?xml version=\"1.0\" encoding=\"utf-8\"?>"
					data_parts << "<soap:Envelope xmlns:xsi=\"#{datastore['XMLINSTANCE']}\" xmlns:xsd=\"#{datastore['XMLSCHEMA']}\" xmlns:soap=\"#{datastore['XMLSOAP']}\">"
					data_parts << "<soap:Body>"
					data_parts << "<#{v}#{n} xmlns=\"#{datastore['XMLNAMESPACE']}\">"
					data_parts << "</#{v}#{n}>"
					data_parts << "</soap:Body>"
					data_parts << "</soap:Envelope>"
					data_parts << nil
					data_parts << nil
					data = data_parts.join("\r\n")

					uri = normalize_uri(datastore['PATH'])
					vprint_status("Sending request #{uri}/#{v}#{n} to #{wmap_target_host}:#{datastore['RPORT']}")

					res = send_request_raw({
						'uri'     => uri + '/' + v + n,
						'method'  => 'POST',
						'vhost'   => vhost,
						'data'	  => data,
						'headers' =>
							{
								'Content-Length' => data.length,
								'SOAPAction'	 => '"' + datastore['XMLNAMESPACE'] + v + n + '"',
								'Expect'	 => '100-continue',
								'Content-Type'	 => datastore['CONTENTTYPE'],
							}
					}, 15)

					if (res && !(res.body.empty?))
						if ((not reject_regexen.select { |r| res.body =~ r }.empty?))
							print_status("Server #{wmap_target_host}:#{datastore['RPORT']} rejected SOAPAction: #{v}#{n} with HTTP: #{res.code} #{res.message}.")
						elsif (res.message =~ /Cannot process the message because the content type/)
							print_status("Server #{wmap_target_host}:#{datastore['RPORT']} rejected CONTENTTYPE: HTTP: #{res.code} #{res.message}.")
							res.message =~ /was not the expected type\s\'([^']+)'/
							print_status("Set CONTENTTYPE to \"#{$1}\"")
							return false
						elsif (res.code == 404)
							print_status("Server #{wmap_target_host}:#{datastore['RPORT']} returned HTTP 404 for #{datastore['PATH']}.  Use a different one.")
							return false
						else
							print_status("Server #{wmap_target_host}:#{datastore['RPORT']} responded to SOAPAction: #{v}#{n} with HTTP: #{res.code} #{res.message}.")
							## Add Report
							report_note(
								:host  => ip,
								:proto => 'tcp',
								:sname => (ssl ? 'https' : 'http'),
								:port  => rport,
								:type  => "SOAPAction: #{v}#{n}",
								:data  => "SOAPAction: #{v}#{n} with HTTP: #{res.code} #{res.message}."
							)
							if datastore['DISPLAYHTML']
								print_status("The HTML content follows:")
								print_status(res.body + "\r\n")
							end
						end
					end
					select(nil, nil, nil, datastore['SLEEP']) if (datastore['SLEEP'] > 0)
				end
			end
		rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout, ::Timeout::Error, ::Errno::EPIPE => e
			vprint_error(e.message)
		end
	end
end
