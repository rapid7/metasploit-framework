# -*- coding: binary -*-

require 'net/https'
require 'net/http'
require 'uri'

module Msf

###
#
# This module provides methods for brute forcing authentication
#
###

module Auxiliary::WebAudit
	include Msf::Auxiliary::Report

	attr_reader :target
	attr_reader :parent

	def initialize(info = {})
		super
	end

	#
	# Called directly before 'run'
	#
	def setup( parent, target )
		@parent = parent
		@target = target
	end

	def token
		"xssmsfpro"
	end

	def signature
	end

	def run
		return if !signature.kind_of? ::Regexp

		target.auditable[:methods].each do |method|
			audit_form_methods( method, target.auditable[:params] )
		end
	end

	def audit_form_methods( method, params )
		return if !signature.kind_of? ::Regexp

		generate_parameters( method, params ).each do |form, param, pname|
			response = submit_request( method, param )

			if proof = find_proof( response )
				process_vulnerability( method, form, param, pname, proof )
			end
		end
	end

	def find_proof( response )
		m = response.body.match( signature )
		return if !m || m.size < 1

		1.upto( m.length - 1 ) { |i| return m[i].gsub( /[\r\n]/, ' ' ) if m[i] }
		nil
	end

	def submit_request( method, params )
		parent.increment_request_counter

		retries = 0
		begin
			conn = http

			# Configure the headers
			headers = {
				'User-Agent' => parent.datastore['UserAgent'] || 'Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0)',
				'Accept'	 => '*/*',
				'Host'	     => target.vhost
			}

			if parent.datastore['HTTPCookie']
				headers['Cookie'] = parent.datastore['HTTPCookie']
			end

			if parent.datastore['BasicAuthUser']
				auth = [ parent.datastore['BasicAuthUser'].to_s + ':' +
					         parent.datastore['BasicAuthPass'] ].pack( 'm*' ).gsub( /\s+/, '' )

				headers['Authorization'] = "Basic #{auth}\r\n"
			end

			parent.datastore['HttpAdditionalHeaders'].to_s.split( "\x01" ).each do |hdr|
				next if !( hdr && hdr.strip.size > 0 )

				k, v = hdr.split( ':', 2 )
				next if !v

				headers[k.strip] = v.strip
			end

			req  = nil
			buff = ''
			case method.upcase

				when 'GET'
					buff = params.map do |param|
						Rex::Text.uri_encode( param[0].to_s ) + '=' +
							Rex::Text.uri_encode( param[1].to_s )
					end.join( '&' )

					req = ::Net::HTTP::Get.new( "#{target.path}?#{buff}", headers )

				when 'POST'
					req = ::Net::HTTP::Post.new( target.path, headers)
					req['Content-Type'] = 'application/x-www-form-urlencoded'

					buff = params.map do |param|
						Rex::Text.uri_encode( param[0].to_s) + '=' +
							Rex::Text.uri_encode( param[1].to_s )
					end.join( '&' )

					req.body = buff

				when 'PATH'
					buff = params[0][1]

					uri = target.path.to_s.dup
					uri << "/" if uri[-1,1] != '/'
					uri << buff

					print_status "URI: #{uri}"
					req = ::Net::HTTP::Get.new( uri, headers )

				else
					print_error "Unsupported method #{method}"
					return nil
			end

			if resp = conn.request( req )
				case resp.code.to_i
					when 200,404,301,302,303
						# print_status("	#{resp.code} - #{method.upcase} #{t[:path]} #{buff}")
					when 500,503,401,403
						print_good  "    #{resp.code} - #{method.upcase} #{target.path} #{buff}"
					else
						print_error "    #{resp.code} - #{method.upcase} #{target.path} #{buff}"
				end
			end

			resp
		# Some CGI servers just spew errors without headers, we need to process these anyways
		rescue ::Net::HTTPBadResponse, ::Net::HTTPHeaderSyntaxError => e
			print_status "Error processing response for #{target.to_url} #{e.class} #{e} "
			return
		rescue ::Exception => e
			retries += 1
			retry if retries < 3

			print_error "Maximum retry count for #{target.to_url} reached (#{e})"
			return
		end
	end

	#
	# This method generates parameters for form testing. The
	# returned array is in the form of:
	# [ [regex-signature,
	#   [ [param1, param_value_1],
	#	  [param2, param_value_2] ..
	#   ], ... ],
	#   [regex-signature, ...
	# ]
	#
	def generate_parameters( method, params )
		return generate_parameters_path_info( params ) if method == 'PATH'

		values = []
		fcnt = 0

		# Walk through all discovered form instances for this method
		target.forms.each do |form|
			fcnt += 1
			break if fcnt > 5

			# Skip methods that don't apply to this pass
			next if form.method.upcase != method

			# Initialize the list of options from this form
			options = form.params.map{|x| x[0] } + ["unknown#{token}"]
			options.delete( nil )
			options.delete( '' )

			# Create the defaults for this specific form
			defaults = {}
			form.params.each do |opt|
				next if not opt[0]
				defaults[opt[0]] = opt[1]
			end

			# Create a baseline to clone for value permutation
			baseline = []
			options.each { |oname| baseline << [ oname, defaults[oname].to_s ] }

			# Starting with this specific form and option set, walk through all known options for each item
			options.each_index do |idx|
				ovalues = [ baseline[idx][1] ]

				if params[options[idx]] && params[options[idx]][:values] &&
					params[options[idx]][:values].keys.length > 0
					ovalues = params[options[idx]][:values].keys
				end

				# This replaces the previous step, limiting the test to smaller range of values
				ovalues = [ defaults[baseline[idx][0]].to_s ]
				ovalues.delete( nil )
				ovalues.uniq!

				ovalues.each do |ovalue|
					seeds_for( ovalue ).each do |input|
						input = input
						tparams = []

						baseline.each_index do |bdx|
							tparams << [ baseline[bdx][0], (idx == bdx) ? input : baseline[bdx][1] ]
						end

						# Insert a fake value for this signature in order to catch false positives
						# XXX: Need some way to skip related values when this fires
						# values << [sig, baseline, -1]

						# Insert the real value
						values << [ form, tparams, baseline[idx][0] ]
					end

					# De-duplicate values (especially the false positive tests)
					values.uniq!
				end
			end
		end

		values
	end

	#
	# This method generates malicious path_info values for form testing. The
	# returned array is in the form of: [ [regex-signature, "param-string"], ... ]
	#
	def generate_parameters_path_info( params )
		values  = []
		sigs	= []

		options = params[:path_info][:values].keys + %w(Unknown)

		options.each do |input|
			seeds_for( input ).each do |input|
				sig, input = input
				values << [ target.forms.first, sig, [ ['PATH', input] ], :path ]
			end
		end

		values.uniq
	end

	def http
		proxy_host = proxy_port = proxy_user = proxy_pass = nil

		http = ::Net::HTTP.new( target.host, target.port, proxy_host,
		                        proxy_port, proxy_user, proxy_pass )
		if target.ssl
			http.use_ssl     = true
			http.verify_mode = OpenSSL::SSL::VERIFY_NONE
		end

		http
	end

	def calculate_confidence( vuln )
		100
	end

	def process_vulnerability( method, form, param, pname, proof )
		mode  = details[:category].to_sym
		vhash = [target.to_url, mode, pname].map{|x| x.to_s}.join("|")

		parent.vulns[mode] ||= {}
		return parent.vulns[mode][vhash] if parent.vulns[mode][vhash]

		parent.vulns[mode][vhash] = {
			:target      => target,
			:method      => method,
			:params      => param,
			:mode        => mode,
			:pname       => pname,
			:proof       => proof,
			:form        => form,
			:risk	     => details[:risk],
			:name	     => details[:name],
			:blame	     => details[:blame],
			:category    => details[:category],
			:description => details[:description]
		}

		confidence = calculate_confidence( parent.vulns[mode][vhash] )

		parent.vulns[mode][vhash].merge!( confidence: confidence )

		info = {
			:web_site    => form.web_site,
			:path	     => form.path,
			:query	     => form.query,
			:method      => method,
			:params      => param,
			:pname	     => pname,
			:proof	     => proof,
			:risk	     => details[:risk],
			:name	     => details[:name],
			:blame	     => details[:blame],
			:category    => details[:category],
			:description => details[:description],
			:confidence  => confidence
		}

		report_web_vuln( info )

		print_good "	VULNERABLE(#{mode.to_s.upcase}) URL(#{target.to_url}) PARAMETER(#{pname}) VALUES(#{param.inspect})"
		print_good "		 PROOF( #{proof} )"

		return
	end

end
end
