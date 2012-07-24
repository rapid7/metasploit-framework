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

	def initialize( info = {} )
		super
	end

	#
	# Called directly before 'run'
	#
	def setup( parent, target )
		@parent = parent
		@target = target
	end

	# Should be overridden to return the exploit to use for this
	# vulnerability type as an Array of Strings.
	def self.exploits
	end

	# Should be overridden to return the payloads used for this
	# vulnerability type as an Array of Strings.
	def payloads
	end

	def token
		"xssmsfpro"
	end

	#
	# Should be overridden to return a Regexp which will be used against the
	# response body in order to identify the vulnerability.
	#
	# You can go one deeper and override #find_proof for more complex processing.
	#
	def signature
	end

	#
	# Default #run, will audit all methods/forms and try to use #signature
	# to identify vulnerabilities.
	#
	def run
		target.auditable.each do |element|
			audit_element( element )
		end
	end

	#
	# Uses the Regexp in #signature against the response body in order to
	# identify vulnerabilities and return a String that proves it.
	#
	# Override it if you need more complex processing, but remember to return
	# the proof as a String.
	#
	# response - Net::HTTPResponse
	#
	def find_proof( response )
		return if !signature.kind_of? ::Regexp

		m = response.body.match( signature )
		return if !m || m.size < 1

		1.upto( m.length - 1 ) { |i| return m[i].gsub( /[\r\n]/, ' ' ) if m[i] }
		nil
	end

	def audit_element( element )
		element.params.values.each do |default_value|
			(seeds_for( default_value ) | ["unknown#{token}"] ).each do |seed|
				element.permutations_for( seed ).each do |p|
					response = submit_element( p )

					if proof = find_proof( response )
						process_vulnerability( p, proof )
					end
				end
			end
		end
	end

	def submit_element( element )
		parent.increment_request_counter

		retries = 0
		begin
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

			if resp = element.submit( http, headers )
				str = "    #{resp.code} - #{element.method.to_s.upcase} #{element.action} #{element.params}"
				case resp.code.to_i
					when 200,404,301,302,303
						# print_status str
					when 500,503,401,403
						print_good str
					else
						print_error str
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

	def http
		proxy_host = proxy_port = proxy_user = proxy_pass = nil

		http = ::Net::HTTP.new( target.host, target.port, proxy_host,
		                        proxy_port, proxy_user, proxy_pass )
		if target.ssl?
			http.use_ssl     = true
			http.verify_mode = OpenSSL::SSL::VERIFY_NONE
		end

		http
	end

	def calculate_confidence( vuln )
		100
	end

	def process_vulnerability( element, proof )
		mode  = details[:category].to_sym
		vhash = [target.to_url, mode, element.altered].map{ |x| x.to_s }.join( '|' )

		parent.vulns[mode] ||= {}
		return parent.vulns[mode][vhash] if parent.vulns[mode][vhash]

		parent.vulns[mode][vhash] = {
			:target      => target,
			:method      => element.method.to_s.upcase,
			:params      => element.params.to_a,
			:mode        => mode,
			:pname       => element.altered,
			:proof       => proof,
			:form        => element.model,
			:risk	     => details[:risk],
			:name	     => details[:name],
			:blame	     => details[:blame],
			:category    => details[:category],
			:description => details[:description]
		}

		confidence = calculate_confidence( parent.vulns[mode][vhash] )

		parent.vulns[mode][vhash].merge!( confidence: confidence )

		payload = nil
		if payloads
			payload = payloads.select{ |p| element.altered_value.include?( p ) }.first
		end

		uri = URI( element.action )
		info = {
			:web_site    => element.model.web_site,
			:path	     => uri.path,
			:query	     => uri.query,
			:method      => element.method.to_s.upcase,
			:params      => element.params.to_a,
			:pname	     => element.altered,
			:proof	     => proof,
			:risk	     => details[:risk],
			:name	     => details[:name],
			:blame	     => details[:blame],
			:category    => details[:category],
			:description => details[:description],
			:confidence  => confidence,
			:payload     => payload,
			:owner       => self
		}

		report_web_vuln( info )

		print_good "	VULNERABLE(#{mode.to_s.upcase}) URL(#{target.to_url}) PARAMETER(#{element.altered}) VALUES(#{element.params})"
		print_good "		 PROOF( #{proof} )"

		return
	end

end
end
