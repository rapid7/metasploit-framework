# -*- coding: binary -*-

require 'msf/core/auxiliary/web/fuzzable'
require 'msf/core/auxiliary/web/form'
require 'msf/core/auxiliary/web/path'
require 'msf/core/auxiliary/web/target'

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
	# element - the submitted element
	#
	def find_proof( response, element )
		return if !signature.kind_of? ::Regexp

		m = response.body.match( signature )
		return if !m || m.size < 1

		1.upto( m.length - 1 ) { |i| return m[i].gsub( /[\r\n]/, ' ' ) if m[i] }
		nil
	end

	def audit_element( element )
		element.fuzz( self ) do |response, permutation|
			if response && (proof = find_proof( response, permutation ))
				process_vulnerability( permutation, proof )
			end
		end
	end

	def increment_request_counter
		parent.increment_request_counter
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
