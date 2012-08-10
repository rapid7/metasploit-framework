# -*- coding: binary -*-

module Msf

###
#
# This module provides methods for brute forcing authentication
#
###

module Auxiliary::Web
	module Analysis
	end

	require 'msf/core/auxiliary/web/http'
	require 'msf/core/auxiliary/web/fuzzable'
	require 'msf/core/auxiliary/web/form'
	require 'msf/core/auxiliary/web/path'
	require 'msf/core/auxiliary/web/target'

	include Auxiliary::Report

	attr_reader :target
	attr_reader :parent
	attr_reader :page

	def initialize( info = {} )
		super
	end

	#
	# Called directly before 'run'
	#
	def setup( parent, target, page = nil )
		@parent = parent
		@target = target
		@page   = page
	end

	# Should be overridden to return the exploits to use for this
	# vulnerability typeas an Array of Strings.
	def self.exploits
	end

	# Must return a configuration Hash for the given exploit and vulnerability.
	def self.configure_exploit( exploit, vuln )
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
	# Default #run, will audit all elements using taint analysis and log
	# results based on #find_proof return values.
	#
	def run
		auditable.each { |element| element.taint_analysis }
	end

	# Returns an Array of elements prepared to be audited.
	def auditable
		target.auditable.map do |element|
			element.fuzzer = self
			element
		end
	end

	def resource_exist?( path )
		res = http.get( path )
		res.code.to_i == 200 && !custom_404?( path, res.body )
	end
	alias :file_exist? :resource_exist?

	def directory_exist?( path )
		dir = path.dup
		dir << '/' if !dir.end_with?( '/' )
		resource_exist?( dir )
	end

	def log_resource_if_exists( path )
		log_resource( :location => path ) if resource_exist?( path )
	end
	alias :log_file_if_exists :log_resource_if_exists

	def log_directory_if_exists( path )
		dir = path.dup
		dir << '/' if !dir.end_with?( '/' )
		log_resource_if_exists( dir )
	end

	def match_and_log_fingerprint( fingerprint )
		page.body.to_s.match( fingerprint ) && log_fingerprint( :fingerprint => fingerprint )
	end

	#
	# Serves as a default detection method for when performing taint analysis.
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

	def increment_request_counter
		parent.increment_request_counter
	end

	def custom_404?( path, body )
		return if !path || !body

		precision = 2

		@@_404 ||= {}
		@@_404[path] ||= []

		trv_back = File.dirname( path )
		trv_back << '/' if trv_back[-1,1] != '/'

		# 404 probes
		generators = [
			# get a random path with an extension
			proc{ path + Rex::Text.rand_text_alpha( 10 ) + '.' + Rex::Text.rand_text_alpha( 10 )[0..precision] },

			# get a random path without an extension
			proc{ path + Rex::Text.rand_text_alpha( 10 ) },

			# move up a dir and get a random file
			proc{ trv_back + Rex::Text.rand_text_alpha( 10 ) },

			# move up a dir and get a random file with an extension
			proc{ trv_back + Rex::Text.rand_text_alpha( 10 ) + '.' + Rex::Text.rand_text_alpha( 10 )[0..precision] },

			# get a random directory
			proc{ path + Rex::Text.rand_text_alpha( 10 ) + '/' }
		]

		@@_404_gathered ||= Set.new

		gathered = 0
		if !@@_404_gathered.include?( path.hash )
			generators.each.with_index do |generator, i|
				@@_404[path][i] ||= {}

				precision.times {
					res = http.get( generator.call, :follow_redirect => true )
					gathered += 1

					if gathered == generators.size * precision
						@@_404_gathered << path.hash
						return is_404?( path, body )
					else
						@@_404[path][i]['rdiff_now'] ||= false

						if !@@_404[path][i]['body']
							@@_404[path][i]['body'] = res.body
						else
							@@_404[path][i]['rdiff_now'] = true
						end

						if @@_404[path][i]['rdiff_now'] && !@@_404[path][i]['rdiff']
							@@_404[path][i]['rdiff'] = Rex::Text.refine( @@_404[path][i]['body'], res.body )
						end
					end
				}
			end
		else
			is_404?( path, body )
		end
	end

	def http
		# only one connection per thread pl0x, kthxb
		return @http if @http

		opts = {
			:target  => target,
			:headers => {}
		}

		if datastore['BasicAuthUser']
			opts[:auth] = {
				:user => datastore['BasicAuthUser'],
				:password => datastore['BasicAuthPass']
			}
		end

		datastore['HttpAdditionalHeaders'].to_s.split( "\x01" ).each do |hdr|
			next if !( hdr && hdr.strip.size > 0 )

			k, v = hdr.split( ':', 2 )
			next if !v

			opts[:headers][k.strip] = v.strip
		end

		@http = Auxiliary::Web::HTTP.new( opts )
	end

	def is_404?( path, body )
		@@_404[path].each { |_404| return true if Rex::Text.refine( _404['body'], body ) == _404['rdiff'] }
		false
	end

	def calculate_confidence( vuln )
		100
	end

	def log_fingerprint( opts = {} )
		mode  = details[:category].to_sym
		vhash = [target.to_url, mode, opts[:location]].map { |x| x.to_s }.join( '|' ).hash

		@@vulns ||= Set.new
		return if @@vulns.include?( vhash )
		@@vulns << vhash

		location = opts[:location] ? URI( opts[:location].to_s ) : page.url
		info = {
			:web_site    => target.site,
			:path	     => location.path,
			:query	     => location.query,
			:method      => 'GET',
			:params      => [],
			:pname	     => 'path',
			:proof	     => opts[:fingerprint],
			:risk	     => details[:risk],
			:name	     => details[:name],
			:blame	     => details[:blame],
			:category    => details[:category],
			:description => details[:description],
			:confidence  => details[:category] || opts[:confidence] || 100,
			:owner       => self
		}

		report_web_vuln( info )

		print_good "	VULNERABLE(#{mode.to_s.upcase}) URL(#{target.to_url})"
		print_good "		 PROOF(#{opts[:fingerprint]})"
	end

	def log_resource( opts = {} )
		mode  = details[:category].to_sym
		vhash = [target.to_url, mode, opts[:location]].map { |x| x.to_s }.join( '|' ).hash

		@@vulns ||= Set.new
		return if @@vulns.include?( vhash )
		@@vulns << vhash

		location = URI( opts[:location].to_s )
		info = {
			:web_site    => target.site,
			:path	     => location.path,
			:query	     => location.query,
			:method      => 'GET',
			:params      => [],
			:pname	     => 'path',
			:proof	     => opts[:location],
			:risk	     => details[:risk],
			:name	     => details[:name],
			:blame	     => details[:blame],
			:category    => details[:category],
			:description => details[:description],
			:confidence  => details[:category] || opts[:confidence] || 100,
			#:payload     => nil,
			:owner       => self
		}

		report_web_vuln( info )

		print_good "	VULNERABLE(#{mode.to_s.upcase}) URL(#{target.to_url})"
		print_good "		 PROOF(#{opts[:location]})"
	end

	def process_vulnerability( element, proof, opts = {} )
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

		if !(payload = opts[:payload])
			if payloads
				payload = payloads.select{ |p| element.altered_value.include?( p ) }.first
			end
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
		print_good "		 PROOF(#{proof})"

		return
	end

end
end
