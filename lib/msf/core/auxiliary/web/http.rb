##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/framework/
##

require 'uri'

module Msf
class Auxiliary::Web::HTTP

	class Request
		attr_accessor :url
		attr_reader	 :opts
		attr_reader	 :callbacks

		def initialize( url, opts = {}, &callback )
			@url  = url.to_s.dup
			@opts = opts.dup

			@opts[:method] ||= :get

			@callbacks = [callback].compact
		end

		def method
			opts[:method]
		end

		def handle_response( response )
			callbacks.each { |c| c.call response }
		end
	end

	class Response < Rex::Proto::Http::Response

		def self.from_rex_response( response )
			return empty if !response

			r = new( response.code, response.message, response.proto )
			response.instance_variables.each do |iv|
				r.instance_variable_set( iv, response.instance_variable_get( iv ) )
			end
			r
		end

		def self.empty
			new( 0, '' )
		end

		def self.timed_out
			r = empty
			r.timed_out
			r
		end

		def timed_out?
			!!@timed_out
		end

		def timed_out
			@timed_out = true
		end
	end

	attr_reader :opts
	attr_reader :headers
	attr_reader :framework

	attr_accessor :redirect_limit

	def initialize( opts = {} )
		@opts = opts.dup

		@framework = opts[:framework]

		@headers = {
			'Accept' => '*/*',
			'Cookie' => opts[:cookie_string]
		}.merge( opts[:headers] || {} )

		@headers.delete( 'Cookie' ) if !@headers['Cookie']

		@request_opts = {}
		if opts[:auth].is_a? Hash
			@request_opts['basic_auth'] = [ opts[:auth][:user].to_s + ':' +
								opts[:auth][:password] ]. pack( 'm*' ).gsub( /\s+/, '' )
		end

		self.redirect_limit = opts[:redirect_limit] || 20

		@queue = Queue.new

		@after_run_blocks = []
	end

	def after_run( &block )
		@after_run_blocks << block
	end

	def connect
		c = Rex::Proto::Http::Client.new(
			opts[:target].host,
			opts[:target].port,
			{},
			opts[:target].ssl,
			'SSLv23'
		)

		c.set_config({
			'vhost' => opts[:target].vhost,
			'agent' => opts[:user_agent] || 'Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0)',
		})
		c
	end

	def run
		return if @queue.empty?

		tl = []
		loop do
			# Spawn threads for each host
			while tl.size <= (opts[:max_threads] || 5) && !@queue.empty? && (req = @queue.pop)
				tl << framework.threads.spawn( "#{self.class.name} - #{req})", false, req ) do |request|
					request.handle_response request( request.url, request.opts )
				end
			end

			break if tl.empty?
			tl.reject! { |t| !t.alive? }

			select( nil, nil, nil, 0.05 )
		end

		call_after_run_blocks
	end

	def request( url, opts = {} )
		rlimit = self.redirect_limit

		while rlimit >= 0
			rlimit -= 1
			res = _request( url, opts )
			return res if !opts[:follow_redirect] || !url = res.headers['location']
		end
		nil
	end

	def request_async( url, opts = {}, &callback )
		queue Request.new( url, opts, &callback )
	end

	def get_async( url, opts = {}, &callback )
		request_async( url, opts.merge( :method => :get ), &callback )
	end

	def post_async( url, opts = {}, &callback )
		request_async( url, opts.merge( :method => :post ), &callback )
	end

	def get( url, opts = {} )
		request( url, opts.merge( :method => :get ) )
	end

	def post( url, opts = {} )
		request( url, opts.merge( :method => :post ) )
	end

	def if_not_custom_404( path, body, &callback )
		custom_404?( path, body ) { |b| callback.call if !b }
	end

	def custom_404?( path, body, &callback )
		return if !path || !body

		precision = 2

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

		synchronize do
			@@_404 ||= {}
			@@_404[path] ||= []

			@@_404_gathered ||= Set.new

			gathered = 0
			if !@@_404_gathered.include?( path.hash )
				generators.each.with_index do |generator, i|
					@@_404[path][i] ||= {}

					precision.times {
						get_async( generator.call, :follow_redirect => true ) do |res|
							gathered += 1

							if gathered == generators.size * precision
								@@_404_gathered << path.hash
								callback.call is_404?( path, body )
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
						end
					}
				end
			else
				callback.call is_404?( path, body )
			end
		end

		nil
	end

	private

	def call_after_run_blocks
		while block = @after_run_blocks.pop
			block.call
		end
	end

	def synchronize( &block )
		(@mutex ||= Mutex.new).synchronize( &block )
	end

	def is_404?( path, body )
		@@_404[path].each { |_404| return true if Rex::Text.refine( _404['body'], body ) == _404['rdiff'] }
		false
	end

	def queue( request )
		@queue << request
	end

	def _request( url, opts = {} )
		body		= opts[:body]
		timeout = opts[:timeout] || 10
		method	= opts[:method].to_s.upcase || 'GET'
		url		 = url.is_a?( URI ) ? url : URI( url.to_s )

		param_opts = {}

		if !(vars_get = Auxiliary::Web::Form.query_to_params( url.query )).empty?
			param_opts['vars_get'] = vars_get
		end

		if method == 'GET'
			param_opts['vars_get'] ||= {}
			param_opts['vars_get'].merge!( opts[:params] ) if opts[:params].is_a?( Hash )
		elsif method == 'POST'
			param_opts['vars_post'] = opts[:params] || {}
		end

		opts = @request_opts.merge( param_opts ).merge(
			'uri'		 => url.path || '/',
			'method'	=> method,
			'headers' => headers.merge( opts[:headers] || {} )
		)

		opts['data'] = body if body

		c = connect
		Response.from_rex_response c.send_recv( c.request_cgi( opts ), timeout )
	rescue ::Timeout::Error
		Response.timed_out
	rescue ::Errno::EPIPE, Rex::ConnectionTimeout
		Response.empty
	end

end
end
