##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/framework/
##

require 'net/https'
require 'net/http'
require 'uri'

module Msf

module Auxiliary::Web
class Form

	attr_accessor :method
	attr_accessor :action
	attr_accessor :inputs
	attr_accessor :altered
	attr_accessor :model

	def initialize( opts = {} )
		self.action = opts[:action]
		self.action.chop! if self.action.end_with?( '?' )

		self.method = opts[:method] || :get
		self.inputs = (opts[:inputs] || []).dup
	end

	def altered=( input_name )
		@altered = input_name.to_s.dup
	end

	def method=( m )
		@method = m.to_s.downcase.to_sym
	end

	def inputs=( i )
		# nil it out so that it'll be updated next time it's requested
		@params = nil
		@inputs = i
	end

	def params
		@params ||= inputs.inject( {} ) { |h, i| h[i[:name]] = i[:value]; h }
	end

	def altered_value
		params[altered].to_s
	end

	def to_query( i = self.params )
		i.map do |k, v|
			Rex::Text.uri_encode( k.to_s ) + '=' + Rex::Text.uri_encode( v.to_s )
		end.join( '&' )
	end

	def query_to_params( query )
		query = query.to_s
		return {} if query.empty?

		query.split( '&' ).inject( {} ) do |h, pair|
			k, v = pair.to_s.split( '=', 2 )
			k[Rex::Text.uri_decode( k.to_s )] = Rex::Text.uri_decode( v.to_s )
			h
		end
	end

	def request( headers = {} )
		case method
			when :get
				h = query_to_params( URI( action ).query ).merge( params )
				::Net::HTTP::Get.new( "#{action}?#{to_query( h )}", headers )

			when :post
				req = ::Net::HTTP::Post.new( action, headers )
				req.form_data = params
				req
		end

	end

	def submit( connection, headers = {} )
		connection.request request( headers )
	end

	def empty?
		params.empty?
	end

	def []( field )
		params[field.to_s]
	end

	def []=( field, value )
		update( field, value )
		[field]
	end

	def update( field, value, type = nil )
		@params = nil
		inputs.each do |i|
			if i[:name] == field.to_s
				i[:value] = value.to_s
				i[:type] = type.to_s if type
				return self
			end
		end

		@inputs << { :name => field.to_s, :value => value.to_s, :type => type || 'text' }
		self
	end

	def field_type_for( name )
		inputs.select{ |i| i[:name] == name.to_s }[:type]
	end

	def permutations_for( seed )
		return [] if empty?

		params.keys.map do |k|
			form = self.dup
			form.altered = k.dup
			form[k] = seed
			form
		end
	end

	def to_hash
		{ :action => action.dup, :method => method,
		  :inputs => inputs.dup, :altered => altered ? altered.dup : nil }
	end

	def dup
		Marshal.load( Marshal.dump( self ) )
	end

	def self.from_model( form )
		inputs = form.params.map do |name, value, extra|
			{ :name => name, :value => value, :type => extra[:type] }
		end
		e = new( :action => "#{form.path}?#{form.query}", :method => form.method, :inputs => inputs )
		e.model = form
		e
	end

end
end
end
