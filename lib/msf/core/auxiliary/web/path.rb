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
class Path

	attr_accessor :method
	attr_accessor :input
	attr_reader   :action

	attr_accessor :model

	def initialize( opts = {} )
		self.action = opts[:action]
		self.action.chop! if self.action.end_with?( '?' )

		self.method = :get
		self.input = (opts[:inputs] || opts[:input]).to_s.dup
	end

	def input=( value )
		@inputs = value.to_s.dup
	end
	alias :param :input

	def inputs
		{ :name => params.keys.first, :value => params.values.first, :type => 'path' }
	end

	def params
		{ input => input }
	end

	def altered
		'path'
	end

	def altered_value
		input.to_s
	end

	def request( headers = {} )
		uri = URI( action )
		path = uri.path
		path << '/' if !path.end_with?( '/' )

		::Net::HTTP::Get.new( "#{path}/#{param}?#{uri.query}", headers )
	end

	def submit( connection, headers = {} )
		connection.request request( headers )
	end

	def empty?
		param.empty?
	end

	def permutations_for( seed )
		return [] if empty?

		path = self.dup
		path.input = seed
		path
	end

	def to_hash
		{ :action => action.dup, :input => input.dup }
	end

	def dup
		Marshal.load( Marshal.dump( self ) )
	end

	def self.from_model( form )
		e = new( :action => "#{form.path}?#{form.query}", :input => inputs[0][1] )
		e.model = form
		e
	end

end
end
end
