# -*- coding: binary -*-
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# https://metasploit.com/framework/

require 'net/https'
require 'net/http'
require 'uri'

module Msf

#
# Represents a webpage form.
#
module Auxiliary::Web

class Form < Fuzzable

  # Method type Symbol: :get, :post
  attr_accessor :method

  # URL String to which to submit the params
  attr_accessor :action

  # Inputs Array in the form of:
  #
  #   [{ :name => 'name', :value => 'John', :type => 'text' }]
  #
  attr_accessor :inputs

  # Name of the altered input as a String
  attr_accessor :altered

  # Mdm::WebForm model if available
  attr_accessor :model

  #
  # opts - Options Hash (default: {})
  #        :action - Action URL of the form
  #        :method - Form method (:get, :post)
  #        :inputs - Form inputs [{ :name => 'name', :value => 'John', :type => 'text' }]
  #
  def initialize( opts = {} )
    self.action = opts[:action]
    self.action.chop! if self.action.end_with?( '?' )

    self.method = opts[:method] || :get
    self.inputs = (opts[:inputs] || []).dup
  end

  #
  # Set the name of the altered field (will be used as the vuln param when logging)
  #
  # input_name    - String
  #
  def altered=( input_name )
    @altered = input_name.to_s.dup
  end

  #
  # Set the form method.
  #
  # input_name    - String, Symbol
  #
  def method=( m )
    @method = m.to_s.downcase.to_sym
  end

  #
  # i -   Array of form inputs
  #
  # Examples
  #
  #   [{ :name => 'name', :value => 'John', :type => 'text' }]
  #
  def inputs=( i )
    # nil it out so that it'll be updated next time it's requested
    @params = nil
    @inputs = i
  end

  #
  # Hash of params to be submited (derived by #inputs)
  #
  # Examples
  #
  #   { 'name' => 'John' }
  #
  def params
    @params ||= inputs.reject{ |i| i[:name].to_s.empty? }.
      inject( {} ) { |h, i| h[i[:name]] = i[:value]; h }
  end

  #
  # Value of the {#altered} input (i.e. the injected value).
  #
  def altered_value
    params[altered]
  end

  def altered_value=( value )
    params[altered] = value.to_s.dup
  end

  #
  # Converts a Hash of params to a query String
  #
  # i -   Hash of params (default: #params)
  #
  def to_query( i = self.params )
    i.map do |k, v|
      Rex::Text.uri_encode( k.to_s ) + '=' + Rex::Text.uri_encode( v.to_s )
    end.join( '&' )
  end

  #
  # Converts a query String to a Hash of params
  #
  # query -   String
  #
  def self.query_to_params( query )
    query = query.to_s
    return {} if query.empty?

    query.split( '&' ).inject( {} ) do |h, pair|
      k, v = pair.to_s.split( '=', 2 )
      h[Rex::Text.uri_decode( k.to_s )] = Rex::Text.uri_decode( v.to_s )
      h
    end
  end

  def query_to_params( query )
    self.class.query_to_params( query)
  end

  def request( opts = {} )
    p = case method
      when :get
        query_to_params( URI( action ).query ).merge( params )

      when :post
        params
    end

    [ action, opts.merge( :method => method, :params => p ) ]
  end

  # Bool  -   true if params are empty, false otherwise.
  def empty?
    params.empty?
  end

  #
  # Param reader shortcut -- returns the value of a param by name, as a String.
  #
  # field -   Param name as a String
  #
  def []( field )
    params[field.to_s]
  end

  #
  # Param writer shortcut -- sets the value of a param by name, as a String.
  #
  # field -   Param name as a String
  # value -   Param value as a String
  #
  def []=( field, value )
    update( field, value )
    [field]
  end

  #
  # Update the form inputs.
  #
  # field -   Field name as a Sting (updated if already exists, created otherwise).
  # value -   Field Value as a String.
  # type -    Field type ('text' if no type has been provided).
  #
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

  #
  # Get a field type, by name, as a String.
  #
  # field -   Field name as a Sting
  #
  def field_type_for( name )
    inputs.select{ |i| i[:name] == name.to_s }[:type]
  end

  #
  # Get an Array with permutations of the form for the given seed.
  #
  # seed  -   String to inject
  #
  def permutations
    return [] if empty?

    params.map do |name, value|
      fuzzer.seeds_for( value || '' ).map { |seed| permutation_for( name, seed ) }
    end.flatten.uniq
  end

  def permutation_for( field_name, field_value )
    form = self.dup
    form.altered = field_name.dup
    form[field_name]   = field_value.dup
    form
  end

  def to_hash
    { :action => action.dup, :method => method,
      :inputs => inputs.dup, :altered => altered ? altered.dup : nil }
  end

  def self.from_model( form )
    inputs = form.params.map do |name, value, extra|
      extra = extra.first if extra.is_a? Array
      extra ||= {}
      { :name => name, :value => value, :type => extra[:type] }
    end

    e = new( :action => "#{form.path}?#{form.query}", :method => form.method,
             :inputs => inputs )
    e.model = form
    e
  end

end
end
end
