# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/framework/

require 'net/https'
require 'net/http'
require 'uri'

module Msf

#
# Represents a webpage path.
#
module Auxiliary::Web


class Path  < Fuzzable

  # URL String to which to submit the params
  attr_accessor :action

  # Mdm::WebForm model if available
  attr_accessor :model

  #
  # opts - Options Hash (default: {})
  #        :action - Action URL of the form
  #        :inputs - PATH_INFO as a String
  #
  def initialize( opts = {} )
    self.action = opts[:action]
    self.action.chop! if self.action.end_with?( '?' )

    self.input = (opts[:inputs] || opts[:input]).to_s.dup
  end

  #
  # Sets the injected PATH_INFO value.
  #
  # value -   PATH_INFO String.
  #
  def input=( value )
    @inputs = value.to_s.dup
  end
  def input
    @inputs
  end
  alias :param :input

  def method
    'GET'
  end

  #
  # Examples
  #
  #   { :name => input, :value => input, :type => 'path' }
  #
  def inputs
    { :name => input, :value => input, :type => 'path' }
  end

  #
  # Examples
  #
  #   { input => input }
  #
  def params
    { input => input }
  end

  #
  # Returns 'path'
  #
  def altered
    'path'
  end

  # Returns the PATH_INFO as a String.
  def altered_value
    input
  end

  def altered_value=( value )
    self.input = value.to_s.dup
  end

  def request( opts = {} )
    uri = URI( action )
    path = uri.path
    path << '/' if !path.end_with?( '/' )

    [ "#{path}/#{param}?#{uri.query}", opts.merge( :method => method ) ]
  end

  # Bool  -   true if PATH_INFO is empty, false otherwise.
  def empty?
    param.empty?
  end

  #
  # A copy of self with seed as PATH_INFO.
  #
  # seed  -   String to use as PATH_INFO.
  #
  def permutations
    return [] if empty?
    fuzzer.seeds_for( altered_value ).map { |seed| permutation_for( nil, seed ) }.uniq
  end

  def permutation_for( field_name, field_value )
    path = self.dup
    path.input = field_value.dup
    path
  end

  def to_hash
    { :action => action.dup, :input => input.dup }
  end

  def self.from_model( form )
    e = new( :action => "#{form.path}?#{form.query}", :input => form.params[0][1] )
    e.model = form
    e
  end

end
end
end
