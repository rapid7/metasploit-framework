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

class Fuzzable

	# load and include all available analysis/audit techniques
	lib = File.dirname( __FILE__ ) + '/analysis/*.rb'
	Dir.glob( lib ).each { |f| require f }
	Analysis.constants.each { |technique| include Analysis.const_get( technique ) }

	attr_accessor :fuzzer

  def fuzzed?( opts = {} )
    fuzzer.checked? fuzz_id( opts )
  end

  def fuzzed( opts = {} )
    fuzzer.checked fuzz_id( opts )
  end

  def fuzz_id( opts = {} )
    "#{opts[:type]}:#{fuzzer.shortname}:#{method}:#{action}:#{params.keys.sort.to_s}:#{altered}=#{altered_value}"
  end

  def fuzz( cfuzzer = nil, &callback )
    fuzz_wrapper( cfuzzer ) { |p| callback.call( p.submit, p ) }
  end

  def fuzz_async( cfuzzer = nil, &callback )
    fuzz_wrapper( cfuzzer ) { |p| p.submit_async { |res| callback.call( res, p ) } }
  end

  def submit( opts = {} )
    fuzzer.increment_request_counter

    resp = http.request_async( *request( opts ) )
    handle_response( resp )
    resp
  end

  def submit_async( opts = {}, &callback )
    fuzzer.increment_request_counter

    http.request_async( *request( opts ) ) do |resp|
      handle_response( resp )
      callback.call resp if callback
    end

    nil
  end

  def http
		fuzzer.http
	end

	def hash
		to_hash.hash
	end

	def ==( other )
		hash == other.hash
	end

	def dup
		cf = self.fuzzer
		self.fuzzer = nil
		ce = Marshal.load( Marshal.dump( self ) )
		self.fuzzer = ce.fuzzer = cf
		ce
  end

  private
  def fuzz_wrapper( cfuzzer = nil, &block )
    self.fuzzer ||= cfuzzer
    permutations.each do |p|
      block.call p
    end
  end

  def handle_response( resp )
    str = "    #{fuzzer.shortname}: #{resp.code} - #{method.to_s.upcase} #{action} #{params}"

    case resp.code.to_i
      when 200,404,301,302,303
        #fuzzer.print_status str
      when 500,503,401,403
        fuzzer.print_good str
      else
        fuzzer.print_error str
    end
  end

end

end
end
