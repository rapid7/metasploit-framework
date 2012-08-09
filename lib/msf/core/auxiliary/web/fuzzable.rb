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

	def fuzz( cfuzzer = nil, &block )
		self.fuzzer ||= cfuzzer
		permutations.each { |p| block.call( p.submit, p ) }
	end

	def submit( opts = {} )
		fuzzer.increment_request_counter

		begin
			if resp = http.request( *request( opts ) )
				str = "    #{resp.code} - #{method.to_s.upcase} #{action} #{params}"
				case resp.code.to_i
					when 200,404,301,302,303
						# fuzzer.print_status str
					when 500,503,401,403
						fuzzer.print_good str
					else
						fuzzer.print_error str
				end
			end

			resp
		# timing attacks depend on this so pass it up
		rescue ::Timeout::Error
			raise
		rescue => e
			fuzzer.print_error "Error processing response for #{fuzzer.target.to_url} #{e.class} #{e} "
			return
		end
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

end

end
end
