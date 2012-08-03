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

		max_retries = opts[:retries] || 3
		retries = 0
		begin
			# Configure the headers
			headers = {
				'User-Agent' => fuzzer.datastore['UserAgent'] || 'Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0)',
				'Accept'	 => '*/*',
				'Host'	     => fuzzer.target.vhost
			}

			if fuzzer.datastore['HTTPCookie']
				headers['Cookie'] = fuzzer.datastore['HTTPCookie']
			end

			if fuzzer.datastore['BasicAuthUser']
				auth = [ fuzzer.datastore['BasicAuthUser'].to_s + ':' +
					         fuzzer.datastore['BasicAuthPass'] ].pack( 'm*' ).gsub( /\s+/, '' )

				headers['Authorization'] = "Basic #{auth}\r\n"
			end

			fuzzer.datastore['HttpAdditionalHeaders'].to_s.split( "\x01" ).each do |hdr|
				next if !( hdr && hdr.strip.size > 0 )

				k, v = hdr.split( ':', 2 )
				next if !v

				headers[k.strip] = v.strip
			end

			chttp = http
			chttp.read_timeout = opts[:timeout] if opts[:timeout]
			if resp = chttp.request( request( headers ) )
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
				# Some CGI servers just spew errors without headers, we need to process these anyways
		rescue ::Net::HTTPBadResponse, ::Net::HTTPHeaderSyntaxError => e
			fuzzer.print_status "Error processing response for #{fuzzer.target.to_url} #{e.class} #{e} "
			return
		rescue ::Exception => e
			if max_retries > 0
				retries += 1
				retry if retries < max_retries

				fuzzer.print_error "Maximum retry count for #{fuzzer.target.to_url} reached (#{e})"
			else
				raise e
			end
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
