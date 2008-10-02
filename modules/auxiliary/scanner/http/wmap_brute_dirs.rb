##
# $Id: brutedirs.rb 1000 2008-25-02 08:21:36Z et $
##

##
# This file is part of the Metasploit Framework and may be subject to 
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/projects/Framework/
##

require 'rex/proto/http'
require 'msf/core'



class Metasploit3 < Msf::Auxiliary

	include Msf::Exploit::Remote::HttpClient
	include Msf::Auxiliary::WMAPScanDir
	include Msf::Auxiliary::Scanner

	def initialize(info = {})
		super(update_info(info,	
			'Name'   		=> 'HTTP Directory Brute Force Scanner',
			'Description'	=> %q{
				This module identifies the existence of interesting directories by brute forcing the name 
				in a given directory path.
					
			},
			'Author' 		=> [ 'et [at] cyberspace.org' ],
			'License'		=> BSD_LICENSE,
			'Version'		=> '$Revision: 1000 $'))   
			
		register_options(
			[
				OptString.new('PATH', [ true,  "The path to identify directories", '/']),
				OptString.new('ERROR_CODE', [ true,  "The expected http code for non existant directories", '404']),
				OptString.new('FORMAT', [ true,  "The expected directory format (a alpha, d digit, A upperalpha, N, n)", 'Aaa'])
			], self.class)	
						
	end

	def run_host(ip)
	
		numb = []
		datastore['FORMAT'].scan(/./) { |c|
			case c
			when 'a'
				numb << ('a'..'z')
			when 'd'
				numb << ('0'..'9')
			when 'A'
				numb << ('A'..'Z')
			when 'N'
				numb << ('A'..'Z')+('0'..'9')
			when 'n'
				numb << ('a'..'z')+('0'..'9')
			else
				print_status("Format string error")
				return
			end
		} 		

		tpath = datastore['PATH'] 	
		if tpath[-1,1] != '/'
			tpath += '/'
		end	

		print_status("Running..")
			
		Enumerable.cart(*numb).each {|testd| 
			begin
			  	teststr = tpath+testd.to_s + '/'
				res = send_request_cgi({
					'uri'  		=>  teststr,
					'method'   	=> 'GET',
					'ctype'		=> 'text/plain'
				}, 20)

				if res
					if res.code.to_i != datastore['ERROR_CODE'].to_i
						print_status("Found http://#{target_host}:#{target_port}#{teststr} #{res.code.to_i}")
					else
						print_status("NOT Found http://#{target_host}:#{target_port}#{teststr}  #{res.code.to_i}") 
						#blah
					end
				end

			rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout
			rescue ::Timeout::Error, ::Errno::EPIPE			
			end
	
		}
	
	end

end



#
# Used module to do the basic brute forcing.
# This Module was developed by Thomas Hafner.
# No other references about the author.
#

# TITLE:
#
#   Cartesian
#
# SUMMARY:
#
#   Cartesian product and similar methods.
#
# AUTHORS:
#
#   - Thomas Hafner

#
module Enumerable

	class << self
		# Provides the cross-product of two or more Enumerables.
		# This is the class-level method. The instance method
		# calls on this.
		#
		#   Enumerable.cart([1,2], [4], ["apple", "banana"])
		#   #=> [[1, 4, "apple"], [1, 4, "banana"], [2, 4, "apple"], [2, 4, "banana"]]
		#
		#   Enumerable.cart([1,2], [3,4])
		#   #=> [[1, 3], [1, 4], [2, 3], [2, 4]]

		def cartesian_product(*enums, &block)
			result = [[]]
			while [] != enums
				t, result = result, []
				b, *enums = enums
				t.each do |a|
					b.each do |n|
						result << a + [n]
					end
				end
			end
			if block_given?
				result.each{ |e| block.call(e) }
			else
				result
			end
		end

		alias_method :cart, :cartesian_product
	end

	# The instance level version of <tt>Enumerable::cartesian_product</tt>.	
	#
	#   a = []
	#   [1,2].cart([4,5]){|elem| a << elem }
	#   a  #=> [[1, 4],[1, 5],[2, 4],[2, 5]]

	def cartesian_product(*enums, &block)
		Enumerable.cartesian_product(self, *enums, &block)
	end

	alias :cart :cartesian_product

	# Operator alias for cross-product.
	#
	#   a = [1,2] ** [4,5]
	#   a  #=> [[1, 4],[1, 5],[2, 4],[2, 5]]
	#
	def **(enum)
		Enumerable.cartesian_product(self, enum)
	end

	# Expected to be an enumeration of arrays. This method
	# iterates through combinations of each in position.
	#
	#   a = [ [0,1], [2,3] ]
	#   a.each_combo { |c| p c }
	#
	# produces
	#
	#   [0, 2]
	#   [0, 3]
	#   [1, 2]
	#   [1, 3]
	#
	def each_combo
		a = collect{ |x|
			x.respond_to?(:to_a) ? x.to_a : 0..x
		}

		if a.size == 1
			r = a.shift
			r.each{ |n|
				yield n
			}
		else
			r = a.shift
			r.each{ |n|
				a.each_combo{ |s|
					yield [n, *s]
				}
			}
		end
	end

	# As with each_combo but returns combos collected in an array.
	#
	def combos
		a = []
		each_combo{ |c| a << c }
		a
	end

end	
