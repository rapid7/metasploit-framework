# Copyright (c) 2010, patrickHVE@googlemail.com
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#     * Redistributions of source code must retain the above copyright
#       notice, this list of conditions and the following disclaimer.
#     * Redistributions in binary form must reproduce the above copyright
#       notice, this list of conditions and the following disclaimer in the
#       documentation and/or other materials provided with the distribution.
#     * The names of the author may not be used to endorse or promote products
#       derived from this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL patrickHVE@googlemail.com BE LIABLE FOR ANY
# DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
# (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
# ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
# SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

module Rex
module Post
module Meterpreter
module Extensions
module Stdapi
module Railgun

#
# Manages our library of windows constants
#
class WinConstManager

	def initialize(initial_consts = {})
		@consts = {}

		initial_consts.each_pair do |name, value|
			add_const(name, value)
		end

		# Load utility
	end

	def add_const(name, value)
		@consts[name] = value
	end

	# parses a string constaining constants and returns an integer
	# the string can be either "CONST" or "CONST1 | CONST2"
	#
	# this function will NOT throw an exception but return "nil" if it can't parse a string
	def parse(s)
		if s.class != String
			return nil # it's not even a string'
		end
		return_value = 0
		for one_const in s.split('|')
			one_const = one_const.strip()
			if not @consts.has_key? one_const
				return nil # at least one "Constant" is unknown to us
			end
			return_value |= @consts[one_const]
		end
		return return_value
	end

	def is_parseable(s)
		return parse(s) != nil
	end
	
	# looks up a windows constant (integer or hex) and returns an array of matching winconstant names
	#
	# this function will NOT throw an exception but return "nil" if it can't find an error code
	def rev_lookup(winconst, filter_regex=nil)
		c = winconst.to_i # this is what we're gonna reverse lookup
		arr = [] # results array
		@consts.each_pair do |k,v|
			arr << k if v == c
		end
		if filter_regex # this is how we're going to filter the results
			# in case we get passed a string instead of a Regexp
			filter_regex = Regexp.new(filter_regex) unless filter_regex.class == Regexp
			# do the actual filtering
			arr.select! do |item|
				item if item =~ filter_regex
			end
		end
		return arr
	end

	def is_parseable(s)
		return parse(s) != nil
	end	
end

end; end; end; end; end; end
